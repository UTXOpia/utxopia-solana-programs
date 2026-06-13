//! Initialize VK Registry instruction (Groth16 JoinSplit)
//!
//! Creates and initializes a verification key registry for a JoinSplit(N,M)
//! variant. The full verifier material is stored on-chain so program upgrades
//! are not required for every VK set change.
//!
//! # Security
//! - Only the pool authority can initialize VK registries
//! - Each (N, M) variant has its own VK registry PDA
//! - VK material can be updated by authority (for circuit upgrades)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolState, VkRegistry, MAX_IC_POINTS, VK_REGISTRY_DISCRIMINATOR};
use crate::utils::{create_pda_account, validate_program_owner, validate_system_program};

/// Initialize VK Registry instruction data
///
/// Layout:
/// - n_inputs: u8 (JoinSplit N)
/// - n_outputs: u8 (JoinSplit M)
/// - vk_hash: [u8; 32] (Groth16 verification key hash)
/// - delta_g2: [u8; 128]
/// - ic_len: u8
/// - ic: [[u8; 64]; ic_len]
pub struct InitVkRegistryData {
    pub n_inputs: u8,
    pub n_outputs: u8,
    pub vk_hash: [u8; 32],
    pub delta_g2: [u8; 128],
    pub ic_len: usize,
    pub ic: [[u8; 64]; MAX_IC_POINTS],
}

impl InitVkRegistryData {
    pub const HEADER_SIZE: usize = 2 + 32 + 128 + 1;

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let n_inputs = data[0];
        let n_outputs = data[1];

        // Validate dimensions against the audited JoinSplit VK set.
        if n_inputs == 0
            || n_outputs == 0
            || (n_inputs as usize + n_outputs as usize) > crate::constants::MAX_SAFE_JOINSPLIT_SIZE
        {
            return Err(ProgramError::InvalidArgument);
        }

        let mut vk_hash = [0u8; 32];
        vk_hash.copy_from_slice(&data[2..34]);

        let mut delta_g2 = [0u8; 128];
        delta_g2.copy_from_slice(&data[34..162]);

        let ic_len = data[162] as usize;
        let expected_ic_len = crate::state::joinsplit_num_public_inputs(n_inputs, n_outputs) + 1;
        if ic_len == 0 || ic_len > MAX_IC_POINTS || ic_len != expected_ic_len {
            return Err(ProgramError::InvalidInstructionData);
        }

        let expected_len = Self::HEADER_SIZE
            .checked_add(ic_len * 64)
            .ok_or(ProgramError::InvalidInstructionData)?;
        if data.len() != expected_len {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut ic = [[0u8; 64]; MAX_IC_POINTS];
        let mut offset = Self::HEADER_SIZE;
        for point in ic.iter_mut().take(ic_len) {
            point.copy_from_slice(&data[offset..offset + 64]);
            offset += 64;
        }

        Ok(Self {
            n_inputs,
            n_outputs,
            vk_hash,
            delta_g2,
            ic_len,
            ic,
        })
    }

    pub fn ic(&self) -> &[[u8; 64]] {
        &self.ic[..self.ic_len]
    }
}

/// Initialize a VK registry account for a JoinSplit(N,M) variant
///
/// Accounts:
/// 0. pool_state - Pool state PDA (to verify authority)
/// 1. vk_registry - VK registry PDA to create (writable)
/// 2. authority - Pool authority (signer, payer)
/// 3. system_program - System program
pub fn process_init_vk_registry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state = &accounts[0];
    let vk_registry = &accounts[1];
    let authority = &accounts[2];
    let system_program = &accounts[3];

    let ix_data = InitVkRegistryData::from_bytes(data)?;

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_system_program(system_program)?;
    validate_program_owner(pool_state, program_id)?;

    // Verify authority matches pool
    {
        let pool_data = pool_state.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    // Derive expected VK registry PDA: ["vk_registry", &[n_inputs], &[n_outputs]]
    let n_inputs_bytes = [ix_data.n_inputs];
    let n_outputs_bytes = [ix_data.n_outputs];
    let seeds: &[&[u8]] = &[VkRegistry::SEED, &n_inputs_bytes, &n_outputs_bytes];
    let (expected_pda, bump) = find_program_address(seeds, program_id);

    if vk_registry.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Check if already initialized
    let account_data_len = vk_registry.data_len();
    if account_data_len > 0 {
        let vk_data = vk_registry.try_borrow_data()?;
        if vk_data[0] == VK_REGISTRY_DISCRIMINATOR {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
    } else {
        let rent = Rent::get()?;
        let lamports = rent.minimum_balance(VkRegistry::SIZE);

        let bump_bytes = [bump];
        let signer_seeds: &[&[u8]] = &[
            VkRegistry::SEED,
            &n_inputs_bytes,
            &n_outputs_bytes,
            &bump_bytes,
        ];

        create_pda_account(
            authority,
            vk_registry,
            program_id,
            lamports,
            VkRegistry::SIZE as u64,
            signer_seeds,
        )?;
    }

    // Initialize VK registry
    {
        let mut vk_data = vk_registry.try_borrow_mut_data()?;
        let registry = VkRegistry::init(&mut vk_data)?;

        registry.n_inputs = ix_data.n_inputs;
        registry.n_outputs = ix_data.n_outputs;
        registry.authority.copy_from_slice(authority.key().as_ref());
        registry.set_vk(&ix_data.vk_hash, &ix_data.delta_g2, ix_data.ic())?;
    }

    pinocchio::msg!("UTXOpia: VK registry initialized");

    Ok(())
}

/// Update an existing VK registry (for circuit upgrades)
///
/// Accounts:
/// 0. vk_registry - VK registry PDA (writable)
/// 1. authority - Current authority (signer)
pub fn process_update_vk_registry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let vk_registry = &accounts[0];
    let authority = &accounts[1];

    let ix_data = InitVkRegistryData::from_bytes(data)?;

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_program_owner(vk_registry, program_id)?;

    {
        let mut vk_data = vk_registry.try_borrow_mut_data()?;
        let registry = VkRegistry::from_bytes_mut(&mut vk_data)?;

        if !registry.is_authority(authority.key().as_ref().try_into().unwrap()) {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        // Verify variant matches
        if registry.n_inputs != ix_data.n_inputs || registry.n_outputs != ix_data.n_outputs {
            return Err(ProgramError::InvalidArgument);
        }

        registry.set_vk(&ix_data.vk_hash, &ix_data.delta_g2, ix_data.ic())?;
    }

    pinocchio::msg!("UTXOpia: VK registry updated");

    Ok(())
}
