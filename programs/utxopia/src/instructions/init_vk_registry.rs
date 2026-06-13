//! Initialize VK Registry instruction (Groth16 JoinSplit)
//!
//! Creates and initializes a verification key hash registry for a JoinSplit(N,M) variant.
//! The VK hash is used for proof verification via BN254 pairing syscalls.
//!
//! # Security
//! - Only the pool authority can initialize VK registries
//! - Each (N, M) variant has its own VK registry PDA
//! - VK hashes can be updated by authority (for circuit upgrades)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolState, VkRegistry, VK_REGISTRY_DISCRIMINATOR};
use crate::utils::{create_pda_account, validate_program_owner, validate_system_program};

/// Initialize VK Registry instruction data
///
/// Layout:
/// - n_inputs: u8 (JoinSplit N)
/// - n_outputs: u8 (JoinSplit M)
/// - vk_hash: [u8; 32] (Groth16 verification key hash)
pub struct InitVkRegistryData {
    pub n_inputs: u8,
    pub n_outputs: u8,
    pub vk_hash: [u8; 32],
}

impl InitVkRegistryData {
    pub const SIZE: usize = 2 + 32; // 34 bytes

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
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

        Ok(Self {
            n_inputs,
            n_outputs,
            vk_hash,
        })
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
        registry.vk_hash.copy_from_slice(&ix_data.vk_hash);
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

        registry.vk_hash.copy_from_slice(&ix_data.vk_hash);
    }

    pinocchio::msg!("UTXOpia: VK registry updated");

    Ok(())
}
