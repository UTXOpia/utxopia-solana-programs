//! Initialize VK Registry instruction (Groth16 JoinSplit)
//!
//! Creates and initializes a verification key registry for a JoinSplit(N,M)
//! variant. The full verifier material is stored on-chain so program upgrades
//! are not required for every VK set change.
//!
//! # Security
//! - Each (N, M) variant has its own VK registry PDA, and that PDA is GLOBAL — not namespaced
//!   by pool. A global resource needs a global admin, so these instructions are gated on the
//!   program upgrade authority. They used to read the authority (and the freeze flag) out of a
//!   caller-supplied `pool_state`; since `INITIALIZE` is permissionless, anyone could stand up
//!   their own pool, name themselves authority, and claim/rewrite the VK every pool verifies
//!   against — while `vk_registries_are_frozen()` read the same fake pool and never fired.
//! - VK material can be updated by that authority (for circuit upgrades) until frozen.
//! - Permanent global freeze = `solana program set-upgrade-authority --final`: with no upgrade
//!   authority, init/update/freeze all fail forever. Per-registry freeze still lives in the
//!   registry account itself, whose address is pinned by `find_program_address`.

use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError, Pubkey};
use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{VkRegistry, MAX_IC_POINTS, VK_REGISTRY_DISCRIMINATOR};
use crate::utils::{
    create_pda_account, validate_account_writable, validate_program_owner, validate_system_program,
    validate_upgrade_authority,
};

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

/// Pin a registry account to its canonical PDA ["vk_registry", n_inputs, n_outputs] — the same
/// derivation the verifier uses (see `joinsplit_common`). Owner + matching (n,m) fields alone
/// would accept a substituted account, so an update/freeze aimed at a copy would silently leave
/// the registry the verifier actually reads untouched.
fn validate_vk_registry_pda(
    vk_registry: &AccountInfo,
    n_inputs: u8,
    n_outputs: u8,
    program_id: &Pubkey,
) -> Result<u8, ProgramError> {
    let (expected, bump) = find_program_address(
        &[VkRegistry::SEED, &[n_inputs], &[n_outputs]],
        program_id,
    );
    if vk_registry.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(bump)
}

/// Initialize a VK registry account for a JoinSplit(N,M) variant
///
/// Accounts:
/// 0. program_data - This program's ProgramData account (to verify the upgrade authority)
/// 1. vk_registry - VK registry PDA to create (writable)
/// 2. authority - Program upgrade authority (signer, payer)
/// 3. system_program - System program
pub fn process_init_vk_registry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let program_data = &accounts[0];
    let vk_registry = &accounts[1];
    let authority = &accounts[2];
    let system_program = &accounts[3];

    let ix_data = InitVkRegistryData::from_bytes(data)?;

    validate_system_program(system_program)?;
    validate_upgrade_authority(program_id, program_data, authority)?;

    let n_inputs_bytes = [ix_data.n_inputs];
    let n_outputs_bytes = [ix_data.n_outputs];
    let bump = validate_vk_registry_pda(
        vk_registry,
        ix_data.n_inputs,
        ix_data.n_outputs,
        program_id,
    )?;

    // Check if already initialized
    let account_data_len = vk_registry.data_len();
    if account_data_len > 0 {
        let vk_data = vk_registry.try_borrow()?;
        if vk_data[0] == VK_REGISTRY_DISCRIMINATOR {
            return Err(ProgramError::AccountAlreadyInitialized);
        }
    } else {
        let rent = Rent::get()?;
        let lamports = rent.try_minimum_balance(VkRegistry::SIZE)?;

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
        let mut vk_data = vk_registry.try_borrow_mut()?;
        let registry = VkRegistry::init(&mut vk_data)?;

        registry.n_inputs = ix_data.n_inputs;
        registry.n_outputs = ix_data.n_outputs;
        registry
            .authority
            .copy_from_slice(authority.address().as_ref());
        registry.set_vk(&ix_data.vk_hash, &ix_data.delta_g2, ix_data.ic())?;
    }

    solana_program_log::log!("UTXOpia: VK registry initialized");

    Ok(())
}

/// Update an existing VK registry (for circuit upgrades)
///
/// Accounts:
/// 0. program_data - This program's ProgramData account
/// 1. vk_registry - VK registry PDA (writable)
/// 2. authority - Program upgrade authority (signer)
pub fn process_update_vk_registry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let program_data = &accounts[0];
    let vk_registry = &accounts[1];
    let authority = &accounts[2];

    let ix_data = InitVkRegistryData::from_bytes(data)?;

    validate_upgrade_authority(program_id, program_data, authority)?;
    validate_program_owner(vk_registry, program_id)?;
    validate_vk_registry_pda(vk_registry, ix_data.n_inputs, ix_data.n_outputs, program_id)?;

    {
        let mut vk_data = vk_registry.try_borrow_mut()?;
        let registry = VkRegistry::from_bytes_mut(&mut vk_data)?;

        if !registry.is_authority(authority.address().as_ref().try_into().unwrap()) {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        // Once frozen, VK material is immutable — a compromised authority can no longer
        // swap in a forging key.
        if registry.is_frozen() {
            return Err(UTXOpiaError::VkRegistryFrozen.into());
        }

        // Verify variant matches
        if registry.n_inputs != ix_data.n_inputs || registry.n_outputs != ix_data.n_outputs {
            return Err(ProgramError::InvalidArgument);
        }

        registry.set_vk(&ix_data.vk_hash, &ix_data.delta_g2, ix_data.ic())?;
    }

    solana_program_log::log!("UTXOpia: VK registry updated");

    Ok(())
}

/// Permanently freeze a VK registry so its key material can never be updated again.
///
/// This is the production hardening step: deploy → register/iterate VKs → freeze before
/// mainnet. After freezing, `process_update_vk_registry` always fails, so a later authority
/// compromise cannot install a malicious verification key and forge proofs.
///
/// Accounts:
/// 0. program_data - This program's ProgramData account
/// 1. vk_registry - VK registry PDA (writable)
/// 2. authority - Program upgrade authority (signer)
pub fn process_freeze_vk_registry(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let program_data = &accounts[0];
    let vk_registry = &accounts[1];
    let authority = &accounts[2];

    validate_upgrade_authority(program_id, program_data, authority)?;
    validate_program_owner(vk_registry, program_id)?;
    validate_account_writable(vk_registry)?;

    {
        let mut vk_data = vk_registry.try_borrow_mut()?;
        let registry = VkRegistry::from_bytes_mut(&mut vk_data)?;
        validate_vk_registry_pda(
            vk_registry,
            registry.n_inputs,
            registry.n_outputs,
            program_id,
        )?;

        if !registry.is_authority(authority.address().as_ref().try_into().unwrap()) {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        registry.freeze();
    }

    solana_program_log::log!("UTXOpia: VK registry frozen");

    Ok(())
}
