//! Set pool config instruction (disc 2)
//!
//! Authority-only initialization instruction for the pool's BTC scriptPubKey
//! and Ika dWallet custody fields in the PoolConfig PDA.
//!
//! PoolConfig is custody-critical: the pool script and Ika dWallet define
//! where BTC is controlled. This instruction creates and initializes the PDA
//! once; it does not mutate an initialized config.
//!
//! Instruction Data Layout:
//! - [0]                pool_script_len: u8 (max 34)
//! - [1..1+N]           pool_script:    [u8; N]
//! - [+32]              ika_dwallet:   [u8; 32]
//! - [+32]              ika_dwallet_xonly_pubkey: [u8; 32]
//! - [+1]               cpi_authority_bump: u8
//!
//! Accounts:
//! 0. pool_state       (read)
//! 1. pool_config      (writable, PDA)
//! 2. authority        (signer)
//! 3. system_program   (read)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolConfig, PoolState, POOL_CONFIG_DISCRIMINATOR};
use crate::utils::{
    create_pda_account, validate_account_writable, validate_program_owner, validate_system_program,
};

pub fn process_set_pool_config(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let pool_config_info = &accounts[1];
    let authority = &accounts[2];
    let system_program = &accounts[3];

    // Validate signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_program_owner(pool_state_info, program_id)?;
    validate_account_writable(pool_config_info)?;
    validate_system_program(system_program)?;

    // Validate authority matches pool
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    // Parse instruction data: pool_script_len(1) + pool_script(N) + Ika custody fields.
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let script_len = data[0] as usize;
    if script_len == 0 || script_len > PoolConfig::MAX_SCRIPT_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    if data.len() < 1 + script_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    let pool_script = &data[1..1 + script_len];

    const IKA_TAIL_LEN: usize = 32 + 32 + 1;
    if data.len() != 1 + script_len + IKA_TAIL_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut cursor = 1 + script_len;

    let mut ika_dwallet = [0u8; 32];
    ika_dwallet.copy_from_slice(&data[cursor..cursor + 32]);
    cursor += 32;

    let mut ika_dwallet_xonly = [0u8; 32];
    ika_dwallet_xonly.copy_from_slice(&data[cursor..cursor + 32]);
    cursor += 32;

    let cpi_authority_bump = data[cursor];

    if ika_dwallet == [0u8; 32] || ika_dwallet_xonly == [0u8; 32] {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Verify PoolConfig PDA
    let config_seeds: &[&[u8]] = &[PoolConfig::SEED];
    let (expected_pda, config_bump) = find_program_address(config_seeds, program_id);
    if pool_config_info.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Create PDA if it doesn't exist yet
    let config_data_len = pool_config_info.data_len();
    if config_data_len == 0 {
        let rent = Rent::get()?;
        let bump_bytes = [config_bump];
        let signer_seeds: &[&[u8]] = &[PoolConfig::SEED, &bump_bytes];

        create_pda_account(
            authority,
            pool_config_info,
            program_id,
            rent.minimum_balance(PoolConfig::LEN),
            PoolConfig::LEN as u64,
            signer_seeds,
        )?;

        let mut config_data = pool_config_info.try_borrow_mut_data()?;
        let config = PoolConfig::init(&mut config_data)?;
        apply_fields(
            config,
            pool_script,
            &ika_dwallet,
            &ika_dwallet_xonly,
            cpi_authority_bump,
        )?;
    } else {
        // Existing account: only initialize zeroed/preallocated PDAs. A
        // populated PoolConfig is immutable because it defines BTC custody.
        validate_program_owner(pool_config_info, program_id)?;

        if config_data_len >= 1 {
            let config_data = pool_config_info.try_borrow_data()?;
            if config_data[0] == POOL_CONFIG_DISCRIMINATOR {
                return Err(UTXOpiaError::AlreadyInitialized.into());
            }
        }

        // Zeroed/preallocated PDA: grow if necessary before initialization.
        if config_data_len < PoolConfig::LEN {
            let rent = Rent::get()?;
            let needed = rent.minimum_balance(PoolConfig::LEN);
            let current = pool_config_info.lamports();
            if needed > current {
                let transfer_ix = pinocchio_system::instructions::Transfer {
                    from: authority,
                    to: pool_config_info,
                    lamports: needed - current,
                };
                transfer_ix.invoke()?;
            }
            pool_config_info.resize(PoolConfig::LEN)?;
        }

        let mut config_data = pool_config_info.try_borrow_mut_data()?;
        let config = PoolConfig::init(&mut config_data)?;
        apply_fields(
            config,
            pool_script,
            &ika_dwallet,
            &ika_dwallet_xonly,
            cpi_authority_bump,
        )?;
    }

    pinocchio::msg!("UTXOpia: pool config initialized");
    Ok(())
}

#[inline]
fn apply_fields(
    config: &mut PoolConfig,
    pool_script: &[u8],
    ika_dwallet: &[u8; 32],
    ika_dwallet_xonly: &[u8; 32],
    cpi_authority_bump: u8,
) -> ProgramResult {
    config.set_pool_script(pool_script)?;
    config.set_ika_dwallet(ika_dwallet);
    config.set_ika_dwallet_xonly_pubkey(ika_dwallet_xonly);
    config.set_cpi_authority_bump(cpi_authority_bump);
    Ok(())
}
