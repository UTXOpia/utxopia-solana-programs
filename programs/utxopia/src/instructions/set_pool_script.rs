//! Update the pool's BTC scriptPubKey (disc 29)
//!
//! Authority-only. Re-points the custody `pool_script` in an already-initialized
//! PoolConfig. `set_pool_config` deliberately treats an initialized config as
//! immutable; this instruction exists to migrate custody (e.g. from an Ika vault
//! to a single-key POC address) on test deployments.
//!
//! Instruction data:
//!   [0]        pool_script_len: u8 (1..=34)
//!   [1..1+N]   pool_script: [u8; N]
//!
//! Accounts:
//! 0. []          PoolState (read)
//! 1. [writable]  PoolConfig PDA
//! 2. [signer]    Authority

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolConfig, PoolState, POOL_CONFIG_DISCRIMINATOR};
use crate::utils::{validate_account_writable, validate_program_owner};

pub fn process_set_pool_script(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let pool_config_info = &accounts[1];
    let authority = &accounts[2];

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(pool_config_info, program_id)?;
    validate_account_writable(pool_config_info)?;

    // Authority must match pool
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let script_len = data[0] as usize;
    if script_len == 0 || script_len > PoolConfig::MAX_SCRIPT_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    // Optional custody-migration tail: ika_dwallet(32) + ika_dwallet_xonly(32)
    // + cpi_authority_bump(1). Migrating the pool script to a new Ika vault
    // requires updating all three together or approve_redemption_signing keeps
    // CPI-ing the stale dWallet.
    const IKA_TAIL_LEN: usize = 32 + 32 + 1;
    let base_len = 1 + script_len;
    if data.len() != base_len && data.len() != base_len + IKA_TAIL_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let pool_script = &data[1..base_len];
    let ika_tail = if data.len() == base_len + IKA_TAIL_LEN {
        let mut dwallet = [0u8; 32];
        dwallet.copy_from_slice(&data[base_len..base_len + 32]);
        let mut xonly = [0u8; 32];
        xonly.copy_from_slice(&data[base_len + 32..base_len + 64]);
        Some((dwallet, xonly, data[base_len + 64]))
    } else {
        None
    };

    // Verify PoolConfig PDA
    let (expected_pda, _) = find_program_address(&[PoolConfig::SEED], program_id);
    if pool_config_info.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let mut config_data = pool_config_info.try_borrow_mut_data()?;
    if config_data.len() < PoolConfig::LEN || config_data[0] != POOL_CONFIG_DISCRIMINATOR {
        return Err(ProgramError::UninitializedAccount);
    }
    let config = PoolConfig::from_bytes_mut(&mut config_data)?;
    config.set_pool_script(pool_script)?;
    if let Some((dwallet, xonly, bump)) = ika_tail {
        config.set_ika_dwallet(&dwallet);
        config.set_ika_dwallet_xonly_pubkey(&xonly);
        config.set_cpi_authority_bump(bump);
        pinocchio::msg!("UTXOpia: pool_script + ika custody updated");
    } else {
        pinocchio::msg!("UTXOpia: pool_script updated");
    }
    Ok(())
}
