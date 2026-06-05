//! Timelocked Pool Parameter Updates
//!
//! Three instructions for governance-delayed pool parameter changes:
//!
//! - `propose_pool_update` (disc 21): Authority proposes new values, starts 48h timelock
//! - `execute_pool_update` (disc 22): Anyone executes after timelock expires
//! - `cancel_pool_update` (disc 23): Authority cancels pending proposal
//!
//! Propose instruction data: min_deposit(u64 LE) + max_deposit(u64 LE) + service_fee_base(u64 LE) = 24 bytes
//! service_fee_base goes through the 48h timelock.
//! Execute/Cancel instruction data: (none)
//!
//! Accounts (all three):
//!   0. [writable] Pool state
//!   1. [signer]   Authority (propose/cancel only; execute is permissionless but still needs payer)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::constants::TIMELOCK_DELAY_SECS;
use crate::error::UTXOpiaError;
use crate::state::PoolState;
use crate::utils::{validate_account_writable, validate_program_owner};

/// Propose new pool parameters. Starts a 48h timelock.
/// Overwrites any existing pending proposal.
pub fn process_propose_pool_update(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() != 24 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let pool_state_info = &accounts[0];
    let authority = &accounts[1];

    validate_program_owner(pool_state_info, program_id)?;
    validate_account_writable(pool_state_info)?;

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let min_deposit = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let max_deposit = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let service_fee = u64::from_le_bytes(data[16..24].try_into().unwrap());

    // Validate bounds: min <= max, max <= 21M BTC in sats
    if min_deposit > max_deposit {
        return Err(ProgramError::InvalidInstructionData);
    }
    if max_deposit > 2_100_000_000_000_000 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let clock = Clock::get()?;
    let execute_after = clock
        .unix_timestamp
        .checked_add(TIMELOCK_DELAY_SECS)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    let mut pool_data = pool_state_info.try_borrow_mut_data()?;
    let pool = PoolState::from_bytes_mut(&mut pool_data)?;

    if authority.key().as_ref() != pool.authority {
        return Err(UTXOpiaError::Unauthorized.into());
    }

    pool.set_pending_min_deposit(min_deposit);
    pool.set_pending_max_deposit(max_deposit);
    pool.set_pending_service_fee(service_fee);
    pool.set_pending_execute_after(execute_after);

    Ok(())
}

/// Execute a pending pool update after the timelock has elapsed.
/// Permissionless — anyone can call this once the timelock expires.
pub fn process_execute_pool_update(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    if accounts.is_empty() {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];

    validate_program_owner(pool_state_info, program_id)?;
    validate_account_writable(pool_state_info)?;

    let clock = Clock::get()?;

    let mut pool_data = pool_state_info.try_borrow_mut_data()?;
    let pool = PoolState::from_bytes_mut(&mut pool_data)?;

    if !pool.has_pending_proposal() {
        return Err(UTXOpiaError::NoPendingProposal.into());
    }

    if clock.unix_timestamp < pool.pending_execute_after() {
        return Err(UTXOpiaError::TimelockNotElapsed.into());
    }

    // Apply pending values
    pool.set_min_deposit(pool.pending_min_deposit());
    pool.set_max_deposit(pool.pending_max_deposit());
    pool.set_service_fee_base(pool.pending_service_fee());
    pool.set_last_update(clock.unix_timestamp);

    // Clear pending proposal
    pool.clear_pending_proposal();

    Ok(())
}

/// Cancel a pending pool update. Authority only.
pub fn process_cancel_pool_update(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let authority = &accounts[1];

    validate_program_owner(pool_state_info, program_id)?;
    validate_account_writable(pool_state_info)?;

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let mut pool_data = pool_state_info.try_borrow_mut_data()?;
    let pool = PoolState::from_bytes_mut(&mut pool_data)?;

    if authority.key().as_ref() != pool.authority {
        return Err(UTXOpiaError::Unauthorized.into());
    }

    if !pool.has_pending_proposal() {
        return Err(UTXOpiaError::NoPendingProposal.into());
    }

    pool.clear_pending_proposal();

    Ok(())
}
