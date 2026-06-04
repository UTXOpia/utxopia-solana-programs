//! Admin Close PDA — Allows pool authority to close any program-owned PDA
//! and reclaim rent lamports.
//!
//! Accounts:
//!   0. [] Pool state (read-only, for authority check)
//!   1. [writable] PDA to close (must be owned by this program)
//!   2. [signer, writable] Authority (must match pool.authority, receives lamports)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::PoolState;
use crate::utils::validate_program_owner;

pub fn process_admin_close_pda(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let pda_to_close = &accounts[1];
    let authority = &accounts[2];

    // Validate
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(pda_to_close, program_id)?;

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Check authority matches pool
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    // Zero out the PDA data
    {
        let mut pda_data = pda_to_close.try_borrow_mut_data()?;
        pda_data.fill(0);
    }

    // Transfer lamports to authority
    let pda_lamports = pda_to_close.lamports();
    unsafe {
        *pda_to_close.borrow_mut_lamports_unchecked() = 0;
        *authority.borrow_mut_lamports_unchecked() = authority
            .lamports()
            .checked_add(pda_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    // Reassign to system program
    unsafe { pda_to_close.assign(&[0u8; 32]) };

    Ok(())
}
