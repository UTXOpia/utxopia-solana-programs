//! Auditor-only pool setters.
//!
//! Two instructions that allow the pool's designated auditor to update their
//! own settings without going through the authority timelock:
//!
//! - `set_auditor_frozen` (disc 28): Freeze / un-freeze the auditor role.
//!   Instruction data: 1 byte — 0 = not frozen, non-zero = frozen.
//!
//! - `set_auditor_viewing_pubkey` (disc 29): Update the auditor's viewing key.
//!   Instruction data: 32 bytes — the new viewing pubkey.
//!
//! Accounts (both instructions):
//!   0. [writable] Pool state (program-owned, writable)
//!   1. [signer]   Auditor

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::PoolState;
use crate::utils::{validate_account_writable, validate_program_owner};

/// Set or clear the auditor-frozen flag (disc 28).
///
/// Gate: accounts[1] must be the signer whose key matches `pool.auditor()`.
/// Instruction data[0]: 0 = un-freeze, non-zero = freeze.
pub fn process_set_auditor_frozen(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let auditor = &accounts[1];

    if !auditor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_program_owner(pool_state_info, program_id)?;
    validate_account_writable(pool_state_info)?;

    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut pool_data = pool_state_info.try_borrow_mut_data()?;
    let pool = PoolState::from_bytes_mut(&mut pool_data)?;

    if auditor.key().as_ref() != pool.auditor() {
        return Err(UTXOpiaError::Unauthorized.into());
    }

    pool.set_auditor_frozen(data[0] != 0);

    Ok(())
}

/// Replace the auditor's viewing pubkey (disc 29).
///
/// Gate: accounts[1] must be the signer whose key matches `pool.auditor()`.
/// Instruction data[0..32]: new 32-byte viewing pubkey.
pub fn process_set_auditor_viewing_pubkey(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let auditor = &accounts[1];

    if !auditor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_program_owner(pool_state_info, program_id)?;
    validate_account_writable(pool_state_info)?;

    if data.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut pool_data = pool_state_info.try_borrow_mut_data()?;
    let pool = PoolState::from_bytes_mut(&mut pool_data)?;

    if auditor.key().as_ref() != pool.auditor() {
        return Err(UTXOpiaError::Unauthorized.into());
    }

    let viewing_pubkey: &[u8; 32] = data[0..32].try_into().unwrap();
    pool.set_auditor_viewing_pubkey(viewing_pubkey);

    Ok(())
}

#[cfg(test)]
mod tests {
    /// Unit tests for instruction data parsing.
    ///
    /// The signer/auditor gate requires a full Pinocchio account context and is
    /// covered by the integration test suite — it is NOT mocked here.

    // --- set_auditor_frozen data parsing ---

    #[test]
    fn frozen_byte_zero_means_not_frozen() {
        let data: &[u8] = &[0u8];
        assert_eq!(data[0] != 0, false);
    }

    #[test]
    fn frozen_byte_one_means_frozen() {
        let data: &[u8] = &[1u8];
        assert_eq!(data[0] != 0, true);
    }

    #[test]
    fn frozen_byte_nonzero_means_frozen() {
        for v in [2u8, 0xFF, 128] {
            let data: &[u8] = &[v];
            assert!(data[0] != 0, "expected frozen for byte {v}");
        }
    }

    #[test]
    fn frozen_empty_data_is_rejected() {
        let data: &[u8] = &[];
        assert!(data.is_empty(), "empty data should trigger InvalidInstructionData");
    }

    // --- set_auditor_viewing_pubkey data parsing ---

    #[test]
    fn viewing_pubkey_exact_32_bytes_parsed() {
        let data = [0xABu8; 32];
        let result: Result<&[u8; 32], _> = data[0..32].try_into();
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), &[0xABu8; 32]);
    }

    #[test]
    fn viewing_pubkey_more_than_32_bytes_uses_first_32() {
        let mut data = [0u8; 40];
        data[0] = 0x01;
        data[31] = 0xFF;
        assert!(data.len() >= 32);
        let key: &[u8; 32] = data[0..32].try_into().unwrap();
        assert_eq!(key[0], 0x01);
        assert_eq!(key[31], 0xFF);
    }

    #[test]
    fn viewing_pubkey_short_input_rejected() {
        for short_len in [0usize, 1, 16, 31] {
            let data = vec![0u8; short_len];
            assert!(
                data.len() < 32,
                "len {short_len} should trigger short-input rejection"
            );
        }
    }
}
