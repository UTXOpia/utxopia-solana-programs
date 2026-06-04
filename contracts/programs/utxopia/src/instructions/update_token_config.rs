//! Update token configuration (admin only).
//!
//! # Accounts
//! 0. `[signer]`   Authority (must match pool.authority)
//! 1. `[]`         Pool state PDA
//! 2. `[writable]` TokenConfig PDA
//!
//! Instruction data:
//! flags(1) + service_fee(8) + min_deposit(8) + max_deposit(8) + deposit_cap(8) + enabled(1)
//! flags byte: bit 0 = update service_fee, bit 1 = update min_deposit,
//!             bit 2 = update max_deposit, bit 3 = update deposit_cap,
//!             bit 4 = update enabled

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolState, TokenConfig};
use crate::utils::{validate_account_writable, validate_program_owner};

const FLAG_SERVICE_FEE: u8 = 1 << 0;
const FLAG_MIN_DEPOSIT: u8 = 1 << 1;
const FLAG_MAX_DEPOSIT: u8 = 1 << 2;
const FLAG_DEPOSIT_CAP: u8 = 1 << 3;
const FLAG_ENABLED: u8 = 1 << 4;

pub fn process_update_token_config(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let authority = &accounts[0];
    let pool_state_info = &accounts[1];
    let token_config_info = &accounts[2];

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(token_config_info, program_id)?;
    validate_account_writable(token_config_info)?;

    // Validate authority
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    let flags = data[0];
    let mut offset = 1;

    let mut tc_data = token_config_info.try_borrow_mut_data()?;
    let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;

    if flags & FLAG_SERVICE_FEE != 0 {
        if data.len() < offset + 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let val = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        tc.set_service_fee(val);
        offset += 8;
    }
    if flags & FLAG_MIN_DEPOSIT != 0 {
        if data.len() < offset + 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let val = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        tc.set_min_deposit(val);
        offset += 8;
    }
    if flags & FLAG_MAX_DEPOSIT != 0 {
        if data.len() < offset + 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let val = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        tc.set_max_deposit(val);
        offset += 8;
    }
    if flags & FLAG_DEPOSIT_CAP != 0 {
        if data.len() < offset + 8 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let val = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        tc.set_deposit_cap(val);
        offset += 8;
    }
    if flags & FLAG_ENABLED != 0 {
        if data.len() < offset + 1 {
            return Err(ProgramError::InvalidInstructionData);
        }
        tc.set_enabled(data[offset] != 0);
    }

    pinocchio::msg!("UTXOpia: updated token config");
    Ok(())
}
