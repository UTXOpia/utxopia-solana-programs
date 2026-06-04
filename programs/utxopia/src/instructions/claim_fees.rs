//! Claim accumulated protocol fees for a specific token (multi-token).
//!
//! # Accounts
//! 0. `[signer]`   Authority (must match pool.authority)
//! 1. `[]`         Pool state PDA
//! 2. `[writable]` TokenConfig PDA (tracks accumulated_fees)
//! 3. `[writable]` Vault token account (source)
//! 4. `[writable]` Admin token account (destination)
//! 5. `[]`         Token-2022 program
//!
//! Instruction data: amount(8) — allows partial claims

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::find_program_address,
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolState, TokenConfig};
use crate::utils::{
    validate_account_writable, validate_program_owner,
    validate_token_owner, validate_any_token_program_key,
};
use crate::utils::token::transfer_zkbtc;

pub fn process_claim_fees(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let authority = &accounts[0];
    let pool_state_info = &accounts[1];
    let token_config_info = &accounts[2];
    let vault = &accounts[3];
    let admin_token_account = &accounts[4];
    let token_program = &accounts[5];

    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(token_config_info, program_id)?;
    validate_token_owner(vault)?;
    validate_token_owner(admin_token_account)?;
    validate_any_token_program_key(token_program)?;
    validate_account_writable(token_config_info)?;
    validate_account_writable(vault)?;
    validate_account_writable(admin_token_account)?;

    // Validate authority
    let pool_bump = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
        pool.bump
    };

    // Verify pool PDA
    let pool_seeds: &[&[u8]] = &[PoolState::SEED];
    let (expected_pda, _) = find_program_address(pool_seeds, program_id);
    if pool_state_info.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Validate amount against accumulated_fees
    {
        let tc_data = token_config_info.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;

        // Validate vault matches
        if vault.key().as_ref() != tc.vault {
            return Err(UTXOpiaError::InvalidVault.into());
        }

        if amount > tc.accumulated_fees() {
            return Err(UTXOpiaError::InsufficientFees.into());
        }
    }

    // Transfer from vault to admin (signed by pool PDA)
    let pool_bump_bytes = [pool_bump];
    let pool_signer_seeds: &[&[u8]] = &[PoolState::SEED, &pool_bump_bytes];

    transfer_zkbtc(
        token_program,
        vault,
        admin_token_account,
        pool_state_info,
        amount,
        pool_signer_seeds,
    )?;

    // Update accumulated_fees
    {
        let mut tc_data = token_config_info.try_borrow_mut_data()?;
        let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;
        tc.sub_fees(amount)?;
    }

    pinocchio::msg!("UTXOpia: claimed fees");
    Ok(())
}
