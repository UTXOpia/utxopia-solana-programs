//! Register Deposit Intent instruction
//!
//! Creates a DepositIntent PDA storing ephemeral_pub + npk for OP_RETURN-free deposits.
//! Called by the backend relayer after a BTC deposit is detected.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    ProgramResult,
    sysvars::{rent::Rent, Sysvar},
};

use crate::state::DepositIntent;
use crate::utils::{create_pda_account, validate_system_program, validate_account_writable};

pub fn process_register_deposit_intent(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let payer = &accounts[0];
    let deposit_intent_info = &accounts[1];
    let system_program = &accounts[2];

    // Validate
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_account_writable(deposit_intent_info)?;
    validate_system_program(system_program)?;

    // Parse instruction data
    if data.len() < 64 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut ephemeral_pub = [0u8; 32];
    let mut npk = [0u8; 32];
    ephemeral_pub.copy_from_slice(&data[0..32]);
    npk.copy_from_slice(&data[32..64]);

    // Derive and verify PDA
    let seeds: &[&[u8]] = &[DepositIntent::SEED, &npk];
    let (expected_pda, bump) = find_program_address(seeds, program_id);
    if deposit_intent_info.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Check PDA doesn't already exist
    {
        let intent_data = deposit_intent_info.try_borrow_data()?;
        if !intent_data.is_empty() && intent_data[0] == crate::state::deposit_intent::DEPOSIT_INTENT_DISCRIMINATOR {
            // Already exists — idempotent, just return Ok
            return Ok(());
        }
    }

    // Create PDA
    let rent = Rent::get()?;
    let bump_bytes = [bump];
    let signer_seeds: &[&[u8]] = &[DepositIntent::SEED, &npk, &bump_bytes];

    create_pda_account(
        payer,
        deposit_intent_info,
        program_id,
        rent.minimum_balance(DepositIntent::LEN),
        DepositIntent::LEN as u64,
        signer_seeds,
    )?;

    // Initialize
    let mut intent_data = deposit_intent_info.try_borrow_mut_data()?;
    DepositIntent::init(&mut intent_data, &ephemeral_pub, &npk)?;

    pinocchio::msg!("UTXOpia: deposit intent registered");

    Ok(())
}
