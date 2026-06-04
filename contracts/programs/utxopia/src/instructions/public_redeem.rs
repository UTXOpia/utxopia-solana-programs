//! Public Redeem instruction (disc 17)
//!
//! Burns public SPL zkBTC tokens and creates a RedemptionRequest PDA
//! for BTC withdrawal. No ZK proof needed — user signs as token authority.
//!
//! Instruction Data Layout:
//! - [0..8]  amount_sats:      u64 (LE)
//! - [8]     btc_script_len:   u8
//! - [9..]   btc_script:       [u8; btc_script_len] (variable, max 62)
//! - [..]    request_nonce:    u64 (LE)
//!
//! Accounts:
//! 0. pool_state           (writable)
//! 1. zkbtc_mint            (writable)
//! 2. user_token_account   (writable)
//! 3. user                 (signer)
//! 4. system_program       (read)
//! 5. token_program        (read, Token-2022)
//! 6. redemption_request   (writable PDA)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{
    PoolState, RedemptionRequest, RedemptionStatus,
    REDEMPTION_REQUEST_DISCRIMINATOR,
};
use crate::utils::token::{burn_zkbtc, validate_token_account};
use crate::utils::{
    create_pda_account, validate_account_writable, validate_program_owner,
    validate_system_program, validate_token_owner, validate_any_token_program_key,
};

pub fn process_public_redeem(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Minimum data: amount(8) + btc_script_len(1) + at least 1 byte script + nonce(8) = 18
    if data.len() < 18 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Parse amount
    let amount_sats = u64::from_le_bytes(data[0..8].try_into().unwrap());

    // Parse btc_script (variable length)
    let btc_script_len = data[8] as usize;
    if btc_script_len == 0 || btc_script_len > crate::constants::MAX_BTC_SCRIPT_LEN {
        return Err(UTXOpiaError::InvalidBtcAddress.into());
    }

    if data.len() < 9 + btc_script_len + 8 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let btc_script = &data[9..9 + btc_script_len];
    let request_nonce = u64::from_le_bytes(
        data[9 + btc_script_len..9 + btc_script_len + 8].try_into().unwrap(),
    );

    // Validate accounts
    if accounts.len() < 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let zkbtc_mint = &accounts[1];
    let user_token_account = &accounts[2];
    let user = &accounts[3];
    let system_program = &accounts[4];
    let token_program = &accounts[5];
    let redemption_request_info = &accounts[6];

    // Validate core accounts
    validate_program_owner(pool_state_info, program_id)?;
    validate_system_program(system_program)?;
    validate_token_owner(zkbtc_mint)?;
    validate_token_owner(user_token_account)?;
    validate_any_token_program_key(token_program)?;
    validate_account_writable(pool_state_info)?;
    validate_account_writable(zkbtc_mint)?;
    validate_account_writable(user_token_account)?;
    validate_account_writable(redemption_request_info)?;

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate pool is not paused
    let pending_redemptions = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }

        // Verify zkbtc_mint matches pool
        if zkbtc_mint.key().as_ref() != pool.zkbtc_mint {
            return Err(ProgramError::InvalidAccountData);
        }

        pool.pending_redemptions()
    };

    // Validate amount
    if amount_sats == 0 {
        return Err(UTXOpiaError::ZeroAmount.into());
    }

    // Validate token account: owned by Token-2022, correct mint, owned by user
    validate_token_account(user_token_account, zkbtc_mint.key(), user.key())?;

    // Burn tokens — user signs as authority (no PDA signer needed)
    burn_zkbtc(token_program, zkbtc_mint, user_token_account, user, amount_sats)?;

    // Create RedemptionRequest PDA
    let clock = Clock::get()?;
    let rent = Rent::get()?;

    let nonce_bytes = request_nonce.to_le_bytes();
    let redemption_seeds: &[&[u8]] = &[
        RedemptionRequest::SEED,
        user.key().as_ref(),
        &nonce_bytes,
    ];
    let (expected_redemption_pda, redemption_bump) =
        find_program_address(redemption_seeds, program_id);
    if redemption_request_info.key() != &expected_redemption_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    {
        let redemption_data = redemption_request_info.try_borrow_data()?;
        if !redemption_data.is_empty()
            && redemption_data[0] == REDEMPTION_REQUEST_DISCRIMINATOR
        {
            return Err(UTXOpiaError::AlreadyInitialized.into());
        }
    }

    let redemption_bump_bytes = [redemption_bump];
    let redemption_signer_seeds: &[&[u8]] = &[
        RedemptionRequest::SEED,
        user.key().as_ref(),
        &nonce_bytes,
        &redemption_bump_bytes,
    ];

    create_pda_account(
        user,
        redemption_request_info,
        program_id,
        rent.minimum_balance(RedemptionRequest::LEN),
        RedemptionRequest::LEN as u64,
        redemption_signer_seeds,
    )?;

    // Compute service fee from pool config (locked at request time)
    let service_fee = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        pool.compute_service_fee(amount_sats)
    };

    {
        let mut redemption_data = redemption_request_info.try_borrow_mut_data()?;
        let redemption = RedemptionRequest::init(&mut redemption_data)?;
        redemption.set_request_id(request_nonce);
        redemption.requester.copy_from_slice(user.key().as_ref());
        redemption.set_amount_sats(amount_sats);
        redemption.set_service_fee(service_fee);
        redemption.set_btc_script(btc_script)?;
        redemption.set_status(RedemptionStatus::Pending);
    }

    // Update pool state: add_burned (these are already-public tokens), increment pending_redemptions
    // Read fee config before mutating for the event emission
    let (fee_base, fee_bps) = {
        let mut pool_data = pool_state_info.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;
        let fb = pool.service_fee_base();
        let fbps = pool.service_fee_bps();
        pool.add_burned(amount_sats)?;
        pool.set_pending_redemptions(pending_redemptions.saturating_add(1));
        pool.set_last_update(clock.unix_timestamp);
        (fb, fbps)
    };

    // Emit redemption requested event (includes fee config locked at request time)
    crate::utils::events::emit_redemption_requested(
        user.key().as_ref().try_into().unwrap(),
        amount_sats,
        request_nonce,
        fee_base,
        fee_bps,
        btc_script,
    );

    pinocchio::msg!("UTXOpia: public redeem");
    Ok(())
}
