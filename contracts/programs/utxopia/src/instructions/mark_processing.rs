//! Mark processing instruction — transitions a redemption from Pending to Processing
//!
//! Called by the pool authority before FROST signing begins.
//! Records the current slot for timeout tracking — if the redemption stays
//! in Processing longer than REDEMPTION_TIMEOUT_SLOTS, the user can cancel it.
//!
//! UTXO selection: Backend passes UTXO PDA accounts as remaining accounts.
//! The program reads and validates each UTXO, sums their amounts trustlessly,
//! marks them as Reserved, and writes total_input_sats to the RedemptionRequest.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolState, RedemptionRequest, RedemptionStatus, UtxoRecord, UtxoStatus};
use crate::state::utxo::UTXO_RECORD_DISCRIMINATOR;
use crate::utils::{validate_program_owner, validate_account_writable};

/// Maximum UTXOs that can be selected in a single mark_processing call
const MAX_UTXOS_PER_MARK: usize = 20;

/// Process mark_processing instruction
///
/// # Instruction Data
/// - utxo_count: 1 byte (u8) — number of UTXO accounts in remaining accounts.
///   If 0, falls back to old behavior (no trustless UTXO tracking).
///
/// # Accounts
/// 0. `[writable]` Pool state
/// 1. `[writable]` Redemption request
/// 2. `[signer]`   Authority (pool authority)
/// 3..3+N `[writable]` UTXO record PDAs (N = utxo_count from instruction data)
pub fn process_mark_processing(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let redemption_info = &accounts[1];
    let authority = &accounts[2];

    // Validate signers
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate account owners and writable
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(redemption_info, program_id)?;
    validate_account_writable(pool_state_info)?;
    validate_account_writable(redemption_info)?;

    // Validate authority matches pool
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    // Parse instruction data: utxo_count (1 byte)
    let utxo_count = if !data.is_empty() { data[0] as usize } else { 0 };

    // Validate we have enough remaining accounts for UTXOs
    if accounts.len() < 3 + utxo_count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    if utxo_count > MAX_UTXOS_PER_MARK {
        return Err(ProgramError::InvalidInstructionData);
    }

    // --- Phase 1: Validate and read UTXO amounts, mark as Reserved ---
    let total_input_sats = if utxo_count > 0 {
        let mut total: u64 = 0;
        // Stack-allocated array to hold amounts for pool state update
        let mut utxo_amounts = [0u64; MAX_UTXOS_PER_MARK];

        for i in 0..utxo_count {
            let utxo_info = &accounts[3 + i];

            // Validate UTXO account
            validate_program_owner(utxo_info, program_id)?;
            validate_account_writable(utxo_info)?;

            let mut utxo_data = utxo_info.try_borrow_mut_data()?;

            // Validate discriminator
            if utxo_data.is_empty() || utxo_data[0] != UTXO_RECORD_DISCRIMINATOR {
                return Err(UTXOpiaError::InvalidUtxo.into());
            }

            let utxo = UtxoRecord::from_bytes_mut(&mut utxo_data)?;

            // Must be Unspent
            if utxo.get_status() != UtxoStatus::Unspent {
                return Err(UTXOpiaError::UtxoNotUnspent.into());
            }

            let amount = utxo.amount_sats();
            utxo_amounts[i] = amount;

            // Sum amount
            total = total.checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;

            // Mark as Reserved
            utxo.set_status(UtxoStatus::Reserved);
        }

        // --- Phase 2: Update PoolState counters ---
        {
            let mut pool_data = pool_state_info.try_borrow_mut_data()?;
            let pool = PoolState::from_bytes_mut(&mut pool_data)?;

            for i in 0..utxo_count {
                pool.remove_utxo(utxo_amounts[i])?;
            }
        }

        total
    } else {
        // Backward compat: no UTXOs passed, use old instruction data format
        // data[0] was utxo_count=0, remaining bytes may contain total_input_sats
        if data.len() >= 9 {
            // utxo_count(1) + total_input_sats(8)
            u64::from_le_bytes(data[1..9].try_into().unwrap())
        } else if data.is_empty() && false {
            // Truly legacy: no data at all
            0
        } else {
            0
        }
    };

    // Validate status is Pending and transition to Processing
    {
        let mut redemption_data = redemption_info.try_borrow_mut_data()?;
        let redemption = RedemptionRequest::from_bytes_mut(&mut redemption_data)?;

        if redemption.get_status() != RedemptionStatus::Pending {
            return Err(UTXOpiaError::InvalidRedemptionState.into());
        }

        redemption.set_status(RedemptionStatus::Processing);

        // Record the slot for timeout tracking
        let clock = Clock::get()?;
        let slot = clock.slot as u32;
        redemption.set_processing_slot(slot);

        // Store total_input_sats (trustlessly computed from UTXO PDAs)
        redemption.set_total_input_sats(total_input_sats);

        // Emit processing event
        let requester: &[u8; 32] = &redemption.requester;
        crate::utils::events::emit_redemption_processing(
            requester,
            redemption.amount_sats(),
            redemption.request_id(),
            slot,
        );
    }

    pinocchio::msg!("UTXOpia: redemption processing");
    Ok(())
}
