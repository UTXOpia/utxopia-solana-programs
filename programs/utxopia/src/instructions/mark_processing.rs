//! Mark processing instruction — transitions a redemption from Pending to Processing
//!
//! Called by the pool authority before Ika signing approval begins.
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
use crate::state::utxo::UTXO_RECORD_DISCRIMINATOR;
use crate::state::{PoolState, RedemptionRequest, RedemptionStatus, UtxoRecord, UtxoStatus};
use crate::utils::sighash::{canonical_sort, inputs_commitment, ReservedInput};
use crate::utils::{validate_account_writable, validate_program_owner};

/// Maximum UTXOs that can be selected in a single mark_processing call
const MAX_UTXOS_PER_MARK: usize = 20;

/// Process mark_processing instruction
///
/// # Instruction Data
/// - utxo_count: 1 byte (u8) — number of UTXO accounts in remaining accounts.
///
/// # Accounts
/// 0. `[writable]` Pool state
/// 1. `[writable]` Redemption request
/// 2. `[signer]`   Authority (pool authority)
///    3..3+N `[writable]` UTXO record PDAs (N = utxo_count from instruction data)
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

    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Parse instruction data: utxo_count (1 byte)
    let utxo_count = data[0] as usize;
    if utxo_count == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Validate we have enough remaining accounts for UTXOs
    if accounts.len() < 3 + utxo_count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    if utxo_count > MAX_UTXOS_PER_MARK {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Reservation key binds each reserved UTXO to THIS redemption's unique PDA (not the
    // caller-chosen nonce, which two users can collide on — audit f26).
    let reservation_key = crate::utils::validation::redemption_reservation_key(redemption_info.key());
    // Re-validate Pending status here; Phase 3 transitions it to Processing.
    {
        let redemption_data = redemption_info.try_borrow_data()?;
        let redemption = RedemptionRequest::from_bytes(&redemption_data)?;
        if redemption.get_status() != RedemptionStatus::Pending {
            return Err(UTXOpiaError::InvalidRedemptionState.into());
        }
    }

    // --- Phase 1: Validate and read UTXO amounts, mark as Reserved ---
    let mut total_input_sats: u64 = 0;
    // Stack-allocated array to hold amounts for pool state update
    let mut utxo_amounts = [0u64; MAX_UTXOS_PER_MARK];
    // Reserved input set (txid/vout/amount), committed below so approve can
    // reconstruct the exact BTC tx the sighash is computed over.
    let mut reserved = [ReservedInput {
        txid: [0u8; 32],
        vout: 0,
        amount_sats: 0,
    }; MAX_UTXOS_PER_MARK];

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
        reserved[i] = ReservedInput {
            txid: utxo.txid,
            vout: utxo.vout(),
            amount_sats: amount,
        };

        // Sum amount
        total_input_sats = total_input_sats
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // Mark as Reserved and bind to this specific redemption (by unique PDA-derived key).
        utxo.set_status(UtxoStatus::Reserved);
        utxo.set_reserved_for_request_id(reservation_key);
    }

    // Commit to the canonical-ordered reserved input set. approve_redemption_signing
    // recomputes this from the supplied UTXO accounts and rejects any mismatch, so the
    // BTC spend's inputs are pinned to trusted on-chain state (not the caller's sighash).
    canonical_sort(&mut reserved[..utxo_count]);
    let commitment = inputs_commitment(&reserved[..utxo_count]);

    // --- Phase 2: Update PoolState counters ---
    {
        let mut pool_data = pool_state_info.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;

        for amount in utxo_amounts.iter().take(utxo_count) {
            pool.remove_utxo(*amount)?;
        }
    }

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

        // Pin the reserved input set for trustless sighash reconstruction at approval.
        redemption.set_reserved_count(utxo_count as u8);
        redemption.set_inputs_commitment(&commitment);

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
