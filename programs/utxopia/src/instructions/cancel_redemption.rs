//! Cancel redemption instruction — user cancels a Pending or timed-out redemption
//!
//! Returns locked funds by re-minting a commitment into the Merkle tree.
//! Allowed when status is Pending, or when Processing has exceeded the timeout.

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::TokenConfig;
use crate::state::{CommitmentTree, PoolState, RedemptionRequest, RedemptionStatus};
use crate::utils::crypto::compute_commitment;
use crate::utils::{close_account_securely, validate_account_writable, validate_program_owner};

/// Cancel redemption instruction data
///
/// Layout:
/// - npk: [u8; 32] - Note public key for the re-minted commitment
pub struct CancelRedemptionData {
    pub npk: [u8; 32],
}

impl CancelRedemptionData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 32 {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut npk = [0u8; 32];
        npk.copy_from_slice(&data[0..32]);
        Ok(Self { npk })
    }
}

/// Process cancel redemption
///
/// # Accounts
/// 0. `[signer]`   User (must be the original requester)
/// 1. `[writable]` Pool state
/// 2. `[writable]` Redemption request
/// 3. `[writable]` Commitment tree
/// 4. `[]`         System program
/// 5. `[writable]` TokenConfig PDA (for token_id to recompute commitment)
pub fn process_cancel_redemption(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let user = &accounts[0];
    let pool_state_info = &accounts[1];
    let redemption_info = &accounts[2];
    let commitment_tree_info = &accounts[3];
    let _system_program = &accounts[4];
    let token_config_info = &accounts[5];

    let ix_data = CancelRedemptionData::from_bytes(data)?;

    // Validate signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate account owners
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(redemption_info, program_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;

    // Validate writable
    validate_account_writable(pool_state_info)?;
    validate_account_writable(redemption_info)?;
    validate_account_writable(commitment_tree_info)?;

    // Validate requester and status; capture the amount and the recorded token_id
    let (amount_sats, token_id) = {
        let redemption_data = redemption_info.try_borrow_data()?;
        let redemption = RedemptionRequest::from_bytes(&redemption_data)?;

        // Must be the original requester
        if user.key().as_ref() != redemption.requester {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        // Allow cancel if Pending, or if Processing and timed out
        match redemption.get_status() {
            RedemptionStatus::Pending => {
                // Always allowed to cancel when Pending
            }
            RedemptionStatus::Processing => {
                // Allow cancel only if timed out
                let clock = Clock::get()?;
                let processing_slot = redemption.processing_slot() as u64;
                if clock.slot
                    < processing_slot.saturating_add(crate::constants::REDEMPTION_TIMEOUT_SLOTS)
                {
                    return Err(UTXOpiaError::RedemptionCancelNotAllowed.into());
                }
                // Timed out — allow cancellation
            }
            _ => {
                return Err(UTXOpiaError::RedemptionCancelNotAllowed.into());
            }
        }

        (redemption.amount_sats(), *redemption.token_id())
    };

    // Re-mint with the token_id recorded at redeem time, not one read from a
    // caller-supplied config. Validate the config's PDA and that it matches the
    // redemption's token so a cheap-token cancel can't mint a valuable-token note.
    validate_program_owner(token_config_info, program_id)?;
    validate_account_writable(token_config_info)?;
    {
        let tc_data = token_config_info.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;
        let (expected_tc_pda, _) = find_program_address(&[TokenConfig::SEED, &tc.mint], program_id);
        if token_config_info.key() != &expected_tc_pda {
            return Err(ProgramError::InvalidSeeds);
        }
        if tc.token_id != token_id {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    // Compute new commitment and insert into Merkle tree
    let commitment = compute_commitment(&ix_data.npk, &token_id, amount_sats)?;
    let leaf_index = {
        let mut tree_data = commitment_tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;
        tree.insert_leaf(&commitment)?
    };

    // Emit stealth announcement for the re-minted commitment (LeafInserted merged)
    let clock = Clock::get()?;
    {
        // For cancel_redemption, use zero ephemeral_pub (self-transfer, no stealth needed)
        let zero_ephemeral = [0u8; 32];
        let amount_bytes = amount_sats.to_le_bytes();
        crate::utils::events::emit_stealth_announcement(
            crate::utils::events::ANNOUNCEMENT_TYPE_DEPOSIT,
            &zero_ephemeral,
            &amount_bytes,
            &commitment,
            leaf_index as u32,
            &token_id,
        );
    }

    // Unlock funds in pool state
    {
        let mut pool_data = pool_state_info.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;

        pool.add_shielded(amount_sats)?;
        let pending = pool.pending_redemptions();
        pool.set_pending_redemptions(pending.saturating_sub(1));
        pool.set_last_update(clock.unix_timestamp);
    }

    // Close RedemptionRequest PDA — return rent to user
    close_account_securely(redemption_info, user)?;

    pinocchio::msg!("UTXOpia: redemption cancelled");
    Ok(())
}
