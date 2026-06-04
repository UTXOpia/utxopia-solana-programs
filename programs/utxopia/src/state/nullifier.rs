//! Nullifier record account (slim layout)
//!
//! Only stores discriminator byte (1B). The PDA seeds contain the nullifier hash,
//! so existence of the account = nullifier is spent. All metadata (operation_type,
//! spent_at, spent_by) is emitted as sol_log_data events for indexer consumption.

use pinocchio::program_error::ProgramError;

/// Discriminator for NullifierRecord account
pub const NULLIFIER_RECORD_DISCRIMINATOR: u8 = 0x03;

/// Type of operation that spent the nullifier (used for event emission)
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum NullifierOperationType {
    /// Full withdrawal (redemption)
    FullWithdrawal = 0,
    /// Partial withdrawal with change
    PartialWithdrawal = 1,
    /// Private transfer (to another commitment)
    PrivateTransfer = 2,
    /// Commitment refresh (1-in-1-out transfer)
    Transfer = 3,
    /// Commitment split (1-in-2-out)
    Split = 4,
    /// Commitment join (2-in-1-out)
    Join = 5,
}

/// Nullifier record to prevent double-spend (slim layout)
///
/// Only 1 byte: the discriminator. PDA seeds = ["nullifier", nullifier_hash],
/// so the account's existence proves the nullifier was spent.
/// Metadata is emitted as sol_log_data events.
#[repr(C)]
pub struct NullifierRecord {
    /// Account discriminator (0x03)
    pub discriminator: u8,
}

impl NullifierRecord {
    pub const LEN: usize = 1;
    pub const SEED: &'static [u8] = b"nullifier";

    /// Initialize a new nullifier record — just sets the discriminator byte
    pub fn init(data: &mut [u8]) -> Result<(), ProgramError> {
        if data.is_empty() {
            return Err(ProgramError::InvalidAccountData);
        }
        data[0] = NULLIFIER_RECORD_DISCRIMINATOR;
        Ok(())
    }
}
