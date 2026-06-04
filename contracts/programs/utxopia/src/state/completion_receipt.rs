//! Completion receipt account (slim layout)
//!
//! Prevents duplicate redemption completion. PDA seeds = ["completion_receipt", btc_txid],
//! so the account's existence proves this BTC txid was already used for a completion.

use pinocchio::program_error::ProgramError;

/// Discriminator for CompletionReceipt account
pub const COMPLETION_RECEIPT_DISCRIMINATOR: u8 = 0x08;

/// Completion receipt to prevent duplicate redemption completion (slim layout)
///
/// Only 1 byte: the discriminator. PDA seeds = ["completion_receipt", btc_txid],
/// so the account's existence proves this BTC tx was already used to complete a redemption.
#[repr(C)]
pub struct CompletionReceipt {
    /// Account discriminator (0x08)
    pub discriminator: u8,
}

impl CompletionReceipt {
    pub const LEN: usize = 1;
    pub const SEED: &'static [u8] = b"completion_receipt";

    /// Initialize a new completion receipt — just sets the discriminator byte
    pub fn init(data: &mut [u8]) -> Result<(), ProgramError> {
        if data.is_empty() {
            return Err(ProgramError::InvalidAccountData);
        }
        data[0] = COMPLETION_RECEIPT_DISCRIMINATOR;
        Ok(())
    }
}
