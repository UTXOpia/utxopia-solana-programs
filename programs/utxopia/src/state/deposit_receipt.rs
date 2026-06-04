//! Deposit receipt account (slim layout)
//!
//! Prevents duplicate deposit verification. PDA seeds = ["deposit_receipt", deposit_txid],
//! so the account's existence proves the deposit was already processed.

use pinocchio::program_error::ProgramError;

/// Discriminator for DepositReceipt account
pub const DEPOSIT_RECEIPT_DISCRIMINATOR: u8 = 0x06;

/// Deposit receipt to prevent duplicate verification (slim layout)
///
/// Only 1 byte: the discriminator. PDA seeds = ["deposit_receipt", deposit_txid],
/// so the account's existence proves the deposit was already verified.
#[repr(C)]
pub struct DepositReceipt {
    /// Account discriminator (0x06)
    pub discriminator: u8,
}

impl DepositReceipt {
    pub const LEN: usize = 1;
    pub const SEED: &'static [u8] = b"deposit_receipt";

    /// Initialize a new deposit receipt — just sets the discriminator byte
    pub fn init(data: &mut [u8]) -> Result<(), ProgramError> {
        if data.is_empty() {
            return Err(ProgramError::InvalidAccountData);
        }
        data[0] = DEPOSIT_RECEIPT_DISCRIMINATOR;
        Ok(())
    }
}
