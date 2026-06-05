//! DepositIntent account
//!
//! Stores ephemeral_pub + npk for OP_RETURN-free deposits.
//! Created by the relayer after BTC detected, read by verify_deposit,
//! then closed (rent returned to relayer).
//!
//! PDA seeds: ["deposit_intent", npk]

use pinocchio::program_error::ProgramError;

/// Discriminator for DepositIntent account
pub const DEPOSIT_INTENT_DISCRIMINATOR: u8 = 0x07;

/// DepositIntent account layout (65 bytes)
#[repr(C)]
pub struct DepositIntent {
    /// Account discriminator (0x07)
    pub discriminator: u8,
    /// Ed25519 ephemeral public key (32 bytes)
    pub ephemeral_pub: [u8; 32],
    /// Note public key: npk = Poseidon(MPK, stealthScalar) (32 bytes)
    pub npk: [u8; 32],
}

impl DepositIntent {
    pub const LEN: usize = 65;
    pub const SEED: &'static [u8] = b"deposit_intent";

    /// Parse from account data (read-only)
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != DEPOSIT_INTENT_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Initialize a new deposit intent
    pub fn init(
        data: &mut [u8],
        ephemeral_pub: &[u8; 32],
        npk: &[u8; 32],
    ) -> Result<(), ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data[0] = DEPOSIT_INTENT_DISCRIMINATOR;
        data[1..33].copy_from_slice(ephemeral_pub);
        data[33..65].copy_from_slice(npk);
        Ok(())
    }
}
