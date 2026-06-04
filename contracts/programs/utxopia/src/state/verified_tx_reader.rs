//! Read-only reader for btc-light-client's VerifiedTransaction and BitcoinLightClient accounts
//!
//! Lightweight module to read btc-light-client accounts from utxopia.
//! No Borsh, just zero-copy byte reading.

use pinocchio::program_error::ProgramError;

/// Discriminator for VerifiedTransaction account (must match btc-light-client)
pub const VERIFIED_TX_DISCRIMINATOR: u8 = 0x08;

/// PDA seed for VerifiedTransaction (must match btc-light-client)
pub const VERIFIED_TX_SEED: &[u8] = b"verified_tx";

/// Discriminator for BitcoinLightClient account (must match btc-light-client)
pub const BTC_LIGHT_CLIENT_DISCRIMINATOR: u8 = 0x06;

/// Minimum size of VerifiedTransaction account
const VERIFIED_TX_MIN_LEN: usize = 120;

/// Minimum size of BitcoinLightClient account for reading tip_height
const LIGHT_CLIENT_MIN_LEN: usize = 144;

/// Read-only view of btc-light-client VerifiedTransaction PDA (120 bytes)
///
/// Layout:
/// - disc(1) + bump(1) + _pad(2) + block_height(4) + block_hash(32) + txid(32) + verified_at(8) + tx_index(4) + _reserved(36)
pub struct VerifiedTransactionView<'a> {
    data: &'a [u8],
}

impl<'a> VerifiedTransactionView<'a> {
    /// Parse from account data, validating discriminator and length
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < VERIFIED_TX_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != VERIFIED_TX_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(Self { data })
    }

    /// Block height (u32 LE at bytes [4..8])
    pub fn block_height(&self) -> u32 {
        u32::from_le_bytes(self.data[4..8].try_into().unwrap())
    }

    /// Block hash (32 bytes at [8..40])
    pub fn block_hash(&self) -> &[u8; 32] {
        self.data[8..40].try_into().unwrap()
    }

    /// Transaction ID (32 bytes at [40..72])
    pub fn txid(&self) -> &[u8; 32] {
        self.data[40..72].try_into().unwrap()
    }

    /// Verified-at timestamp (i64 LE at [72..80])
    pub fn verified_at(&self) -> i64 {
        i64::from_le_bytes(self.data[72..80].try_into().unwrap())
    }

    /// Transaction index in block (u32 LE at [80..84])
    pub fn tx_index(&self) -> u32 {
        u32::from_le_bytes(self.data[80..84].try_into().unwrap())
    }
}

/// Read tip height from btc-light-client BitcoinLightClient account
///
/// Layout offset 136..144 is tip_height (u64 LE)
pub fn light_client_tip_height(data: &[u8]) -> Result<u64, ProgramError> {
    if data.len() < LIGHT_CLIENT_MIN_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[0] != BTC_LIGHT_CLIENT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(u64::from_le_bytes(data[136..144].try_into().unwrap()))
}
