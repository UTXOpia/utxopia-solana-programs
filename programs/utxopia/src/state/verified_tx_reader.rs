//! Read-only reader for btc-light-client's VerifiedTransaction and BitcoinLightClient accounts
//!
//! Lightweight module to read btc-light-client accounts from utxopia.
//! No Borsh, just zero-copy byte reading.

use pinocchio::{
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
};

/// Discriminator for VerifiedTransaction account (must match btc-light-client)
pub const VERIFIED_TX_DISCRIMINATOR: u8 = 0x08;

/// PDA seed for VerifiedTransaction (must match btc-light-client)
pub const VERIFIED_TX_SEED: &[u8] = b"verified_tx";

/// PDA seed for the singleton BitcoinLightClient account (must match btc-light-client)
pub const LIGHT_CLIENT_SEED: &[u8] = b"btc_light_client";

/// Discriminator for BitcoinLightClient account (must match btc-light-client)
pub const BTC_LIGHT_CLIENT_DISCRIMINATOR: u8 = 0x06;

/// Pin a VerifiedTransaction account to its canonical PDA `["verified_tx", block_hash, txid]`.
///
/// Owner + discriminator checks alone are not enough: they accept any btc-light-client-owned
/// account whose first byte is the VT discriminator. Re-deriving the PDA from the block_hash
/// and txid stored *inside* the account and matching it against the account's own address
/// proves the account was created by the light client's `verify_transaction` at the canonical
/// address — a forged/substituted account cannot satisfy this.
pub fn assert_canonical_verified_tx(
    account_key: &Pubkey,
    block_hash: &[u8; 32],
    txid: &[u8; 32],
    btc_lc_id: &Pubkey,
) -> Result<(), ProgramError> {
    let (expected, _) = find_program_address(&[VERIFIED_TX_SEED, block_hash, txid], btc_lc_id);
    if account_key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

/// Pin the BitcoinLightClient (tip) account to its canonical singleton PDA.
pub fn assert_canonical_light_client(
    account_key: &Pubkey,
    btc_lc_id: &Pubkey,
) -> Result<(), ProgramError> {
    let (expected, _) = find_program_address(&[LIGHT_CLIENT_SEED], btc_lc_id);
    if account_key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

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

    /// Reinit epoch this proof was minted under (u32 LE at [84..88]).
    /// Bound at verify_transaction time to the light client's reinit epoch so a stale
    /// proof from a pre-reinitialization chain instance can be detected.
    pub fn reinit_epoch(&self) -> u32 {
        u32::from_le_bytes(self.data[84..88].try_into().unwrap())
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

/// Minimum size of BitcoinLightClient account for reading the reinit epoch (offset 176..180).
const LIGHT_CLIENT_EPOCH_MIN_LEN: usize = 180;

/// Read the reinit epoch from btc-light-client BitcoinLightClient account.
///
/// Layout offset 176..180 is reinit_epoch (u32 LE), stored in the account's _reserved region.
pub fn light_client_reinit_epoch(data: &[u8]) -> Result<u32, ProgramError> {
    if data.len() < LIGHT_CLIENT_EPOCH_MIN_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[0] != BTC_LIGHT_CLIENT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(u32::from_le_bytes(data[176..180].try_into().unwrap()))
}

/// Assert that a VerifiedTransaction proof belongs to the current light-client chain instance.
///
/// After `process_reinitialize` resets the singleton light client to a different chain, old
/// proofs keep their PDA and discriminator but carry the *previous* reinit epoch. Comparing the
/// proof's epoch against the current light-client epoch rejects stale/wrong-chain proofs.
pub fn assert_verified_tx_current_epoch(
    vt: &VerifiedTransactionView,
    light_client_data: &[u8],
) -> Result<(), ProgramError> {
    let current_epoch = light_client_reinit_epoch(light_client_data)?;
    if vt.reinit_epoch() != current_epoch {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}
