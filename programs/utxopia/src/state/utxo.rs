//! UTXO record account (zero-copy)
//!
//! Tracks pool BTC UTXOs on-chain for trustless withdrawal/miner-fee accounting.
//! PDA seeds = ["utxo", pool_state(32), txid(32), vout_le(4)].
//!
//! The pool is part of the address on purpose. One program hosts several pools,
//! and if they ever share a custody key they share a Taproot address and so a
//! single UTXO set; a record keyed by outpoint alone is then equally valid for
//! either of them, and the reservation check further down only binds a UTXO to
//! a redemption, never to a pool. Putting the pool in the seeds makes "this
//! coin is ours" something the runtime checks rather than something the caller
//! asserts.
//!
//! Lifecycle:
//! 1. Created by complete_deposit (Unspent) when a direct Ika-vault BTC deposit lands
//! 2. Marked Reserved by mark_processing when selected for a withdrawal tx
//! 3. Closed by complete_redemption after BTC tx is confirmed (reclaim rent)
//! 4. Change output in withdrawal tx creates a new UTXO PDA (Unspent)

use crate::pinocchio_compat::ProgramError;

/// Discriminator for UtxoRecord account
pub const UTXO_RECORD_DISCRIMINATOR: u8 = 0x09;

/// UTXO status
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum UtxoStatus {
    /// Available for spending
    Unspent = 0,
    /// Selected for a withdrawal tx (mark_processing)
    Reserved = 1,
}

/// On-chain UTXO record (zero-copy layout)
///
/// Layout (56 bytes):
/// - discriminator:           1 byte  (0x09)
/// - status:                  1 byte  (0=Unspent, 1=Reserved)
/// - _padding:                2 bytes
/// - vout:                    4 bytes (u32 LE)
/// - txid:                    32 bytes
/// - amount_sats:             8 bytes (u64 LE)
/// - reserved_for_request_id: 8 bytes (u64 LE; 0 when Unspent)
#[repr(C)]
pub struct UtxoRecord {
    /// Account discriminator (0x09)
    pub discriminator: u8,

    /// Current status
    pub status: u8,

    /// Padding for alignment
    _padding: [u8; 2],

    /// Output index in the BTC transaction
    vout: [u8; 4],

    /// BTC transaction ID (internal byte order)
    pub txid: [u8; 32],

    /// Amount in satoshis
    amount_sats: [u8; 8],

    /// request_id of the RedemptionRequest that reserved this UTXO (0 while Unspent).
    /// Binds a Reserved UTXO to one specific redemption so it cannot be consumed to
    /// complete a different in-flight redemption.
    reserved_for_request_id: [u8; 8],
}

impl UtxoRecord {
    pub const LEN: usize = core::mem::size_of::<Self>(); // 48 bytes
    pub const SEED: &'static [u8] = b"utxo";

    /// Account size for a UTXO whose tapleaf must be reconstructable to spend it.
    ///
    /// `LEN` bytes of record, then the 32-byte deposit commitment.
    pub const LEN_WITH_LEAF: usize = Self::LEN + 32;

    /// The deposit commitment this UTXO's tapleaf carries, if it has one.
    ///
    /// Kept as a tail past the fixed struct rather than a field, so records
    /// written before this existed still parse: an account at exactly `LEN` is a
    /// key-path UTXO sitting at the raw dWallet address, and answers `None`.
    ///
    /// Spending a script-path UTXO means rebuilding
    /// `<commitment> OP_DROP <ika_xonly> OP_CHECKSIG`, and the commitment is the
    /// only half not already on chain. Without it stored here the leaf is
    /// unreconstructable and the coins are unspendable by anyone — the key path
    /// is a NUMS point, so there is no fallback.
    pub fn leaf_commitment(data: &[u8]) -> Option<&[u8; 32]> {
        data.get(Self::LEN..Self::LEN_WITH_LEAF)?.try_into().ok()
    }

    /// Write the tapleaf commitment. The account must have been created at
    /// `LEN_WITH_LEAF`.
    pub fn set_leaf_commitment(
        data: &mut [u8],
        commitment: &[u8; 32],
    ) -> Result<(), ProgramError> {
        let tail = data
            .get_mut(Self::LEN..Self::LEN_WITH_LEAF)
            .ok_or(ProgramError::AccountDataTooSmall)?;
        tail.copy_from_slice(commitment);
        Ok(())
    }

    /// Parse from account data
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != UTXO_RECORD_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Parse as mutable from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != UTXO_RECORD_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Initialize a new UTXO record
    pub fn init(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data[..Self::LEN].fill(0);
        data[0] = UTXO_RECORD_DISCRIMINATOR;
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    // Getters
    pub fn get_status(&self) -> UtxoStatus {
        match self.status {
            0 => UtxoStatus::Unspent,
            1 => UtxoStatus::Reserved,
            _ => UtxoStatus::Unspent,
        }
    }

    pub fn vout(&self) -> u32 {
        u32::from_le_bytes(self.vout)
    }

    pub fn amount_sats(&self) -> u64 {
        u64::from_le_bytes(self.amount_sats)
    }

    pub fn reserved_for_request_id(&self) -> u64 {
        u64::from_le_bytes(self.reserved_for_request_id)
    }

    // Setters
    pub fn set_status(&mut self, status: UtxoStatus) {
        self.status = status as u8;
    }

    pub fn set_vout(&mut self, value: u32) {
        self.vout = value.to_le_bytes();
    }

    pub fn set_txid(&mut self, value: &[u8; 32]) {
        self.txid.copy_from_slice(value);
    }

    pub fn set_amount_sats(&mut self, value: u64) {
        self.amount_sats = value.to_le_bytes();
    }

    pub fn set_reserved_for_request_id(&mut self, value: u64) {
        self.reserved_for_request_id = value.to_le_bytes();
    }
}

#[cfg(test)]
#[path = "utxo_tests.rs"]
mod tests;
