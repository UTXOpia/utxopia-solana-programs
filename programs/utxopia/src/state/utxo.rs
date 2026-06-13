//! UTXO record account (zero-copy)
//!
//! Tracks pool BTC UTXOs on-chain for trustless withdrawal/miner-fee accounting.
//! PDA seeds = ["utxo", txid(32), vout_le(4)], so each UTXO has a unique address.
//!
//! Lifecycle:
//! 1. Created by complete_deposit (Unspent) when a direct Ika-vault BTC deposit lands
//! 2. Marked Reserved by mark_processing when selected for a withdrawal tx
//! 3. Closed by complete_redemption after BTC tx is confirmed (reclaim rent)
//! 4. Change output in withdrawal tx creates a new UTXO PDA (Unspent)

use pinocchio::program_error::ProgramError;

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
/// Layout (48 bytes):
/// - discriminator:  1 byte  (0x09)
/// - status:         1 byte  (0=Unspent, 1=Reserved)
/// - _padding:       2 bytes
/// - vout:           4 bytes (u32 LE)
/// - txid:           32 bytes
/// - amount_sats:    8 bytes (u64 LE)
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
}

impl UtxoRecord {
    pub const LEN: usize = core::mem::size_of::<Self>(); // 48 bytes
    pub const SEED: &'static [u8] = b"utxo";

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utxo_record_size() {
        assert_eq!(UtxoRecord::LEN, 48);
    }

    #[test]
    fn test_utxo_record_seed() {
        assert_eq!(UtxoRecord::SEED, b"utxo");
    }

    #[test]
    fn test_utxo_record_discriminator() {
        assert_eq!(UTXO_RECORD_DISCRIMINATOR, 0x09);
    }

    #[test]
    fn test_utxo_record_init() {
        let mut buf = [0u8; 48];
        let utxo = UtxoRecord::init(&mut buf).unwrap();

        assert_eq!(utxo.discriminator, UTXO_RECORD_DISCRIMINATOR);
        assert_eq!(utxo.get_status(), UtxoStatus::Unspent);
        assert_eq!(utxo.vout(), 0);
        assert_eq!(utxo.amount_sats(), 0);
        assert_eq!(utxo.txid, [0u8; 32]);
    }

    #[test]
    fn test_utxo_record_init_too_small() {
        let mut buf = [0u8; 47]; // 1 byte short
        assert!(UtxoRecord::init(&mut buf).is_err());
    }

    #[test]
    fn test_utxo_record_setters_getters() {
        let mut buf = [0u8; 48];
        let utxo = UtxoRecord::init(&mut buf).unwrap();

        let txid = [0xABu8; 32];
        utxo.set_txid(&txid);
        assert_eq!(utxo.txid, txid);

        utxo.set_vout(2);
        assert_eq!(utxo.vout(), 2);

        utxo.set_amount_sats(100_000);
        assert_eq!(utxo.amount_sats(), 100_000);

        utxo.set_status(UtxoStatus::Reserved);
        assert_eq!(utxo.get_status(), UtxoStatus::Reserved);
    }

    #[test]
    fn test_utxo_record_from_bytes() {
        let mut buf = [0u8; 48];
        {
            let utxo = UtxoRecord::init(&mut buf).unwrap();
            utxo.set_vout(3);
            utxo.set_amount_sats(50_000);
            utxo.set_txid(&[0xCCu8; 32]);
        }

        let utxo = UtxoRecord::from_bytes(&buf).unwrap();
        assert_eq!(utxo.vout(), 3);
        assert_eq!(utxo.amount_sats(), 50_000);
        assert_eq!(utxo.txid, [0xCCu8; 32]);
        assert_eq!(utxo.get_status(), UtxoStatus::Unspent);
    }

    #[test]
    fn test_utxo_record_from_bytes_wrong_discriminator() {
        let mut buf = [0u8; 48];
        buf[0] = 0x01; // wrong discriminator
        assert!(UtxoRecord::from_bytes(&buf).is_err());
    }

    #[test]
    fn test_utxo_record_from_bytes_too_small() {
        let buf = [0x09u8; 10]; // correct disc but too small
        assert!(UtxoRecord::from_bytes(&buf).is_err());
    }

    #[test]
    fn test_utxo_record_from_bytes_mut() {
        let mut buf = [0u8; 48];
        UtxoRecord::init(&mut buf).unwrap();

        let utxo = UtxoRecord::from_bytes_mut(&mut buf).unwrap();
        utxo.set_status(UtxoStatus::Reserved);
        assert_eq!(utxo.get_status(), UtxoStatus::Reserved);

        // Read back immutably
        let utxo2 = UtxoRecord::from_bytes(&buf).unwrap();
        assert_eq!(utxo2.get_status(), UtxoStatus::Reserved);
    }

    #[test]
    fn test_utxo_status_values() {
        assert_eq!(UtxoStatus::Unspent as u8, 0);
        assert_eq!(UtxoStatus::Reserved as u8, 1);
    }

    #[test]
    fn test_utxo_unknown_status_defaults_to_unspent() {
        let mut buf = [0u8; 48];
        UtxoRecord::init(&mut buf).unwrap();
        buf[1] = 0xFF; // invalid status byte
        let utxo = UtxoRecord::from_bytes(&buf).unwrap();
        assert_eq!(utxo.get_status(), UtxoStatus::Unspent);
    }

    #[test]
    fn test_utxo_record_large_amount() {
        let mut buf = [0u8; 48];
        let utxo = UtxoRecord::init(&mut buf).unwrap();

        let max_btc = 21_000_000 * 100_000_000u64; // 21M BTC in sats
        utxo.set_amount_sats(max_btc);
        assert_eq!(utxo.amount_sats(), max_btc);
    }

    #[test]
    fn test_utxo_record_max_vout() {
        let mut buf = [0u8; 48];
        let utxo = UtxoRecord::init(&mut buf).unwrap();
        utxo.set_vout(u32::MAX);
        assert_eq!(utxo.vout(), u32::MAX);
    }

    #[test]
    fn test_utxo_record_zero_copy_layout() {
        // Verify the zero-copy layout matches the documented byte offsets
        let mut buf = [0u8; 48];
        let utxo = UtxoRecord::init(&mut buf).unwrap();

        utxo.set_status(UtxoStatus::Reserved);
        utxo.set_vout(7);
        let txid = [0x42u8; 32];
        utxo.set_txid(&txid);
        utxo.set_amount_sats(12345);

        // Check raw bytes at documented offsets
        assert_eq!(buf[0], 0x09); // discriminator
        assert_eq!(buf[1], 1); // status = Reserved
        assert_eq!(buf[2], 0); // padding
        assert_eq!(buf[3], 0); // padding
        assert_eq!(buf[4..8], 7u32.to_le_bytes()); // vout
        assert_eq!(&buf[8..40], &txid); // txid
        assert_eq!(buf[40..48], 12345u64.to_le_bytes()); // amount_sats
    }
}
