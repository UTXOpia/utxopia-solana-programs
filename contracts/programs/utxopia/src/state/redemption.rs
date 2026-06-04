//! Redemption request account (zero-copy)

use pinocchio::program_error::ProgramError;

use crate::constants::MAX_BTC_SCRIPT_LEN;

/// Discriminator for RedemptionRequest account
pub const REDEMPTION_REQUEST_DISCRIMINATOR: u8 = 0x04;

/// Redemption status enum
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedemptionStatus {
    /// Request created, waiting for processing
    Pending = 0,
    /// Being processed by relayer (blocks cancel)
    Processing = 1,
    /// Failed
    Failed = 2,
}

/// Redemption request - pending BTC withdrawal (zero-copy layout)
///
/// Layout (106 bytes):
/// - discriminator:     1 byte
/// - status:            1 byte
/// - btc_script_len:    1 byte
/// - _padding1:         1 byte
/// - processing_slot:   4 bytes (u32 LE, slot when mark_processing was called, 0 if Pending)
/// - request_id:        8 bytes
/// - requester:         32 bytes
/// - amount_sats:       8 bytes
/// - service_fee:       8 bytes (locked at request time from pool config)
/// - total_input_sats:  8 bytes (sum of BTC input UTXOs, set at mark_processing by backend)
/// - btc_script:        34 bytes (raw scriptPubKey for BTC withdrawal, not bech32 string)
#[repr(C)]
pub struct RedemptionRequest {
    /// Account discriminator
    pub discriminator: u8,

    /// Current status
    pub status: u8,

    /// BTC scriptPubKey length
    pub btc_script_len: u8,

    /// Padding for alignment
    _padding1: u8,

    /// Slot when mark_processing was called (0 = not yet processing).
    /// Used for timeout: if current_slot - processing_slot > TIMEOUT_SLOTS, user can cancel.
    processing_slot: [u8; 4],

    /// Unique request ID (incrementing)
    request_id: [u8; 8],

    /// User who requested the redemption
    pub requester: [u8; 32],

    /// Amount to withdraw (satoshis)
    amount_sats: [u8; 8],

    /// Service fee in satoshis — locked at request time from pool's compute_service_fee().
    /// complete_redemption uses this instead of re-reading pool config.
    service_fee: [u8; 8],

    /// Total BTC input UTXO value in satoshis — set by backend at mark_processing.
    /// Used by complete_redemption to compute miner_fee = total_input_sats - sum(tx_outputs).
    total_input_sats: [u8; 8],

    /// Bitcoin scriptPubKey for withdrawal (fixed buffer)
    pub btc_script: [u8; MAX_BTC_SCRIPT_LEN],
}

impl RedemptionRequest {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = b"redemption";

    /// Parse from account data
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != REDEMPTION_REQUEST_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Parse as mutable from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != REDEMPTION_REQUEST_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Initialize a new redemption request in the given buffer
    pub fn init(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data[..Self::LEN].fill(0);
        data[0] = REDEMPTION_REQUEST_DISCRIMINATOR;
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    // Getters
    pub fn get_status(&self) -> RedemptionStatus {
        match self.status {
            0 => RedemptionStatus::Pending,
            1 => RedemptionStatus::Processing,
            2 => RedemptionStatus::Failed,
            _ => RedemptionStatus::Pending,
        }
    }

    pub fn request_id(&self) -> u64 {
        u64::from_le_bytes(self.request_id)
    }

    pub fn amount_sats(&self) -> u64 {
        u64::from_le_bytes(self.amount_sats)
    }

    pub fn service_fee(&self) -> u64 {
        u64::from_le_bytes(self.service_fee)
    }

    pub fn processing_slot(&self) -> u32 {
        u32::from_le_bytes(self.processing_slot)
    }

    pub fn total_input_sats(&self) -> u64 {
        u64::from_le_bytes(self.total_input_sats)
    }

    pub fn get_btc_script(&self) -> &[u8] {
        &self.btc_script[..self.btc_script_len as usize]
    }

    // Setters
    pub fn set_status(&mut self, status: RedemptionStatus) {
        self.status = status as u8;
    }

    pub fn set_request_id(&mut self, value: u64) {
        self.request_id = value.to_le_bytes();
    }

    pub fn set_amount_sats(&mut self, value: u64) {
        self.amount_sats = value.to_le_bytes();
    }

    pub fn set_service_fee(&mut self, value: u64) {
        self.service_fee = value.to_le_bytes();
    }

    pub fn set_processing_slot(&mut self, value: u32) {
        self.processing_slot = value.to_le_bytes();
    }

    pub fn set_total_input_sats(&mut self, value: u64) {
        self.total_input_sats = value.to_le_bytes();
    }

    pub fn set_btc_script(&mut self, script: &[u8]) -> Result<(), ProgramError> {
        if script.len() > MAX_BTC_SCRIPT_LEN {
            return Err(ProgramError::InvalidArgument);
        }
        self.btc_script[..script.len()].copy_from_slice(script);
        self.btc_script_len = script.len() as u8;
        Ok(())
    }
}
