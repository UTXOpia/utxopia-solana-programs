use pinocchio::program_error::ProgramError;

use crate::constants::BTC_LIGHT_CLIENT_DISCRIMINATOR;

/// Bitcoin Light Client state (zero-copy layout)
/// Must match utxopia's BitcoinLightClient exactly.
#[repr(C)]
pub(crate) struct BitcoinLightClient {
    pub discriminator: u8,
    pub bump: u8,
    pub paused: u8,
    pub network: u8,
    pub _padding: [u8; 4],
    pub authority: [u8; 32],
    pub genesis_hash: [u8; 32],
    pub tip_hash: [u8; 32],
    pub total_chainwork: [u8; 32],
    pub tip_height: [u8; 8],
    pub finalized_height: [u8; 8],
    pub header_count: [u8; 8],
    pub last_update: [u8; 8],
    pub expected_bits: [u8; 4],
    pub epoch_start_time: [u8; 4],
    pub _reserved: [u8; 56],
}

impl BitcoinLightClient {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != BTC_LIGHT_CLIENT_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != BTC_LIGHT_CLIENT_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    pub fn tip_height(&self) -> u64 {
        u64::from_le_bytes(self.tip_height)
    }

    pub fn header_count(&self) -> u64 {
        u64::from_le_bytes(self.header_count)
    }

    pub fn expected_bits(&self) -> u32 {
        u32::from_le_bytes(self.expected_bits)
    }

    pub fn epoch_start_time(&self) -> u32 {
        u32::from_le_bytes(self.epoch_start_time)
    }

    pub fn set_tip_height(&mut self, value: u64) {
        self.tip_height = value.to_le_bytes();
    }

    pub fn set_finalized_height(&mut self, value: u64) {
        self.finalized_height = value.to_le_bytes();
    }

    pub fn set_header_count(&mut self, value: u64) {
        self.header_count = value.to_le_bytes();
    }

    pub fn set_last_update(&mut self, value: i64) {
        self.last_update = value.to_le_bytes();
    }

    pub fn set_expected_bits(&mut self, value: u32) {
        self.expected_bits = value.to_le_bytes();
    }

    pub fn set_epoch_start_time(&mut self, value: u32) {
        self.epoch_start_time = value.to_le_bytes();
    }
}
