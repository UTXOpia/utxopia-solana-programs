//! Token configuration account (zero-copy)
//!
//! Per-token settings for multi-token shielded pool.
//! PDA seeds: ["token_config", mint_pubkey]

use pinocchio::program_error::ProgramError;

/// Discriminator for TokenConfig account
pub const TOKEN_CONFIG_DISCRIMINATOR: u8 = 0x0B;

/// Token configuration account (zero-copy layout)
/// All multi-byte integers stored as little-endian byte arrays for alignment safety
#[repr(C)]
pub struct TokenConfig {
    /// Account discriminator (1 byte) — 0x0B
    pub discriminator: u8,
    /// PDA bump seed
    pub bump: u8,
    /// SPL mint address
    pub mint: [u8; 32],
    /// Poseidon(reduce_to_field(mint), 0) — precomputed at registration
    pub token_id: [u8; 32],
    /// Token account holding shielded deposits (PDA-owned vault)
    pub vault: [u8; 32],
    /// Token decimals
    pub decimals: u8,
    /// 0 = disabled, 1 = enabled
    pub enabled: u8,
    /// Flat service fee in token native units (u64 LE)
    service_fee: [u8; 8],
    /// Minimum deposit amount (u64 LE)
    min_deposit: [u8; 8],
    /// Maximum deposit amount (u64 LE)
    max_deposit: [u8; 8],
    /// Max total shielded for this token (u64 LE)
    deposit_cap: [u8; 8],
    /// Current total shielded (u64 LE)
    total_shielded: [u8; 8],
    /// Explicitly tracked accumulated protocol fees (u64 LE)
    accumulated_fees: [u8; 8],
    /// Reserved for future use
    _reserved: [u8; 16],
}

impl TokenConfig {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = b"token_config";

    /// Parse from account data
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != TOKEN_CONFIG_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Parse as mutable from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != TOKEN_CONFIG_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Initialize a new TokenConfig in the given buffer
    pub fn init(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data[..Self::LEN].fill(0);
        data[0] = TOKEN_CONFIG_DISCRIMINATOR;
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    // Getters
    pub fn is_enabled(&self) -> bool {
        self.enabled != 0
    }
    pub fn service_fee(&self) -> u64 {
        u64::from_le_bytes(self.service_fee)
    }
    pub fn min_deposit(&self) -> u64 {
        u64::from_le_bytes(self.min_deposit)
    }
    pub fn max_deposit(&self) -> u64 {
        u64::from_le_bytes(self.max_deposit)
    }
    pub fn deposit_cap(&self) -> u64 {
        u64::from_le_bytes(self.deposit_cap)
    }
    pub fn total_shielded(&self) -> u64 {
        u64::from_le_bytes(self.total_shielded)
    }
    pub fn accumulated_fees(&self) -> u64 {
        u64::from_le_bytes(self.accumulated_fees)
    }

    // Setters
    pub fn set_enabled(&mut self, v: bool) {
        self.enabled = v as u8;
    }
    pub fn set_service_fee(&mut self, v: u64) {
        self.service_fee = v.to_le_bytes();
    }
    pub fn set_min_deposit(&mut self, v: u64) {
        self.min_deposit = v.to_le_bytes();
    }
    pub fn set_max_deposit(&mut self, v: u64) {
        self.max_deposit = v.to_le_bytes();
    }
    pub fn set_deposit_cap(&mut self, v: u64) {
        self.deposit_cap = v.to_le_bytes();
    }
    pub fn set_total_shielded(&mut self, v: u64) {
        self.total_shielded = v.to_le_bytes();
    }
    pub fn set_accumulated_fees(&mut self, v: u64) {
        self.accumulated_fees = v.to_le_bytes();
    }

    // Increment helpers with overflow check
    pub fn add_shielded(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.total_shielded();
        self.set_total_shielded(
            total
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn sub_shielded(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.total_shielded();
        self.set_total_shielded(
            total
                .checked_sub(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn add_fees(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.accumulated_fees();
        self.set_accumulated_fees(
            total
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn sub_fees(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.accumulated_fees();
        self.set_accumulated_fees(
            total
                .checked_sub(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "token_config_tests.rs"]
mod tests;
