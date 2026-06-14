//! Pool configuration PDA — extended fields that don't fit in PoolState
//!
//! Stores the pool's BTC scriptPubKey (P2TR) and Ika custody keys on-chain for
//! trustless verification in `complete_redemption` and `verify_deposit`.
//!
//! PDA seeds: ["pool_config"]

use pinocchio::program_error::ProgramError;

/// Discriminator for PoolConfig account
pub const POOL_CONFIG_DISCRIMINATOR: u8 = 0x0A;

/// Pool configuration account (zero-copy layout, 129 bytes)
#[repr(C)]
pub struct PoolConfig {
    /// Account discriminator (1 byte)
    pub discriminator: u8,

    /// Length of pool_script (0 = not set, max 34 for P2TR)
    pub pool_script_len: u8,

    /// Pool wallet's BTC scriptPubKey (P2TR = 0x5120 + 32-byte x-only pubkey)
    pub pool_script: [u8; 34],

    /// Solana account address of the Ika dWallet controlling pool BTC custody
    pub ika_dwallet: [u8; 32],

    /// Compressed-x x-only secp256k1 pubkey for the Ika dWallet (Taproot internal key)
    pub ika_dwallet_xonly_pubkey: [u8; 32],

    /// Bump for our program's CPI authority PDA (`[CPI_AUTHORITY_SEED]` against this program ID)
    pub cpi_authority_bump: u8,

    /// Reserved for future use
    _reserved: [u8; 28],
}

impl PoolConfig {
    pub const LEN: usize = core::mem::size_of::<Self>(); // 129 bytes
    pub const SEED: &'static [u8] = b"pool_config";

    /// Maximum pool_script length (P2TR scriptPubKey)
    pub const MAX_SCRIPT_LEN: usize = 34;

    /// Parse from account data
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != POOL_CONFIG_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Parse as mutable from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != POOL_CONFIG_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Initialize a new PoolConfig
    pub fn init(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data[..Self::LEN].fill(0);
        data[0] = POOL_CONFIG_DISCRIMINATOR;
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Get the pool script slice (empty if not set)
    pub fn get_pool_script(&self) -> &[u8] {
        let len = self.pool_script_len as usize;
        if len == 0 || len > Self::MAX_SCRIPT_LEN {
            return &[];
        }
        &self.pool_script[..len]
    }

    /// Set pool script
    pub fn set_pool_script(&mut self, script: &[u8]) -> Result<(), ProgramError> {
        if script.len() > Self::MAX_SCRIPT_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        self.pool_script_len = script.len() as u8;
        self.pool_script = [0u8; 34];
        self.pool_script[..script.len()].copy_from_slice(script);
        Ok(())
    }

    /// Get the Ika dWallet's Solana account address (zeros if not set).
    pub fn get_ika_dwallet(&self) -> &[u8; 32] {
        &self.ika_dwallet
    }

    /// True if `ika_dwallet` is set (non-zero).
    pub fn has_ika_dwallet(&self) -> bool {
        self.ika_dwallet != [0u8; 32]
    }

    /// Set the Ika dWallet account address.
    pub fn set_ika_dwallet(&mut self, key: &[u8; 32]) {
        self.ika_dwallet = *key;
    }

    /// Get the Ika dWallet's x-only secp256k1 pubkey (zeros if not set).
    pub fn get_ika_dwallet_xonly_pubkey(&self) -> &[u8; 32] {
        &self.ika_dwallet_xonly_pubkey
    }

    /// Set the Ika dWallet's x-only secp256k1 pubkey.
    pub fn set_ika_dwallet_xonly_pubkey(&mut self, key: &[u8; 32]) {
        self.ika_dwallet_xonly_pubkey = *key;
    }

    /// Get the cached CPI authority bump.
    pub fn get_cpi_authority_bump(&self) -> u8 {
        self.cpi_authority_bump
    }

    /// Set the cached CPI authority bump.
    pub fn set_cpi_authority_bump(&mut self, bump: u8) {
        self.cpi_authority_bump = bump;
    }
}

#[cfg(test)]
#[path = "pool_config_tests.rs"]
mod tests;
