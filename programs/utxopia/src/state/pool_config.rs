//! Pool configuration PDA — extended fields that don't fit in PoolState
//!
//! Stores the pool's BTC scriptPubKey (P2TR) and FROST group public key
//! on-chain for trustless verification in `complete_redemption` and
//! `verify_deposit`.
//!
//! PDA seeds: ["pool_config"]

use pinocchio::program_error::ProgramError;

/// Discriminator for PoolConfig account
pub const POOL_CONFIG_DISCRIMINATOR: u8 = 0x0A;

/// Pool configuration account (zero-copy layout, 161 bytes)
///
/// Field history:
/// - `group_pub_key` is the legacy FROST group key. New pools (Ika-controlled)
///   leave it zero; `verify_deposit` falls back to the Ika x-only pubkey.
/// - `ika_dwallet`, `ika_dwallet_xonly_pubkey`, `cpi_authority_bump` are the
///   Ika-era custody fields (2026-05).
#[repr(C)]
pub struct PoolConfig {
    /// Account discriminator (1 byte)
    pub discriminator: u8,

    /// Length of pool_script (0 = not set, max 34 for P2TR)
    pub pool_script_len: u8,

    /// Pool wallet's BTC scriptPubKey (P2TR = 0x5120 + 32-byte x-only pubkey)
    pub pool_script: [u8; 34],

    /// FROST group x-only public key (legacy; zero for Ika-controlled pools)
    pub group_pub_key: [u8; 32],

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
    pub const LEN: usize = core::mem::size_of::<Self>(); // 161 bytes
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

    /// Get the FROST group public key (returns zeros if not set)
    pub fn get_group_pub_key(&self) -> &[u8; 32] {
        &self.group_pub_key
    }

    /// Check if group_pub_key is set (non-zero)
    pub fn has_group_pub_key(&self) -> bool {
        self.group_pub_key != [0u8; 32]
    }

    /// Set the FROST group public key
    pub fn set_group_pub_key(&mut self, key: &[u8; 32]) {
        self.group_pub_key = *key;
    }

    // ── Ika-era accessors ──

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
mod tests {
    use super::*;

    #[test]
    fn test_pool_config_size() {
        // 1 disc + 1 len + 34 script + 32 group + 32 ika_dwallet
        // + 32 ika_xonly + 1 bump + 28 reserved = 161
        assert_eq!(PoolConfig::LEN, 161);
    }

    #[test]
    fn test_pool_config_init_and_set() {
        let mut buf = vec![0u8; PoolConfig::LEN];
        let config = PoolConfig::init(&mut buf).unwrap();

        assert_eq!(config.pool_script_len, 0);
        assert_eq!(config.get_pool_script(), &[] as &[u8]);
        assert!(!config.has_group_pub_key());

        // P2TR script: 0x5120 + 32 bytes
        let mut script = [0u8; 34];
        script[0] = 0x51;
        script[1] = 0x20;
        script[2..].fill(0xAB);

        config.set_pool_script(&script).unwrap();
        assert_eq!(config.pool_script_len, 34);
        assert_eq!(config.get_pool_script(), &script);

        // Group pub key
        let key = [0x42u8; 32];
        config.set_group_pub_key(&key);
        assert!(config.has_group_pub_key());
        assert_eq!(config.get_group_pub_key(), &key);
    }

    #[test]
    fn test_pool_config_script_too_long() {
        let mut buf = vec![0u8; PoolConfig::LEN];
        let config = PoolConfig::init(&mut buf).unwrap();

        let script = [0u8; 35];
        assert!(config.set_pool_script(&script).is_err());
    }

    #[test]
    fn test_pool_config_roundtrip() {
        let mut buf = vec![0u8; PoolConfig::LEN];
        {
            let config = PoolConfig::init(&mut buf).unwrap();
            let script = [0x51, 0x20, 0x01, 0x02];
            config.set_pool_script(&script).unwrap();
            config.set_group_pub_key(&[0xBB; 32]);
        }
        let config = PoolConfig::from_bytes(&buf).unwrap();
        assert_eq!(config.get_pool_script(), &[0x51, 0x20, 0x01, 0x02]);
        assert_eq!(config.get_group_pub_key(), &[0xBB; 32]);
    }

    #[test]
    fn test_pool_config_round_trips_ika_dwallet() {
        let mut buf = vec![0u8; PoolConfig::LEN];
        {
            let config = PoolConfig::init(&mut buf).unwrap();
            let dwallet = [0x07u8; 32];
            let xonly = [0x42u8; 32];
            config.set_ika_dwallet(&dwallet);
            config.set_ika_dwallet_xonly_pubkey(&xonly);
            config.set_cpi_authority_bump(255);
        }
        let config = PoolConfig::from_bytes(&buf).unwrap();
        assert_eq!(config.get_ika_dwallet(), &[0x07u8; 32]);
        assert_eq!(config.get_ika_dwallet_xonly_pubkey(), &[0x42u8; 32]);
        assert_eq!(config.get_cpi_authority_bump(), 255);
        assert!(config.has_ika_dwallet());

        // group_pub_key remains zero — these are independent fields.
        assert!(!config.has_group_pub_key());
    }

    #[test]
    fn test_pool_config_ika_unset_returns_zero() {
        let mut buf = vec![0u8; PoolConfig::LEN];
        let config = PoolConfig::init(&mut buf).unwrap();
        assert!(!config.has_ika_dwallet());
        assert_eq!(config.get_ika_dwallet(), &[0u8; 32]);
        assert_eq!(config.get_ika_dwallet_xonly_pubkey(), &[0u8; 32]);
        assert_eq!(config.get_cpi_authority_bump(), 0);
    }
}
