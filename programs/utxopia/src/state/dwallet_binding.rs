//! dWallet binding account
//!
//! Records which pool owns an Ika dWallet. PDA seeds = ["dwallet_binding",
//! ika_dwallet], so the account's existence proves the dWallet is already some
//! pool's custody key — the same existence-as-a-lock pattern `DepositReceipt`
//! uses to make a BTC deposit creditable exactly once.
//!
//! Without it nothing stops two pools from naming the same dWallet, and two
//! pools that share a dWallet share one Taproot address and therefore one
//! indistinguishable UTXO set. Their bitcoin is then pooled while their
//! accounting is kept apart, so either pool's redemption can spend the other's
//! coins and neither pool's balance means anything on its own. That state is
//! reachable today by an ordinary `set_pool_config` call with no error
//! anywhere, which is why the invariant belongs in the program rather than in
//! whoever is running the deploy.
//!
//! The owning pool is stored, not just a marker byte, so the binding can be
//! read in both directions: a pool names its dWallet in `PoolConfig`, and the
//! dWallet names its pool here.

use crate::pinocchio_compat::ProgramError;

/// Discriminator for DwalletBinding account
pub const DWALLET_BINDING_DISCRIMINATOR: u8 = 0x15;

/// Binds one Ika dWallet to exactly one pool.
#[repr(C)]
pub struct DwalletBinding {
    /// Account discriminator (0x15)
    pub discriminator: u8,

    /// The pool that owns this dWallet
    pub pool_state: [u8; 32],
}

impl DwalletBinding {
    pub const LEN: usize = core::mem::size_of::<Self>(); // 33 bytes
    pub const SEED: &'static [u8] = b"dwallet_binding";

    /// Initialize the binding, recording the owning pool.
    pub fn init(data: &mut [u8], pool_state: &[u8; 32]) -> Result<(), ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data[0] = DWALLET_BINDING_DISCRIMINATOR;
        data[1..1 + 32].copy_from_slice(pool_state);
        Ok(())
    }

    /// Read the owning pool from an initialized binding.
    pub fn pool_state(data: &[u8]) -> Result<[u8; 32], ProgramError> {
        if data.len() < Self::LEN || data[0] != DWALLET_BINDING_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut pool = [0u8; 32];
        pool.copy_from_slice(&data[1..1 + 32]);
        Ok(pool)
    }
}

#[cfg(test)]
#[path = "dwallet_binding_tests.rs"]
mod tests;
