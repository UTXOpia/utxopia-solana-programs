//! Pure on-chain signing policy for redemptions.
//!
//! This module keeps only validation predicates that (a) are computable from
//! on-chain data alone, and (b) are not already covered elsewhere in
//! `complete_redemption`:
//! - amount limit (max gross redemption per signing operation)
//! - fee limit  (max miner fee per signing operation)
//! - paused state (pool-wide kill switch)
//!
//! Dropped (handled elsewhere or impossible on-chain):
//! - sighash recomputation: too expensive on-chain; sighash arrives opaque
//!   in instruction data, signed off-chain by Ika.
//! - destination whitelist: redemption PDA's `btc_script` already pins this.
//! - UTXO existence check: requires Esplora HTTP.
//! - duplicate signing: `CompletionReceipt` PDA already prevents this.
//! - cross-validate outputs: `complete_redemption` already does this against
//!   the SPV-verified broadcast tx.
//! - mempool already-paid check: requires Esplora HTTP.

use pinocchio::program_error::ProgramError;

use crate::error::UTXOpiaError;
use crate::state::PoolState;

/// Maximum gross redemption amount per signing operation, in satoshis.
/// Set conservatively at 1 BTC for the hackathon — bumps require redeploy.
pub const MAX_REDEMPTION_AMOUNT_SATS: u64 = 100_000_000;

/// Maximum allowed miner fee per signing operation, in satoshis.
pub const MAX_MINER_FEE_SATS: u64 = 50_000;

/// Run all pre-CPI signing policy checks.
///
/// Called from `complete_redemption` *before* the Ika `approve_message` CPI.
/// Gate the on-chain Ika CPI so a compromised backend cannot drain funds by
/// submitting forged sighashes for sky-high amounts.
pub fn check_redemption_signing(
    pool: &PoolState,
    amount_sats: u64,
    miner_fee_sats: u64,
) -> Result<(), ProgramError> {
    if pool.is_paused() {
        return Err(UTXOpiaError::PoolPaused.into());
    }
    if amount_sats > MAX_REDEMPTION_AMOUNT_SATS {
        return Err(UTXOpiaError::RedemptionAmountExceedsLimit.into());
    }
    if miner_fee_sats > MAX_MINER_FEE_SATS {
        return Err(UTXOpiaError::RedemptionFeeExceedsLimit.into());
    }
    Ok(())
}

#[cfg(test)]
#[path = "policy_tests.rs"]
mod tests;
