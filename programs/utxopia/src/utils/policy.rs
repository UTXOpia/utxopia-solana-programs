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
//! - sighash recomputation: now done in `approve_redemption_signing`, which
//!   rebuilds the BIP-341 preimage from trusted on-chain state rather than
//!   trusting the caller's value.
//! - destination whitelist: redemption PDA's `btc_script` already pins this,
//!   which is why the later BTC legs need no registry check of their own.
//! - UTXO existence check: requires Esplora HTTP.
//! - duplicate signing: `CompletionReceipt` PDA already prevents this.
//! - cross-validate outputs: `complete_redemption` already does this against
//!   the SPV-verified broadcast tx.
//! - mempool already-paid check: requires Esplora HTTP.

use crate::pinocchio_compat::ProgramError;

use crate::error::UTXOpiaError;
use crate::state::PoolState;

/// Maximum gross redemption amount per signing operation, in satoshis.
/// Set conservatively at 1 BTC for the hackathon — bumps require redeploy.
pub const MAX_REDEMPTION_AMOUNT_SATS: u64 = 100_000_000;

/// Maximum allowed miner fee per signing operation, in satoshis.
pub const MAX_MINER_FEE_SATS: u64 = 50_000;

/// Who may drive a redemption's BTC legs (`mark_processing`,
/// `approve_redemption_signing`, `complete_redemption`).
///
/// The pool authority runs these as ordinary operations. The requester may run
/// them too, because none of the three decides anything: the destination is
/// fixed in the RedemptionRequest when `redeem` creates it, the input set is
/// committed at `mark_processing`, and the signed transaction is reconstructed
/// on chain from that state. The authority signature was an operational gate,
/// never a security one — and left alone it let an operator who stops answering
/// strand a withdrawal that the pool has no right to prevent.
///
/// What the driver still picks is bounded: the UTXO set (validated and summed
/// on chain, capped per call) and the miner fee (capped at both
/// `MAX_MINER_FEE_SATS` and the redemption's own prepaid `service_fee`, so a
/// wasteful choice can only burn what that redemption already paid).
pub fn redemption_driver_is_allowed(
    signer: &[u8],
    pool_authority: &[u8; 32],
    requester: &[u8; 32],
) -> Result<(), ProgramError> {
    if signer == &pool_authority[..] || signer == &requester[..] {
        Ok(())
    } else {
        Err(UTXOpiaError::Unauthorized.into())
    }
}

/// Compute a basis-point fee, charging at least one base unit whenever both
/// the amount and configured rate are non-zero.
pub fn compute_bps_fee(amount: u64, fee_bps: u16) -> u64 {
    let fee = (amount as u128 * fee_bps as u128 / 10_000) as u64;
    if fee == 0 && amount > 0 && fee_bps > 0 {
        1
    } else {
        fee
    }
}

/// Run all pre-CPI signing policy checks.
///
/// Called from `approve_redemption_signing` *before* the Ika `approve_message` CPI.
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
