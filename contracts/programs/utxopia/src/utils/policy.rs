//! Pure on-chain signing policy for redemptions.
//!
//! This is the *minimal* port of `frost_server/src/policy.rs` — only the
//! validation predicates that (a) are computable from on-chain data alone,
//! and (b) are not already covered elsewhere in `complete_redemption`.
//!
//! Surviving from the FROST policy:
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
/// Symmetric with the FROST signers' independent verification: even though
/// Ika is one entity, we still gate the on-chain CPI so that a compromised
/// backend cannot drain funds by submitting forged sighashes for sky-high
/// amounts.
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
mod tests {
    use super::*;

    fn unpaused_pool() -> Vec<u8> {
        let mut buf = vec![0u8; PoolState::LEN];
        let p = PoolState::init(&mut buf).expect("init pool");
        assert!(!p.is_paused(), "fresh pool must start unpaused");
        buf
    }

    #[test]
    fn accepts_amount_and_fee_at_limit() {
        let buf = unpaused_pool();
        let pool = PoolState::from_bytes(&buf).unwrap();
        assert!(check_redemption_signing(
            pool,
            MAX_REDEMPTION_AMOUNT_SATS,
            MAX_MINER_FEE_SATS,
        )
        .is_ok());
    }

    #[test]
    fn rejects_amount_over_limit() {
        let buf = unpaused_pool();
        let pool = PoolState::from_bytes(&buf).unwrap();
        let err =
            check_redemption_signing(pool, MAX_REDEMPTION_AMOUNT_SATS + 1, 0).unwrap_err();
        assert_eq!(err, UTXOpiaError::RedemptionAmountExceedsLimit.into());
    }

    #[test]
    fn rejects_fee_over_limit() {
        let buf = unpaused_pool();
        let pool = PoolState::from_bytes(&buf).unwrap();
        let err = check_redemption_signing(pool, 0, MAX_MINER_FEE_SATS + 1).unwrap_err();
        assert_eq!(err, UTXOpiaError::RedemptionFeeExceedsLimit.into());
    }

    #[test]
    fn rejects_when_paused() {
        let mut buf = unpaused_pool();
        {
            let p = PoolState::from_bytes_mut(&mut buf).unwrap();
            p.set_paused(true);
        }
        let pool = PoolState::from_bytes(&buf).unwrap();
        let err = check_redemption_signing(pool, 0, 0).unwrap_err();
        assert_eq!(err, UTXOpiaError::PoolPaused.into());
    }
}
