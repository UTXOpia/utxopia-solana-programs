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
    assert!(
        check_redemption_signing(pool, MAX_REDEMPTION_AMOUNT_SATS, MAX_MINER_FEE_SATS,).is_ok()
    );
}

#[test]
fn rejects_amount_over_limit() {
    let buf = unpaused_pool();
    let pool = PoolState::from_bytes(&buf).unwrap();
    let err = check_redemption_signing(pool, MAX_REDEMPTION_AMOUNT_SATS + 1, 0).unwrap_err();
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

#[test]
fn bps_fee_has_one_unit_minimum_when_configured() {
    assert_eq!(compute_bps_fee(1, 1), 1);
    assert_eq!(compute_bps_fee(9_999, 1), 1);
    assert_eq!(compute_bps_fee(10_000, 1), 1);
}

#[test]
fn bps_fee_stays_zero_when_amount_or_rate_is_zero() {
    assert_eq!(compute_bps_fee(0, 100), 0);
    assert_eq!(compute_bps_fee(100, 0), 0);
}

// ---- who may drive a redemption's BTC legs ----------------------------------

const OPERATOR: [u8; 32] = [1; 32];
const REQUESTER: [u8; 32] = [2; 32];
const STRANGER: [u8; 32] = [3; 32];

#[test]
fn the_operator_drives_a_redemption_as_before() {
    assert!(redemption_driver_is_allowed(&OPERATOR, &OPERATOR, &REQUESTER).is_ok());
}

/// The guarantee this exists for: an operator who stops answering can slow a
/// withdrawal down but never prevent it.
#[test]
fn the_requester_can_drive_their_own_redemption() {
    assert!(redemption_driver_is_allowed(&REQUESTER, &OPERATOR, &REQUESTER).is_ok());
}

/// It is not open to the world: a third party could otherwise push a redemption
/// into Processing with a bad input set, which only a cancel can undo.
#[test]
fn a_stranger_cannot_drive_someone_elses_redemption() {
    assert_eq!(
        redemption_driver_is_allowed(&STRANGER, &OPERATOR, &REQUESTER).unwrap_err(),
        UTXOpiaError::Unauthorized.into()
    );
}

#[test]
fn a_short_or_long_signer_never_matches() {
    assert!(redemption_driver_is_allowed(&OPERATOR[..31], &OPERATOR, &REQUESTER).is_err());
    assert!(redemption_driver_is_allowed(&[1u8; 33], &OPERATOR, &REQUESTER).is_err());
}
