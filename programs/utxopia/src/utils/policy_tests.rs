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
