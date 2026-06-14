    use super::*;

    #[test]
    fn test_token_config_size() {
        assert_eq!(TokenConfig::LEN, 164);
    }

    #[test]
    fn test_token_config_init_roundtrip() {
        let mut buf = vec![0u8; TokenConfig::LEN];
        let tc = TokenConfig::init(&mut buf).unwrap();
        tc.set_service_fee(1000);
        tc.set_min_deposit(5000);
        tc.set_max_deposit(1_000_000);
        tc.set_deposit_cap(100_000_000);
        tc.set_enabled(true);

        let tc2 = TokenConfig::from_bytes(&buf).unwrap();
        assert_eq!(tc2.service_fee(), 1000);
        assert_eq!(tc2.min_deposit(), 5000);
        assert_eq!(tc2.max_deposit(), 1_000_000);
        assert_eq!(tc2.deposit_cap(), 100_000_000);
        assert!(tc2.is_enabled());
        assert_eq!(tc2.total_shielded(), 0);
        assert_eq!(tc2.accumulated_fees(), 0);
    }

    #[test]
    fn test_token_config_add_sub_shielded() {
        let mut buf = vec![0u8; TokenConfig::LEN];
        let tc = TokenConfig::init(&mut buf).unwrap();

        tc.add_shielded(50_000).unwrap();
        assert_eq!(tc.total_shielded(), 50_000);

        tc.add_shielded(30_000).unwrap();
        assert_eq!(tc.total_shielded(), 80_000);

        tc.sub_shielded(20_000).unwrap();
        assert_eq!(tc.total_shielded(), 60_000);
    }

    #[test]
    fn test_token_config_add_sub_fees() {
        let mut buf = vec![0u8; TokenConfig::LEN];
        let tc = TokenConfig::init(&mut buf).unwrap();

        tc.add_fees(1000).unwrap();
        assert_eq!(tc.accumulated_fees(), 1000);

        tc.sub_fees(500).unwrap();
        assert_eq!(tc.accumulated_fees(), 500);
    }

    #[test]
    fn test_token_config_sub_shielded_underflow() {
        let mut buf = vec![0u8; TokenConfig::LEN];
        let tc = TokenConfig::init(&mut buf).unwrap();
        assert!(tc.sub_shielded(1).is_err());
    }

    #[test]
    fn test_token_config_invalid_discriminator() {
        let buf = vec![0u8; TokenConfig::LEN];
        assert!(TokenConfig::from_bytes(&buf).is_err());
    }
