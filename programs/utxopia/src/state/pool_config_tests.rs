    use super::*;

    #[test]
    fn test_pool_config_size() {
        // 1 disc + 1 len + 34 script + 32 ika_dwallet
        // + 32 ika_xonly + 1 bump + 28 reserved = 129
        assert_eq!(PoolConfig::LEN, 129);
    }

    #[test]
    fn test_pool_config_init_and_set() {
        let mut buf = vec![0u8; PoolConfig::LEN];
        let config = PoolConfig::init(&mut buf).unwrap();

        assert_eq!(config.pool_script_len, 0);
        assert_eq!(config.get_pool_script(), &[] as &[u8]);

        // P2TR script: 0x5120 + 32 bytes
        let mut script = [0u8; 34];
        script[0] = 0x51;
        script[1] = 0x20;
        script[2..].fill(0xAB);

        config.set_pool_script(&script).unwrap();
        assert_eq!(config.pool_script_len, 34);
        assert_eq!(config.get_pool_script(), &script);
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
        }
        let config = PoolConfig::from_bytes(&buf).unwrap();
        assert_eq!(config.get_pool_script(), &[0x51, 0x20, 0x01, 0x02]);
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
