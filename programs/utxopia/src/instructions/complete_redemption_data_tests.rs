    use super::*;

    fn build_ix_data(
        txid: &[u8; 32],
        tx_size: u32,
        pool_script: &[u8],
        consumed_count: u8,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(38 + pool_script.len());
        buf.extend_from_slice(txid);
        buf.extend_from_slice(&tx_size.to_le_bytes());
        buf.push(pool_script.len() as u8);
        buf.extend_from_slice(pool_script);
        buf.push(consumed_count);
        buf
    }

    #[test]
    fn parses_no_script_no_consumed() {
        let txid = [0x11u8; 32];
        let data = build_ix_data(&txid, 200, &[], 0);
        assert_eq!(data.len(), 38);
        let parsed = CompleteRedemptionData::from_bytes(&data).unwrap();
        assert_eq!(parsed.btc_txid, txid);
        assert_eq!(parsed.tx_size, 200);
        assert_eq!(parsed.pool_script_len, 0);
        assert_eq!(parsed.consumed_utxo_count, 0);
    }

    #[test]
    fn parses_with_pool_script_and_consumed_utxos() {
        let txid = [0x33u8; 32];
        let mut p2tr = vec![0x51u8, 0x20u8];
        p2tr.extend_from_slice(&[0xAAu8; 32]);
        let data = build_ix_data(&txid, 250, &p2tr, 3);
        assert_eq!(data.len(), 38 + 34);
        let parsed = CompleteRedemptionData::from_bytes(&data).unwrap();
        assert_eq!(parsed.pool_script_len, 34);
        assert_eq!(&parsed.pool_script[..34], p2tr.as_slice());
        assert_eq!(parsed.consumed_utxo_count, 3);
    }

    #[test]
    fn rejects_below_min_size() {
        let short = vec![0u8; CompleteRedemptionData::MIN_SIZE - 1];
        assert!(CompleteRedemptionData::from_bytes(&short).is_err());
    }

    #[test]
    fn rejects_missing_consumed_count() {
        let txid = [0u8; 32];
        let mut data = Vec::new();
        data.extend_from_slice(&txid);
        data.extend_from_slice(&100u32.to_le_bytes());
        data.push(0); // pool_script_len
        assert!(CompleteRedemptionData::from_bytes(&data).is_err());
    }

    #[test]
    fn rejects_trailing_bytes() {
        let txid = [0x44u8; 32];
        let mut data = build_ix_data(&txid, 200, &[], 0);
        data.push(0x99);
        assert!(CompleteRedemptionData::from_bytes(&data).is_err());
    }
