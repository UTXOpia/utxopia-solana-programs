    use super::*;

    #[test]
    fn test_read_transaction_from_buffer() {
        // Create mock buffer: 32-byte header + 10-byte tx
        let mut buffer = vec![0u8; 32]; // header (authority)
        buffer.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]); // tx data

        let tx = read_transaction_from_buffer(&buffer, 10).unwrap();
        assert_eq!(tx, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_buffer_too_small() {
        let buffer = vec![0u8; 31]; // Less than header size
        assert!(read_transaction_from_buffer(&buffer, 10).is_err());
    }

    #[test]
    fn test_insufficient_tx_data() {
        let mut buffer = vec![0u8; 32]; // header only
        buffer.extend_from_slice(&[1, 2, 3]); // only 3 bytes of tx

        assert!(read_transaction_from_buffer(&buffer, 10).is_err());
    }
