    use super::*;

    #[test]
    fn take_bytes_rejects_short_input_without_advancing() {
        let data = [1u8, 2, 3];
        let mut offset = 1usize;

        let err = take_bytes(&data, &mut offset, 4).unwrap_err();

        assert_eq!(err, ProgramError::InvalidInstructionData);
        assert_eq!(offset, 1);
    }

    #[test]
    fn read_u64_le_advances_offset() {
        let data = [9u8, 8, 7, 6, 5, 4, 3, 2, 1];
        let mut offset = 1usize;

        let value = read_u64_le(&data, &mut offset).unwrap();

        assert_eq!(value, u64::from_le_bytes([8, 7, 6, 5, 4, 3, 2, 1]));
        assert_eq!(offset, data.len());
    }

    /// Build a JoinSplit(1,1) instruction body (proof_source=0, 1 tree output) with the
    /// given nullifier bytes. Layout: header(4) + proof(256) + root(32) + bound(32) +
    /// nullifier(32) + commitment(32) + stealth(72).
    fn joinsplit_1x1_with_nullifier(nullifier: [u8; 32]) -> Vec<u8> {
        let mut d = vec![1u8, 1, 1, 0]; // n_in=1, n_out=1, n_pub=1, proof_source=0
        d.extend_from_slice(&[0u8; GROTH16_PROOF_SIZE]); // proof
        d.extend_from_slice(&[0u8; 32]); // merkle_root
        d.extend_from_slice(&[0u8; 32]); // bound_params_hash
        d.extend_from_slice(&nullifier); // nullifier
        d.extend_from_slice(&[0u8; 32]); // commitment_out
        d.extend_from_slice(&[0u8; STEALTH_DATA_PER_OUTPUT]); // stealth for 1 tree output
        d
    }

    #[test]
    fn parse_prefix_accepts_canonical_nullifier() {
        let data = joinsplit_1x1_with_nullifier([0u8; 32]);
        let header = parse_header(&data).unwrap();
        let mut proof_buf = [0u8; GROTH16_PROOF_SIZE];
        // proof_source==0 path never indexes accounts, so an empty slice is fine.
        let res = parse_prefix(&data, &[], header, 1, &mut proof_buf);
        assert!(res.is_ok(), "canonical nullifier should parse");
    }

    #[test]
    fn parse_prefix_rejects_noncanonical_nullifier() {
        // 0xff..ff >= BN254 Fr modulus: a non-canonical alias that the alt_bn128 syscall
        // would reduce to the same field element while seeding a *different* nullifier PDA.
        // This is the double-spend vector — parsing must reject it outright.
        let data = joinsplit_1x1_with_nullifier([0xffu8; 32]);
        let header = parse_header(&data).unwrap();
        let mut proof_buf = [0u8; GROTH16_PROOF_SIZE];
        let res = parse_prefix(&data, &[], header, 1, &mut proof_buf);
        assert!(res.is_err(), "non-canonical nullifier must be rejected");
    }
