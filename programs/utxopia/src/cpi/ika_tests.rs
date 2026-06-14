    use super::*;

    /// Recon-brief vectors: the byte layout of `approve_message` instruction data
    /// must exactly match the upstream contract. See
    /// `chains/solana/program-sdk/pinocchio/src/cpi.rs:62` in `dwallet-labs/ika-pre-alpha`.
    #[test]
    fn approve_message_ix_data_layout_taproot() {
        let bump = 0xAB;
        let mut sighash = [0u8; 32];
        for (i, b) in sighash.iter_mut().enumerate() {
            *b = i as u8; // 0x00, 0x01, ..., 0x1F
        }
        let metadata = [0u8; 32];
        let mut user = [0u8; 32];
        for (i, b) in user.iter_mut().enumerate() {
            *b = 0xCC ^ (i as u8);
        }

        let data = build_approve_message_ix_data(
            bump,
            &sighash,
            &metadata,
            &user,
            SIG_SCHEME_TAPROOT_SHA256,
        );

        // Total length is exactly 100 bytes.
        assert_eq!(data.len(), 100);
        // [0]: discriminator
        assert_eq!(data[0], IX_APPROVE_MESSAGE);
        assert_eq!(data[0], 8);
        // [1]: bump
        assert_eq!(data[1], 0xAB);
        // [2..34]: message_digest
        assert_eq!(&data[2..34], &sighash);
        // [34..66]: message_metadata_digest
        assert_eq!(&data[34..66], &metadata);
        // [66..98]: user_pubkey
        assert_eq!(&data[66..98], &user);
        // [98..100]: signature_scheme little-endian u16
        assert_eq!(&data[98..100], &3u16.to_le_bytes());
    }

    #[test]
    fn approve_message_ix_data_signature_scheme_constants_match_recon() {
        // The upstream enum (crates/ika-dwallet-types/src/lib.rs:163) assigns
        // these explicit u16 discriminants. Drift caught here at compile time.
        assert_eq!(SIG_SCHEME_ECDSA_SHA256, 1);
        assert_eq!(SIG_SCHEME_ECDSA_DOUBLE_SHA256, 2);
        assert_eq!(SIG_SCHEME_TAPROOT_SHA256, 3);
    }

    #[test]
    fn approve_message_ix_data_zero_inputs_round_trip() {
        let zeros = [0u8; 32];
        let data =
            build_approve_message_ix_data(0, &zeros, &zeros, &zeros, SIG_SCHEME_ECDSA_SHA256);
        assert_eq!(data[0], IX_APPROVE_MESSAGE);
        assert_eq!(data[1], 0);
        assert!(data[2..98].iter().all(|&b| b == 0));
        assert_eq!(&data[98..100], &1u16.to_le_bytes());
    }

    #[test]
    fn approve_message_ix_data_distinguishes_metadata_from_user() {
        let sighash = [0xAAu8; 32];
        let meta = [0xBBu8; 32];
        let user = [0xCCu8; 32];

        let data =
            build_approve_message_ix_data(7, &sighash, &meta, &user, SIG_SCHEME_TAPROOT_SHA256);

        assert_eq!(data[2..34], [0xAAu8; 32]);
        assert_eq!(data[34..66], [0xBBu8; 32]);
        assert_eq!(data[66..98], [0xCCu8; 32]);
    }

    #[test]
    fn cpi_authority_seed_matches_recon() {
        // Upstream constant: `pub const CPI_AUTHORITY_SEED: &[u8] = b"__ika_cpi_authority";`
        // (chains/solana/program-sdk/pinocchio/src/lib.rs:53)
        assert_eq!(CPI_AUTHORITY_SEED, b"__ika_cpi_authority");
    }
