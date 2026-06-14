    use super::*;

    /// BN254 Fr modulus p (big-endian) — the boundary for canonical encodings.
    const P: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58,
        0x5d, 0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00,
        0x00, 0x01,
    ];

    #[test]
    fn zero_is_canonical() {
        assert!(is_canonical_fr(&[0u8; 32]));
    }

    #[test]
    fn modulus_is_not_canonical() {
        // p mod p == 0, so the encoding `p` is a non-canonical alias of 0 → must be rejected.
        assert!(!is_canonical_fr(&P));
    }

    #[test]
    fn modulus_minus_one_is_canonical() {
        let mut p_minus_1 = P;
        p_minus_1[31] = 0x00; // ...f000_0001 -> ...f000_0000 = p-1, the largest valid element
        assert!(is_canonical_fr(&p_minus_1));
    }

    #[test]
    fn all_ones_is_not_canonical() {
        // 2^256-1 is far above p → the classic `n + k*p` alias family that enabled the
        // nullifier double-spend.
        assert!(!is_canonical_fr(&[0xff; 32]));
    }

    #[test]
    fn modulus_plus_one_is_not_canonical() {
        let mut p_plus_1 = P;
        p_plus_1[31] = 0x02; // p+1, a non-canonical alias of 1
        assert!(!is_canonical_fr(&p_plus_1));
    }
