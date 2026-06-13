use super::*;

#[test]
fn test_taptweak_tag_hash_is_correct() {
    // SHA256("TapTweak") should equal our precomputed constant.
    // Note: off-chain tests use a mock SHA256 (XOR-based), so we only
    // verify the constant on-chain where the real syscall is available.
    // Here we just verify the constant is non-zero and has expected length.
    assert_ne!(TAPTWEAK_TAG_HASH, [0u8; 32], "Tag hash must be non-zero");
    assert_eq!(TAPTWEAK_TAG_HASH.len(), 32);

    // Cross-check: the known value SHA256("TapTweak") from BIP-341
    let expected: [u8; 32] = [
        0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50, 0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6,
        0x3e, 0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb, 0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57,
        0xc5, 0xe9,
    ];
    assert_eq!(
        TAPTWEAK_TAG_HASH, expected,
        "Must match BIP-341 known value"
    );
}

#[test]
fn test_u256_conversions_roundtrip() {
    let bytes: [u8; 32] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    let limbs = u256_from_be(&bytes);
    let back = u256_to_be(&limbs);
    assert_eq!(bytes, back);
}

#[test]
fn test_u256_addmod() {
    let n = u256_from_be(&SECP256K1_N);
    let one: U256 = [1, 0, 0, 0];
    let zero: U256 = [0, 0, 0, 0];

    // 0 + 0 = 0
    assert_eq!(u256_addmod(&zero, &zero, &n), zero);

    // 1 + 0 = 1
    assert_eq!(u256_addmod(&one, &zero, &n), one);

    // (n-1) + 1 = 0 mod n
    let n_minus_1 = u256_sub(&n, &one);
    assert_eq!(u256_addmod(&n_minus_1, &one, &n), zero);
}

#[test]
fn test_u256_mulmod() {
    let n = u256_from_be(&SECP256K1_N);
    let one: U256 = [1, 0, 0, 0];
    let two: U256 = [2, 0, 0, 0];
    let three: U256 = [3, 0, 0, 0];
    let six: U256 = [6, 0, 0, 0];

    // 1 * 1 = 1
    assert_eq!(u256_mulmod(&one, &one, &n), one);

    // 2 * 3 = 6
    assert_eq!(u256_mulmod(&two, &three, &n), six);

    // 0 * anything = 0
    let zero: U256 = [0, 0, 0, 0];
    assert_eq!(u256_mulmod(&zero, &two, &n), zero);

    // (n-1) * 1 = n-1
    let n_minus_1 = u256_sub(&n, &one);
    assert_eq!(u256_mulmod(&n_minus_1, &one, &n), n_minus_1);
}

#[test]
fn test_u256_negmod() {
    let n = u256_from_be(&SECP256K1_N);
    let one: U256 = [1, 0, 0, 0];
    let zero: U256 = [0, 0, 0, 0];

    // -0 = 0
    assert_eq!(u256_negmod(&zero, &n), zero);

    // -1 = n-1
    let n_minus_1 = u256_sub(&n, &one);
    assert_eq!(u256_negmod(&one, &n), n_minus_1);
}

#[test]
fn test_extract_p2tr_output_key() {
    // Valid P2TR
    let mut script = [0u8; 34];
    script[0] = 0x51;
    script[1] = 0x20;
    script[2..].fill(0xAB);
    let key = extract_p2tr_output_key(&script).unwrap();
    assert_eq!(key, [0xAB; 32]);

    // Wrong prefix
    let mut bad = script;
    bad[0] = 0x00;
    assert!(extract_p2tr_output_key(&bad).is_none());

    // Wrong length
    assert!(extract_p2tr_output_key(&[0x51, 0x20]).is_none());
}

#[test]
fn test_compute_taptweak_hash_deterministic() {
    let key = [0x42u8; 32];
    let npk = [0x01u8; 32];
    let h1 = compute_taptweak_hash(&key, &npk);
    let h2 = compute_taptweak_hash(&key, &npk);
    assert_eq!(h1, h2);
    assert_ne!(h1, [0u8; 32]); // non-trivial
}

#[test]
fn test_compute_taptweak_hash_different_inputs() {
    let key = [0x42u8; 32];
    let npk1 = [0x01u8; 32];
    let npk2 = [0x02u8; 32];
    assert_ne!(
        compute_taptweak_hash(&key, &npk1),
        compute_taptweak_hash(&key, &npk2),
    );
}

#[test]
fn test_verify_taproot_output_key_with_known_vectors() {
    // Use the SDK's deriveTaprootAddress logic:
    // internal_key = secp256k1 generator x-coordinate
    // npk = some 32-byte value
    // tweak = H_TapTweak(internal_key || npk)
    // outputKey = (internal_key_point + tweak*G).x
    //
    // We verify the ecrecover trick produces the correct result by using
    // a known internal key and checking the math is self-consistent.

    let internal_key: [u8; 32] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98,
    ];
    let npk = [0x42u8; 32];

    // Compute tweak
    let tweak = compute_taptweak_hash(&internal_key, &npk);

    // Use ecrecover to compute the expected output key
    // (this tests the internal consistency of the ecrecover trick)
    let n = u256_from_be(&SECP256K1_N);
    let r = u256_from_be(&internal_key);
    let t = u256_from_be(&tweak);

    let tweak_times_r = u256_mulmod(&t, &r, &n);
    let hash = u256_negmod(&tweak_times_r, &n);
    let hash_bytes = u256_to_be(&hash);

    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(&internal_key);
    signature[32..64].copy_from_slice(&internal_key);

    let mut recovered = [0u8; 64];
    test_secp256k1_recover(&hash_bytes, 0, &signature, &mut recovered).unwrap();

    // The recovered x-coordinate is the expected output key
    let expected_output_key: [u8; 32] = recovered[0..32].try_into().unwrap();

    // Now verify using the public API
    let result = verify_taproot_output_key(&internal_key, &npk, &expected_output_key);
    assert!(
        result.is_ok(),
        "Taproot verification should pass with correct output key"
    );

    // Verify with wrong output key should fail
    let mut wrong_key = expected_output_key;
    wrong_key[0] ^= 0xFF;
    let result = verify_taproot_output_key(&internal_key, &npk, &wrong_key);
    assert!(
        result.is_err(),
        "Taproot verification should fail with wrong output key"
    );
}

#[test]
fn test_verify_rejects_wrong_npk() {
    let internal_key: [u8; 32] = [
        0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B,
        0x07, 0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8,
        0x17, 0x98,
    ];
    let npk_real = [0x42u8; 32];
    let npk_fake = [0x43u8; 32];

    // Compute output key from real npk
    let tweak = compute_taptweak_hash(&internal_key, &npk_real);
    let n = u256_from_be(&SECP256K1_N);
    let r = u256_from_be(&internal_key);
    let t = u256_from_be(&tweak);
    let tweak_times_r = u256_mulmod(&t, &r, &n);
    let hash = u256_negmod(&tweak_times_r, &n);
    let hash_bytes = u256_to_be(&hash);
    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(&internal_key);
    signature[32..64].copy_from_slice(&internal_key);
    let mut recovered = [0u8; 64];
    test_secp256k1_recover(&hash_bytes, 0, &signature, &mut recovered).unwrap();
    let real_output_key: [u8; 32] = recovered[0..32].try_into().unwrap();

    // Verification with wrong npk should fail
    let result = verify_taproot_output_key(&internal_key, &npk_fake, &real_output_key);
    assert!(result.is_err(), "Wrong npk should fail verification");
}
