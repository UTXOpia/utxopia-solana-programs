use super::*;

#[test]
fn test_poseidon2_hash_deterministic() {
    let left = [1u8; 32];
    let right = [2u8; 32];

    let hash1 = poseidon2_hash(&left, &right).unwrap();
    let hash2 = poseidon2_hash(&left, &right).unwrap();

    assert_eq!(hash1, hash2, "Hash should be deterministic");
}

#[test]
fn test_poseidon2_hash_different_inputs() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];

    let hash_ab = poseidon2_hash(&a, &b).unwrap();
    let hash_ac = poseidon2_hash(&a, &c).unwrap();
    let hash_ba = poseidon2_hash(&b, &a).unwrap();

    assert_ne!(
        hash_ab, hash_ac,
        "Different inputs should produce different hashes"
    );
    assert_ne!(hash_ab, hash_ba, "Order should matter");
}

#[test]
fn test_poseidon3_hash_deterministic() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];

    let hash1 = poseidon3_hash(&a, &b, &c).unwrap();
    let hash2 = poseidon3_hash(&a, &b, &c).unwrap();

    assert_eq!(hash1, hash2, "Poseidon3 hash should be deterministic");
}

#[test]
fn test_poseidon3_hash_different_inputs() {
    let a = [1u8; 32];
    let b = [2u8; 32];
    let c = [3u8; 32];
    let d = [4u8; 32];

    let hash_abc = poseidon3_hash(&a, &b, &c).unwrap();
    let hash_abd = poseidon3_hash(&a, &b, &d).unwrap();

    assert_ne!(
        hash_abc, hash_abd,
        "Different inputs should produce different hashes"
    );
}

#[test]
fn test_compute_commitment() {
    let npk = [0x42u8; 32];
    let token_id = [0x01u8; 32];
    let amount_sats = 100_000u64;

    let commitment1 = compute_commitment(&npk, &token_id, amount_sats).unwrap();
    let commitment2 = compute_commitment(&npk, &token_id, amount_sats).unwrap();

    assert_eq!(
        commitment1, commitment2,
        "Commitment should be deterministic"
    );

    // Different amount should give different commitment
    let commitment3 = compute_commitment(&npk, &token_id, 200_000).unwrap();
    assert_ne!(
        commitment1, commitment3,
        "Different amounts should give different commitments"
    );

    // Different npk should give different commitment
    let npk2 = [0x43u8; 32];
    let commitment4 = compute_commitment(&npk2, &token_id, amount_sats).unwrap();
    assert_ne!(
        commitment1, commitment4,
        "Different npks should give different commitments"
    );

    // Different token_id should give different commitment
    let token_id2 = [0x02u8; 32];
    let commitment5 = compute_commitment(&npk, &token_id2, amount_sats).unwrap();
    assert_ne!(
        commitment1, commitment5,
        "Different token_ids should give different commitments"
    );
}

#[test]
fn test_merkle_root_computation() {
    let leaf = [1u8; 32];
    let siblings = [[2u8; 32], [3u8; 32]];

    let root = compute_merkle_root(&leaf, 0, &siblings).unwrap();

    // Root should be deterministic
    let root2 = compute_merkle_root(&leaf, 0, &siblings).unwrap();
    assert_eq!(root, root2);
}

#[test]
fn test_reduce_to_field_exact_below_modulus() {
    // Value below modulus should be unchanged
    let val = [0x10u8; 32];
    assert_eq!(reduce_to_field_exact(&val), val);
}

#[test]
fn test_reduce_to_field_exact_equal_to_modulus() {
    // Value equal to modulus should reduce to zero
    let result = reduce_to_field_exact(&BN254_FR_MODULUS);
    assert_eq!(result, [0u8; 32]);
}

#[test]
fn test_reduce_to_field_exact_above_modulus() {
    // Value above modulus should reduce correctly
    let mut val = BN254_FR_MODULUS;
    val[31] = val[31].wrapping_add(1); // modulus + 1
    let result = reduce_to_field_exact(&val);
    let mut expected = [0u8; 32];
    expected[31] = 1;
    assert_eq!(result, expected);
}

#[test]
fn test_reduce_to_field_exact_max_value() {
    // 0xFF...FF should reduce to a value < modulus
    let val = [0xFFu8; 32];
    let result = reduce_to_field_exact(&val);
    assert!(!is_ge_modulus(&result), "Result must be < modulus");
}

#[test]
fn test_burn_commitment_zero_npk() {
    // Unshield/redeem uses npk = 0x00..00 — verify it produces a deterministic non-zero result
    let zero_npk = [0u8; 32];
    let token_id = [0x01u8; 32];
    let amount = 100_000u64;

    let commitment = compute_commitment(&zero_npk, &token_id, amount).unwrap();
    assert_ne!(commitment, [0u8; 32], "Burn commitment must be non-zero");

    // Deterministic
    let commitment2 = compute_commitment(&zero_npk, &token_id, amount).unwrap();
    assert_eq!(commitment, commitment2);

    // Different amounts produce different commitments
    let commitment3 = compute_commitment(&zero_npk, &token_id, 200_000).unwrap();
    assert_ne!(
        commitment, commitment3,
        "Different burn amounts must produce different commitments"
    );
}

#[test]
fn test_compute_token_id_deterministic() {
    let mint = [0xABu8; 32];
    let id1 = compute_token_id(&mint).unwrap();
    let id2 = compute_token_id(&mint).unwrap();
    assert_eq!(id1, id2, "Token ID should be deterministic");

    let mint2 = [0xCDu8; 32];
    let id3 = compute_token_id(&mint2).unwrap();
    assert_ne!(
        id1, id3,
        "Different mints should produce different token IDs"
    );
}

#[test]
fn test_bound_params_hash_deterministic() {
    let stealth = [0u8; 32];
    let hash1 = compute_bound_params_hash_private_transfer(103, &stealth);
    let hash2 = compute_bound_params_hash_private_transfer(103, &stealth);
    assert_eq!(hash1, hash2);
}

#[test]
fn test_bound_params_hash_different_chain_ids() {
    let stealth = [0u8; 32];
    let devnet = compute_bound_params_hash_private_transfer(103, &stealth);
    let mainnet = compute_bound_params_hash_private_transfer(101, &stealth);
    assert_ne!(
        devnet, mainnet,
        "Different chain IDs must produce different hashes"
    );
}

#[test]
fn test_bound_params_hash_is_valid_field_element() {
    let stealth = [0u8; 32];
    let hash = compute_bound_params_hash_private_transfer(103, &stealth);
    assert!(
        !is_ge_modulus(&hash),
        "Hash must be a valid BN254 field element"
    );
}

#[test]
fn test_bound_params_hash_different_stealth_data() {
    let stealth_a = [0xAAu8; 32];
    let stealth_b = [0xBBu8; 32];
    let hash_a = compute_bound_params_hash_private_transfer(103, &stealth_a);
    let hash_b = compute_bound_params_hash_private_transfer(103, &stealth_b);
    assert_ne!(
        hash_a, hash_b,
        "Different stealth data must produce different hashes"
    );
}

#[test]
fn test_bound_params_hash_redeem_binds_btc_script() {
    let stealth = [0u8; 32];
    let script_a = [0x51u8, 0x20, 0xAAu8, 0xBB]; // dummy P2TR-like
    let script_b = [0x51u8, 0x20, 0xCC, 0xDD];
    let hash_a = compute_bound_params_hash_redeem(103, &script_a, &stealth);
    let hash_b = compute_bound_params_hash_redeem(103, &script_b, &stealth);
    assert_ne!(
        hash_a, hash_b,
        "Different BTC scripts must produce different hashes"
    );

    // Same script, same stealth → deterministic
    let hash_a2 = compute_bound_params_hash_redeem(103, &script_a, &stealth);
    assert_eq!(hash_a, hash_a2, "Same inputs must produce same hash");
}

#[test]
fn test_bound_params_hash_redeem_binds_stealth() {
    let stealth_a = [0xAAu8; 32];
    let stealth_b = [0xBBu8; 32];
    let script = [0x51u8, 0x20, 0xAA, 0xBB];
    let hash_a = compute_bound_params_hash_redeem(103, &script, &stealth_a);
    let hash_b = compute_bound_params_hash_redeem(103, &script, &stealth_b);
    assert_ne!(
        hash_a, hash_b,
        "Different stealth data must produce different redeem hashes"
    );
}

/// Cross-language test vectors — these hex values must match the SDK tests.
#[test]
fn test_bound_params_cross_lang_vectors() {
    let stealth = [0u8; 32]; // zero stealth hash

    // Vector 1: private transfer, chain_id=103, zero stealth
    let transfer = compute_bound_params_hash_private_transfer(103, &stealth);
    let transfer_hex: String = transfer.iter().map(|b| format!("{:02x}", b)).collect();
    println!("VECTOR_transfer={}", transfer_hex);

    // Vector 2: unshield, chain_id=103, address=0xAA*32, zero stealth
    let addr = [0xAAu8; 32];
    let unshield = compute_bound_params_hash_unshield(103, &addr, &stealth);
    // Note: single owner passed as 32-byte slice → SHA256(owner)
    let unshield_hex: String = unshield.iter().map(|b| format!("{:02x}", b)).collect();
    println!("VECTOR_unshield={}", unshield_hex);

    // Vector 3: redeem, chain_id=103, btcScript=5120+0xBB*32, zero stealth
    let mut script = vec![0x51u8, 0x20];
    script.extend_from_slice(&[0xBBu8; 32]);
    let redeem = compute_bound_params_hash_redeem(103, &script, &stealth);
    let redeem_hex: String = redeem.iter().map(|b| format!("{:02x}", b)).collect();
    println!("VECTOR_redeem={}", redeem_hex);

    // Vector 4: transfer with non-zero stealth
    let stealth_nz = [0xCCu8; 32];
    let transfer_nz = compute_bound_params_hash_private_transfer(103, &stealth_nz);
    let transfer_nz_hex: String = transfer_nz.iter().map(|b| format!("{:02x}", b)).collect();
    println!("VECTOR_transfer_nz={}", transfer_nz_hex);

    // Ensure they're all different
    assert_ne!(transfer, unshield);
    assert_ne!(transfer, redeem);
    assert_ne!(unshield, redeem);
    assert_ne!(transfer, transfer_nz);
}

/// Test real Poseidon3 against circomlibjs expected output
/// circomlibjs: poseidon([1n, 2n, 3n]) = 0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732
#[test]
fn test_poseidon3_vs_circomlibjs() {
    let mut a = [0u8; 32];
    a[31] = 1;
    let mut b = [0u8; 32];
    b[31] = 2;
    let mut c = [0u8; 32];
    c[31] = 3;
    let hash = poseidon3_hash(&a, &b, &c).unwrap();
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Poseidon3(1,2,3) = {}", hex);
    assert_eq!(
        hex,
        "0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732"
    );
}

/// Test real Poseidon2 against circomlibjs expected output
/// circomlibjs: poseidon([1n, 2n]) = 115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
#[test]
fn test_poseidon2_vs_circomlibjs() {
    let mut a = [0u8; 32];
    a[31] = 1;
    let mut b = [0u8; 32];
    b[31] = 2;
    let hash = poseidon2_hash(&a, &b).unwrap();
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    println!("Poseidon2(1,2) = {}", hex);
    assert_eq!(
        hex,
        "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a"
    );
}

#[test]
fn test_bound_params_hash_modes_are_distinct() {
    let stealth = [0u8; 32];
    let addr = [0u8; 32]; // single 32-byte owner
    let transfer = compute_bound_params_hash_private_transfer(103, &stealth);
    let unshield = compute_bound_params_hash_unshield(103, &addr, &stealth);
    let redeem = compute_bound_params_hash_redeem(103, &[], &stealth);
    // At minimum, transfer and unshield should differ (different flag byte)
    assert_ne!(
        transfer, unshield,
        "Transfer and unshield hashes must differ"
    );
    // Note: redeem with empty script may fail in production (btc_script_len=0 check),
    // but the hash function itself should still work and produce a different result
    assert_ne!(transfer, redeem, "Transfer and redeem hashes must differ");
}
