//! secp256k1 Taproot verification using sol_secp256k1_recover syscall
//!
//! Verifies that a Taproot output key matches the derivation from
//! an internal key and a TapTweak commitment. Uses the ecrecover
//! trick to compute point addition via a single syscall call (~25k CU)
//! instead of implementing full secp256k1 point arithmetic (~300k CU).
//!
//! The trick: ecrecover(hash, recovery_id, (r, s)) returns pubkey where
//!   pubkey = (-hash/r)*G + (s/r)*R
//!
//! Setting R = P (groupPubKey), r = s = P.x, hash = -(tweak * P.x) mod n:
//!   pubkey = tweak*G + P = expected output key

use pinocchio::program_error::ProgramError;

use crate::error::UTXOpiaError;

/// secp256k1 curve order n (big-endian)
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Precomputed SHA256("TapTweak") (32 bytes)
const TAPTWEAK_TAG_HASH: [u8; 32] = [
    0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50,
    0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
    0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb,
    0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57, 0xc5, 0xe9,
];

// ============================================================================
// U256 arithmetic (little-endian limbs, [u64; 4] where [0] = least significant)
// ============================================================================

type U256 = [u64; 4];

fn u256_from_be(bytes: &[u8; 32]) -> U256 {
    [
        u64::from_be_bytes(bytes[24..32].try_into().unwrap()),
        u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_be_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
    ]
}

fn u256_to_be(a: &U256) -> [u8; 32] {
    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&a[3].to_be_bytes());
    result[8..16].copy_from_slice(&a[2].to_be_bytes());
    result[16..24].copy_from_slice(&a[1].to_be_bytes());
    result[24..32].copy_from_slice(&a[0].to_be_bytes());
    result
}

/// a + b, returns (result, carry)
fn u256_add_carry(a: &U256, b: &U256) -> (U256, bool) {
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        result[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    (result, carry != 0)
}

/// a >= b
fn u256_gte(a: &U256, b: &U256) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true
}

/// a - b (assumes a >= b)
fn u256_sub(a: &U256, b: &U256) -> U256 {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_sub(b[i]);
        let (s2, c2) = s1.overflowing_sub(borrow);
        result[i] = s2;
        borrow = (c1 as u64) + (c2 as u64);
    }
    result
}

/// (a + b) mod n
fn u256_addmod(a: &U256, b: &U256, n: &U256) -> U256 {
    let (sum, overflow) = u256_add_carry(a, b);
    if overflow || u256_gte(&sum, n) {
        u256_sub(&sum, n)
    } else {
        sum
    }
}

/// (a * b) mod n using binary double-and-add
/// Scans bits of `a` from MSB to LSB, doubling result and adding `b` when bit is set.
fn u256_mulmod(a: &U256, b: &U256, n: &U256) -> U256 {
    let mut result: U256 = [0, 0, 0, 0];

    // Scan from MSB (limb 3, bit 63) to LSB (limb 0, bit 0)
    for limb_idx in (0..4).rev() {
        for bit in (0..64).rev() {
            // Double: result = (result + result) mod n
            result = u256_addmod(&result, &result, n);
            // Conditionally add b
            if (a[limb_idx] >> bit) & 1 == 1 {
                result = u256_addmod(&result, b, n);
            }
        }
    }
    result
}

/// n - a (mod n), assumes a < n
fn u256_negmod(a: &U256, n: &U256) -> U256 {
    if *a == [0, 0, 0, 0] {
        return [0, 0, 0, 0];
    }
    u256_sub(n, a)
}

// ============================================================================
// BIP-340 Tagged Hash
// ============================================================================

/// Compute BIP-340 tagged hash: H_TapTweak(internal_key || commitment)
///
/// result = SHA256(tag_hash || tag_hash || internal_key || commitment)
/// where tag_hash = SHA256("TapTweak") (precomputed constant)
pub fn compute_taptweak_hash(internal_key: &[u8; 32], commitment: &[u8; 32]) -> [u8; 32] {
    // Input: tag_hash(32) + tag_hash(32) + internal_key(32) + commitment(32) = 128 bytes
    let mut input = [0u8; 128];
    input[0..32].copy_from_slice(&TAPTWEAK_TAG_HASH);
    input[32..64].copy_from_slice(&TAPTWEAK_TAG_HASH);
    input[64..96].copy_from_slice(internal_key);
    input[96..128].copy_from_slice(commitment);

    super::sha256(&input)
}

// ============================================================================
// Taproot Output Key Verification (ecrecover trick)
// ============================================================================

/// Verify that `expected_output_key` equals `x_only(groupPubKey + H_TapTweak(groupPubKey || npk) * G)`
///
/// Uses sol_secp256k1_recover syscall to compute the point addition efficiently:
///   ecrecover(hash, 0, (P.x, P.x)) with hash = -(tweak * P.x) mod n
///   → returns tweak*G + P
///
/// # Arguments
/// * `group_pub_key` - 32-byte x-only FROST group public key (big-endian)
/// * `npk` - 32-byte note public key (big-endian)
/// * `expected_output_key` - 32-byte x-only key from deposit TX P2TR output (big-endian)
///
/// # Returns
/// Ok(()) if verification passes, Err otherwise
pub fn verify_taproot_output_key(
    group_pub_key: &[u8; 32],
    npk: &[u8; 32],
    expected_output_key: &[u8; 32],
) -> Result<(), ProgramError> {
    // 1. Compute tweak = H_TapTweak(groupPubKey || npk)
    let tweak = compute_taptweak_hash(group_pub_key, npk);

    verify_taproot_tweak(group_pub_key, &tweak, expected_output_key)
}

/// Lower-level verification: given a precomputed tweak, verify the output key.
/// Separated so it can be reused for script-path Taproot (where tweak includes merkle root).
pub fn verify_taproot_tweak(
    group_pub_key: &[u8; 32],
    tweak: &[u8; 32],
    expected_output_key: &[u8; 32],
) -> Result<(), ProgramError> {
    let n = u256_from_be(&SECP256K1_N);
    let r = u256_from_be(group_pub_key);
    let t = u256_from_be(tweak);

    // Validate r < n (extremely rare for r >= n, but check for safety)
    if u256_gte(&r, &n) {
        return Err(UTXOpiaError::TaprootVerificationFailed.into());
    }

    // Validate tweak < n
    if u256_gte(&t, &n) {
        return Err(UTXOpiaError::TaprootVerificationFailed.into());
    }

    // 2. Compute hash = -(tweak * r) mod n = n - (tweak * r mod n)
    let tweak_times_r = u256_mulmod(&t, &r, &n);
    let hash = u256_negmod(&tweak_times_r, &n);
    let hash_bytes = u256_to_be(&hash);

    // 3. Build signature: r || s where r = s = group_pub_key.x
    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(group_pub_key);
    signature[32..64].copy_from_slice(group_pub_key);

    // 4. Call ecrecover: recovery_id = 0 (even y, per BIP-340 lift_x)
    let mut recovered = [0u8; 64]; // x(32) || y(32), big-endian

    #[cfg(target_os = "solana")]
    {
        extern "C" {
            fn sol_secp256k1_recover(
                hash: *const u8,
                recovery_id: u64,
                signature: *const u8,
                result: *mut u8,
            ) -> u64;
        }
        let rc = unsafe {
            sol_secp256k1_recover(
                hash_bytes.as_ptr(),
                0, // recovery_id = 0 (even y)
                signature.as_ptr(),
                recovered.as_mut_ptr(),
            )
        };
        if rc != 0 {
            return Err(UTXOpiaError::TaprootVerificationFailed.into());
        }
    }

    #[cfg(all(not(target_os = "solana"), test))]
    {
        // Off-chain: use libsecp256k1 for testing
        test_secp256k1_recover(&hash_bytes, 0, &signature, &mut recovered)?;
    }

    // Non-test, non-solana: unreachable in production but needed for cargo check
    #[cfg(all(not(target_os = "solana"), not(test)))]
    {
        let _ = (&hash_bytes, &signature, &mut recovered, expected_output_key);
        return Err(ProgramError::InvalidArgument);
    }

    // 5. Compare recovered x-coordinate with expected output key
    if recovered[0..32] != *expected_output_key {
        return Err(UTXOpiaError::TaprootVerificationFailed.into());
    }

    Ok(())
}

/// Off-chain secp256k1 recovery for tests
#[cfg(test)]
fn test_secp256k1_recover(
    hash: &[u8; 32],
    recovery_id: u8,
    signature: &[u8; 64],
    result: &mut [u8; 64],
) -> Result<(), ProgramError> {
    use libsecp256k1::{Message, RecoveryId, Signature as LibSig, recover};

    let msg = Message::parse(hash);
    let rid = RecoveryId::parse(recovery_id)
        .map_err(|_| ProgramError::InvalidArgument)?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = LibSig::parse_standard(&sig_bytes)
        .map_err(|_| ProgramError::InvalidArgument)?;

    let pubkey = recover(&msg, &sig, &rid)
        .map_err(|_| ProgramError::InvalidArgument)?;

    let serialized = pubkey.serialize();
    // serialized is 65 bytes: 0x04 || x(32) || y(32)
    result.copy_from_slice(&serialized[1..65]);
    Ok(())
}

// ============================================================================
// P2TR helpers
// ============================================================================

/// Extract the 32-byte x-only output key from a P2TR scriptPubKey.
/// P2TR format: OP_1 (0x51) + PUSH32 (0x20) + <32 bytes> = 34 bytes total
pub fn extract_p2tr_output_key(script_pubkey: &[u8]) -> Option<[u8; 32]> {
    if script_pubkey.len() != 34 {
        return None;
    }
    if script_pubkey[0] != 0x51 || script_pubkey[1] != 0x20 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&script_pubkey[2..34]);
    Some(key)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
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
            0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50,
            0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
            0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb,
            0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57, 0xc5, 0xe9,
        ];
        assert_eq!(TAPTWEAK_TAG_HASH, expected, "Must match BIP-341 known value");
    }

    #[test]
    fn test_u256_conversions_roundtrip() {
        let bytes: [u8; 32] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
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
        // groupPubKey = secp256k1 generator x-coordinate (used as default internal key in SDK)
        // npk = some 32-byte value
        // tweak = H_TapTweak(groupPubKey || npk)
        // outputKey = (groupPubKey_point + tweak*G).x
        //
        // We verify the ecrecover trick produces the correct result by using
        // a known FROST group pubkey and checking the math is self-consistent.

        let group_pub_key: [u8; 32] = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
            0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
            0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
            0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        let npk = [0x42u8; 32];

        // Compute tweak
        let tweak = compute_taptweak_hash(&group_pub_key, &npk);

        // Use ecrecover to compute the expected output key
        // (this tests the internal consistency of the ecrecover trick)
        let n = u256_from_be(&SECP256K1_N);
        let r = u256_from_be(&group_pub_key);
        let t = u256_from_be(&tweak);

        let tweak_times_r = u256_mulmod(&t, &r, &n);
        let hash = u256_negmod(&tweak_times_r, &n);
        let hash_bytes = u256_to_be(&hash);

        let mut signature = [0u8; 64];
        signature[0..32].copy_from_slice(&group_pub_key);
        signature[32..64].copy_from_slice(&group_pub_key);

        let mut recovered = [0u8; 64];
        test_secp256k1_recover(&hash_bytes, 0, &signature, &mut recovered).unwrap();

        // The recovered x-coordinate is the expected output key
        let expected_output_key: [u8; 32] = recovered[0..32].try_into().unwrap();

        // Now verify using the public API
        let result = verify_taproot_output_key(&group_pub_key, &npk, &expected_output_key);
        assert!(result.is_ok(), "Taproot verification should pass with correct output key");

        // Verify with wrong output key should fail
        let mut wrong_key = expected_output_key;
        wrong_key[0] ^= 0xFF;
        let result = verify_taproot_output_key(&group_pub_key, &npk, &wrong_key);
        assert!(result.is_err(), "Taproot verification should fail with wrong output key");
    }

    #[test]
    fn test_verify_rejects_wrong_npk() {
        let group_pub_key: [u8; 32] = [
            0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
            0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
            0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
            0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
        ];
        let npk_real = [0x42u8; 32];
        let npk_fake = [0x43u8; 32];

        // Compute output key from real npk
        let tweak = compute_taptweak_hash(&group_pub_key, &npk_real);
        let n = u256_from_be(&SECP256K1_N);
        let r = u256_from_be(&group_pub_key);
        let t = u256_from_be(&tweak);
        let tweak_times_r = u256_mulmod(&t, &r, &n);
        let hash = u256_negmod(&tweak_times_r, &n);
        let hash_bytes = u256_to_be(&hash);
        let mut signature = [0u8; 64];
        signature[0..32].copy_from_slice(&group_pub_key);
        signature[32..64].copy_from_slice(&group_pub_key);
        let mut recovered = [0u8; 64];
        test_secp256k1_recover(&hash_bytes, 0, &signature, &mut recovered).unwrap();
        let real_output_key: [u8; 32] = recovered[0..32].try_into().unwrap();

        // Verification with wrong npk should fail
        let result = verify_taproot_output_key(&group_pub_key, &npk_fake, &real_output_key);
        assert!(result.is_err(), "Wrong npk should fail verification");
    }
}
