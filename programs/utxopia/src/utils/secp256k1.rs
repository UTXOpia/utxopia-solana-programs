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
//! Setting R = P (internal key), r = s = P.x, hash = -(tweak * P.x) mod n:
//!   pubkey = tweak*G + P = expected output key

use pinocchio::program_error::ProgramError;

use crate::error::UTXOpiaError;

/// secp256k1 curve order n (big-endian)
const SECP256K1_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// Precomputed SHA256("TapTweak") (32 bytes)
const TAPTWEAK_TAG_HASH: [u8; 32] = [
    0xe8, 0x0f, 0xe1, 0x63, 0x9c, 0x9c, 0xa0, 0x50, 0xe3, 0xaf, 0x1b, 0x39, 0xc1, 0x43, 0xc6, 0x3e,
    0x42, 0x9c, 0xbc, 0xeb, 0x15, 0xd9, 0x40, 0xfb, 0xb5, 0xc5, 0xa1, 0xf4, 0xaf, 0x57, 0xc5, 0xe9,
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
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
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

/// Verify that `expected_output_key` equals `x_only(internal_key + H_TapTweak(internal_key || npk) * G)`
///
/// Uses sol_secp256k1_recover syscall to compute the point addition efficiently:
///   ecrecover(hash, 0, (P.x, P.x)) with hash = -(tweak * P.x) mod n
///   → returns tweak*G + P
///
/// # Arguments
/// * `internal_key` - 32-byte x-only Taproot internal key (big-endian)
/// * `npk` - 32-byte note public key (big-endian)
/// * `expected_output_key` - 32-byte x-only key from deposit TX P2TR output (big-endian)
///
/// # Returns
/// Ok(()) if verification passes, Err otherwise
pub fn verify_taproot_output_key(
    internal_key: &[u8; 32],
    npk: &[u8; 32],
    expected_output_key: &[u8; 32],
) -> Result<(), ProgramError> {
    // 1. Compute tweak = H_TapTweak(internal_key || npk)
    let tweak = compute_taptweak_hash(internal_key, npk);

    verify_taproot_tweak(internal_key, &tweak, expected_output_key)
}

/// Lower-level verification: given a precomputed tweak, verify the output key.
/// Separated so it can be reused for script-path Taproot (where tweak includes merkle root).
pub fn verify_taproot_tweak(
    internal_key: &[u8; 32],
    tweak: &[u8; 32],
    expected_output_key: &[u8; 32],
) -> Result<(), ProgramError> {
    let n = u256_from_be(&SECP256K1_N);
    let r = u256_from_be(internal_key);
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

    // 3. Build signature: r || s where r = s = internal_key.x
    let mut signature = [0u8; 64];
    signature[0..32].copy_from_slice(internal_key);
    signature[32..64].copy_from_slice(internal_key);

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

    #[cfg(any(target_os = "solana", test))]
    {
        // 5. Compare recovered x-coordinate with expected output key
        if recovered[0..32] != *expected_output_key {
            return Err(UTXOpiaError::TaprootVerificationFailed.into());
        }

        Ok(())
    }

    #[cfg(all(not(target_os = "solana"), not(test)))]
    {
        let _ = (&hash_bytes, &signature, &mut recovered, expected_output_key);
        Err(ProgramError::InvalidArgument)
    }
}

/// Off-chain secp256k1 recovery for tests
#[cfg(test)]
fn test_secp256k1_recover(
    hash: &[u8; 32],
    recovery_id: u8,
    signature: &[u8; 64],
    result: &mut [u8; 64],
) -> Result<(), ProgramError> {
    use libsecp256k1::{recover, Message, RecoveryId, Signature as LibSig};

    let msg = Message::parse(hash);
    let rid = RecoveryId::parse(recovery_id).map_err(|_| ProgramError::InvalidArgument)?;

    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = LibSig::parse_standard(&sig_bytes).map_err(|_| ProgramError::InvalidArgument)?;

    let pubkey = recover(&msg, &sig, &rid).map_err(|_| ProgramError::InvalidArgument)?;

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
#[path = "secp256k1_tests.rs"]
mod secp256k1_tests;
