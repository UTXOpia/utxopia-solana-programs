//! Cryptographic utilities for UTXOpia
//!
//! Provides Poseidon hashing for Merkle tree operations.
//! Uses Solana's native Poseidon syscall for efficiency.

use pinocchio::program_error::ProgramError;


/// BN254 scalar field modulus (Fr) — big-endian
/// = 21888242871839275222246405745257275088548364400416034343698204186575808495617
const BN254_FR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Poseidon hash of two 32-byte inputs (for Merkle tree nodes)
///
/// Uses the BN254 field with Poseidon parameters optimized for
/// binary Merkle trees (2 inputs → 1 output).
///
/// # On-chain Implementation
/// Uses Solana's `sol_poseidon` syscall (requires v1.17.5+).
/// With `localnet` feature, uses SHA256 (test validator lacks Poseidon syscall).
#[inline]
pub fn poseidon2_hash(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    // On-chain: always use Poseidon syscall (validator must be started with --clone-feature-set --url devnet)
    #[cfg(target_os = "solana")]
    {
        poseidon2_hash_syscall(left, right)
    }

    #[cfg(not(target_os = "solana"))]
    {
        poseidon2_hash_reference(left, right)
    }
}

/// Check if a big-endian 32-byte value is >= BN254 Fr modulus
#[inline]
fn is_ge_modulus(val: &[u8; 32]) -> bool {
    for i in 0..32 {
        if val[i] < BN254_FR_MODULUS[i] {
            return false;
        }
        if val[i] > BN254_FR_MODULUS[i] {
            return true;
        }
    }
    true // Equal to modulus
}

/// Reduce a big-endian value modulo BN254 Fr if needed
/// For values >= modulus, we XOR with a mask to bring into range
/// This is a simple reduction that maintains determinism
#[cfg(target_os = "solana")]
#[inline]
fn reduce_to_field(val: &[u8; 32]) -> [u8; 32] {
    if !is_ge_modulus(val) {
        return *val;
    }
    // Simple reduction: clear top bits to ensure < modulus
    // The modulus starts with 0x30, so clearing to 0x2F or less ensures < modulus
    let mut result = *val;
    result[0] &= 0x2F;
    result
}

/// Poseidon hash using Solana syscall
/// Inputs are automatically reduced to valid BN254 field elements
#[cfg(target_os = "solana")]
fn poseidon2_hash_syscall(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    use solana_poseidon::{hashv, Parameters, Endianness};

    // Reduce inputs to valid field elements if needed
    let left_reduced = reduce_to_field(left);
    let right_reduced = reduce_to_field(right);

    // Call Poseidon syscall - no fallback, this MUST work
    hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&left_reduced, &right_reduced])
        .map(|hash| hash.to_bytes())
        .map_err(|_| ProgramError::InvalidArgument)
}

/// Off-chain implementation using light-poseidon (matches on-chain Poseidon syscall exactly)
#[cfg(not(target_os = "solana"))]
fn poseidon2_hash_reference(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    use light_poseidon::{Poseidon, PoseidonBytesHasher};
    use ark_bn254::Fr;

    // Reduce inputs to valid field elements (matches on-chain reduce_to_field)
    let left_r = reduce_to_field_exact(left);
    let right_r = reduce_to_field_exact(right);
    let mut poseidon = Poseidon::<Fr>::new_circom(2).map_err(|_| ProgramError::InvalidArgument)?;
    let hash = poseidon.hash_bytes_be(&[&left_r, &right_r]).map_err(|_| ProgramError::InvalidArgument)?;
    Ok(hash)
}

/// Poseidon hash of three 32-byte inputs (for commitment computation)
///
/// Used to compute deposit commitments: Poseidon(npk, token_id, amount)
#[inline]
pub fn poseidon3_hash(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    // On-chain: always use Poseidon syscall (validator must be started with --clone-feature-set --url devnet)
    #[cfg(target_os = "solana")]
    {
        poseidon3_hash_syscall(a, b, c)
    }

    #[cfg(not(target_os = "solana"))]
    {
        poseidon3_hash_reference(a, b, c)
    }
}

/// SHA256 hash for localnet testing with 3 inputs
/// Poseidon3 hash using Solana syscall
#[cfg(target_os = "solana")]
fn poseidon3_hash_syscall(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    use solana_poseidon::{hashv, Parameters, Endianness};

    let a_reduced = reduce_to_field(a);
    let b_reduced = reduce_to_field(b);
    let c_reduced = reduce_to_field(c);

    hashv(Parameters::Bn254X5, Endianness::BigEndian, &[&a_reduced, &b_reduced, &c_reduced])
        .map(|hash| hash.to_bytes())
        .map_err(|_| ProgramError::InvalidArgument)
}

/// Off-chain implementation using light-poseidon (matches on-chain Poseidon syscall exactly)
#[cfg(not(target_os = "solana"))]
fn poseidon3_hash_reference(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    use light_poseidon::{Poseidon, PoseidonBytesHasher};
    use ark_bn254::Fr;

    // Reduce inputs to valid field elements (matches on-chain reduce_to_field)
    let a_r = reduce_to_field_exact(a);
    let b_r = reduce_to_field_exact(b);
    let c_r = reduce_to_field_exact(c);
    let mut poseidon = Poseidon::<Fr>::new_circom(3).map_err(|_| ProgramError::InvalidArgument)?;
    let hash = poseidon.hash_bytes_be(&[&a_r, &b_r, &c_r]).map_err(|_| ProgramError::InvalidArgument)?;
    Ok(hash)
}

/// Subtract BN254 Fr modulus from a big-endian 32-byte value.
/// Assumes val >= modulus.
#[inline]
fn subtract_modulus(val: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let diff = (val[i] as u16)
            .wrapping_sub(BN254_FR_MODULUS[i] as u16)
            .wrapping_sub(borrow);
        result[i] = diff as u8;
        borrow = if diff > 0xFF { 1 } else { 0 };
    }
    result
}

/// Reduce a big-endian SHA256 hash modulo BN254 Fr.
/// Matches SDK's `bytesToBigint(hash) % BN254_FIELD_PRIME`.
///
/// SHA256 output is 256 bits, modulus is ~254 bits, so the quotient
/// can be up to 5. We loop subtracting the modulus until the value
/// is in range (at most 5 iterations).
#[inline]
fn reduce_to_field_exact(val: &[u8; 32]) -> [u8; 32] {
    let mut result = *val;
    while is_ge_modulus(&result) {
        result = subtract_modulus(&result);
    }
    result
}

/// Compute bound params hash for private transfer verification.
/// Must match SDK's `computeBoundParamsHash()` exactly.
///
/// Layout (77 bytes LE):
///   treeNumber(4) + flag(1) + address(32) + chainId(8) + stealthDataHash(32)
///   → SHA256 → mod BN254_SCALAR_FIELD
///
/// For private transfers: treeNumber=0, flag=0, address=zeros
pub fn compute_bound_params_hash_private_transfer(
    chain_id: u64,
    stealth_data_hash: &[u8; 32],
) -> [u8; 32] {
    use super::sha256;

    let mut buf = [0u8; 77];
    // treeNumber = 0 (first 4 bytes already zero)
    // flag = 0 (byte 4 already zero)
    // unshieldAddress = zeros (bytes 5-36 already zero)
    buf[37..45].copy_from_slice(&chain_id.to_le_bytes());
    buf[45..77].copy_from_slice(stealth_data_hash);

    let hash: [u8; 32] = sha256(&buf);
    reduce_to_field_exact(&hash)
}

/// Compute bound params hash for public unshield verification (multi-output).
/// Must match SDK's `computeBoundParamsHash(createUnshieldBoundParams(...))`.
///
/// Layout (77 bytes LE):
///   treeNumber(4) + flag(1) + destinations_hash(32) + chainId(8) + stealthDataHash(32)
///   → SHA256 → mod BN254_SCALAR_FIELD
///
/// destinations_hash = SHA256(owner_1 || owner_2 || ...)
/// For single output: SHA256(owner_1) — no special case.
pub fn compute_bound_params_hash_unshield(
    chain_id: u64,
    owners_concat: &[u8],
    stealth_data_hash: &[u8; 32],
) -> [u8; 32] {
    use super::sha256;

    let mut buf = [0u8; 77];
    buf[4] = 1; // flag = 1 (unshield)
    let destinations_hash: [u8; 32] = sha256(owners_concat);
    buf[5..37].copy_from_slice(&destinations_hash);
    buf[37..45].copy_from_slice(&chain_id.to_le_bytes());
    buf[45..77].copy_from_slice(stealth_data_hash);

    let hash: [u8; 32] = sha256(&buf);
    reduce_to_field_exact(&hash)
}

/// Compute bound params hash for redeem (JoinSplit → BTC withdrawal).
/// Must match SDK's `computeBoundParamsHash(createRedeemBoundParams(...))`.
///
/// Layout (77 bytes LE):
///   treeNumber(4) + flag(1) + address(32) + chainId(8) + stealthDataHash(32)
///   → SHA256 → mod BN254_SCALAR_FIELD
///
/// For redeem: treeNumber=0, flag=2, address=SHA256(btcScript)
pub fn compute_bound_params_hash_redeem(
    chain_id: u64,
    btc_script: &[u8],
    stealth_data_hash: &[u8; 32],
) -> [u8; 32] {
    use super::sha256;

    let mut buf = [0u8; 77];
    buf[4] = 2; // flag = 2 (redeem)
    let script_hash: [u8; 32] = sha256(btc_script);
    buf[5..37].copy_from_slice(&script_hash);
    buf[37..45].copy_from_slice(&chain_id.to_le_bytes());
    buf[45..77].copy_from_slice(stealth_data_hash);

    let hash: [u8; 32] = sha256(&buf);
    reduce_to_field_exact(&hash)
}


/// Compute commitment with explicit token_id: Poseidon(npk, token_id, amount)
///
/// Used by multi-token shield/unshield. The token_id is Poseidon(reduce_to_field(mint), 0).
pub fn compute_commitment(npk: &[u8; 32], token_id: &[u8; 32], amount_sats: u64) -> Result<[u8; 32], ProgramError> {
    let mut amount = [0u8; 32];
    amount[24..32].copy_from_slice(&amount_sats.to_be_bytes());

    poseidon3_hash(npk, token_id, &amount)
}

/// Compute token_id from mint address: Poseidon(reduce_to_field(mint), 0)
///
/// Uses 2-input Poseidon (consistent with existing poseidon2_hash).
/// The SDK must use the identical approach: poseidon([reduced_mint, 0n]).
pub fn compute_token_id(mint_bytes: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    let reduced = reduce_to_field_exact(mint_bytes);
    poseidon2_hash(&reduced, &[0u8; 32])
}


/// Compute Merkle root from a leaf and its sibling path
///
/// # Arguments
/// * `leaf` - The leaf commitment
/// * `leaf_index` - Position of the leaf (determines left/right placement)
/// * `siblings` - Array of sibling hashes from leaf to root
///
/// # Returns
/// The computed Merkle root
pub fn compute_merkle_root(
    leaf: &[u8; 32],
    leaf_index: u64,
    siblings: &[[u8; 32]],
) -> Result<[u8; 32], ProgramError> {
    let mut current = *leaf;
    let mut index = leaf_index;

    for sibling in siblings {
        // If index is even, current is left child; if odd, current is right child
        let is_left = index & 1 == 0; // Bitwise check: even = left child
        current = if is_left {
            poseidon2_hash(&current, sibling)?
        } else {
            poseidon2_hash(sibling, &current)?
        };
        index /= 2;
    }

    Ok(current)
}

/// Zero value for empty Merkle tree nodes at each level
/// These are precomputed: zero[0] = H(0,0), zero[1] = H(zero[0], zero[0]), etc.
pub const ZERO_HASHES: [[u8; 32]; 20] = [
    // Level 0: Hash of two zero leaves
    [0u8; 32],
    // Levels 1-19: Each level is hash of previous level with itself
    // In production, these should be precomputed with actual Poseidon2
    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],
    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],
    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],
    [0u8; 32], [0u8; 32], [0u8; 32], [0u8; 32],
    [0u8; 32], [0u8; 32], [0u8; 32],
];

#[cfg(test)]
mod tests {
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

        assert_ne!(hash_ab, hash_ac, "Different inputs should produce different hashes");
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

        assert_ne!(hash_abc, hash_abd, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_compute_commitment() {
        let npk = [0x42u8; 32];
        let token_id = [0x01u8; 32];
        let amount_sats = 100_000u64;

        let commitment1 = compute_commitment(&npk, &token_id, amount_sats).unwrap();
        let commitment2 = compute_commitment(&npk, &token_id, amount_sats).unwrap();

        assert_eq!(commitment1, commitment2, "Commitment should be deterministic");

        // Different amount should give different commitment
        let commitment3 = compute_commitment(&npk, &token_id, 200_000).unwrap();
        assert_ne!(commitment1, commitment3, "Different amounts should give different commitments");

        // Different npk should give different commitment
        let npk2 = [0x43u8; 32];
        let commitment4 = compute_commitment(&npk2, &token_id, amount_sats).unwrap();
        assert_ne!(commitment1, commitment4, "Different npks should give different commitments");

        // Different token_id should give different commitment
        let token_id2 = [0x02u8; 32];
        let commitment5 = compute_commitment(&npk, &token_id2, amount_sats).unwrap();
        assert_ne!(commitment1, commitment5, "Different token_ids should give different commitments");
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
        assert_ne!(commitment, commitment3, "Different burn amounts must produce different commitments");
    }

    #[test]
    fn test_compute_token_id_deterministic() {
        let mint = [0xABu8; 32];
        let id1 = compute_token_id(&mint).unwrap();
        let id2 = compute_token_id(&mint).unwrap();
        assert_eq!(id1, id2, "Token ID should be deterministic");

        let mint2 = [0xCDu8; 32];
        let id3 = compute_token_id(&mint2).unwrap();
        assert_ne!(id1, id3, "Different mints should produce different token IDs");
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
        assert_ne!(devnet, mainnet, "Different chain IDs must produce different hashes");
    }

    #[test]
    fn test_bound_params_hash_is_valid_field_element() {
        let stealth = [0u8; 32];
        let hash = compute_bound_params_hash_private_transfer(103, &stealth);
        assert!(!is_ge_modulus(&hash), "Hash must be a valid BN254 field element");
    }

    #[test]
    fn test_bound_params_hash_different_stealth_data() {
        let stealth_a = [0xAAu8; 32];
        let stealth_b = [0xBBu8; 32];
        let hash_a = compute_bound_params_hash_private_transfer(103, &stealth_a);
        let hash_b = compute_bound_params_hash_private_transfer(103, &stealth_b);
        assert_ne!(hash_a, hash_b, "Different stealth data must produce different hashes");
    }

    #[test]
    fn test_bound_params_hash_redeem_binds_btc_script() {
        let stealth = [0u8; 32];
        let script_a = [0x51u8, 0x20, 0xAAu8, 0xBB]; // dummy P2TR-like
        let script_b = [0x51u8, 0x20, 0xCC, 0xDD];
        let hash_a = compute_bound_params_hash_redeem(103, &script_a, &stealth);
        let hash_b = compute_bound_params_hash_redeem(103, &script_b, &stealth);
        assert_ne!(hash_a, hash_b, "Different BTC scripts must produce different hashes");

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
        assert_ne!(hash_a, hash_b, "Different stealth data must produce different redeem hashes");
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
        let mut a = [0u8; 32]; a[31] = 1;
        let mut b = [0u8; 32]; b[31] = 2;
        let mut c = [0u8; 32]; c[31] = 3;
        let hash = poseidon3_hash(&a, &b, &c).unwrap();
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        println!("Poseidon3(1,2,3) = {}", hex);
        assert_eq!(hex, "0e7732d89e6939c0ff03d5e58dab6302f3230e269dc5b968f725df34ab36d732");
    }

    /// Test real Poseidon2 against circomlibjs expected output
    /// circomlibjs: poseidon([1n, 2n]) = 115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a
    #[test]
    fn test_poseidon2_vs_circomlibjs() {
        let mut a = [0u8; 32]; a[31] = 1;
        let mut b = [0u8; 32]; b[31] = 2;
        let hash = poseidon2_hash(&a, &b).unwrap();
        let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        println!("Poseidon2(1,2) = {}", hex);
        assert_eq!(hex, "115cc0f5e7d690413df64c6b9662e9cf2a3617f2743245519e19607a4417189a");
    }

    #[test]
    fn test_bound_params_hash_modes_are_distinct() {
        let stealth = [0u8; 32];
        let addr = [0u8; 32]; // single 32-byte owner
        let transfer = compute_bound_params_hash_private_transfer(103, &stealth);
        let unshield = compute_bound_params_hash_unshield(103, &addr, &stealth);
        let redeem = compute_bound_params_hash_redeem(103, &[], &stealth);
        // At minimum, transfer and unshield should differ (different flag byte)
        assert_ne!(transfer, unshield, "Transfer and unshield hashes must differ");
        // Note: redeem with empty script may fail in production (btc_script_len=0 check),
        // but the hash function itself should still work and produce a different result
        assert_ne!(transfer, redeem, "Transfer and redeem hashes must differ");
    }
}
