//! Cryptographic utilities for UTXOpia
//!
//! Provides Poseidon hashing for Merkle tree operations.
//! Uses Solana's native Poseidon syscall for efficiency.

use crate::pinocchio_compat::ProgramError;

/// BN254 scalar field modulus (Fr) — big-endian
/// = 21888242871839275222246405745257275088548364400416034343698204186575808495617
pub(crate) const BN254_FR_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
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

/// True if a big-endian 32-byte value is a canonical BN254 Fr element (< modulus).
///
/// The `alt_bn128` multiplication syscall does NOT reduce its scalar — it multiplies by the
/// raw 256-bit value — but G1 has order r, so `n` and `n + r` yield the same point and verify
/// the same Groth16 proof. Nullifiers are also used as PDA dedup seeds from their raw bytes,
/// so a non-canonical re-encoding would seed a fresh nullifier PDA while re-using a spent
/// note's proof → double-spend. This check is what prevents that; do not delete it on the
/// assumption the syscall reduces. `verify_groth16_proof` repeats it as defence in depth.
#[inline]
pub fn is_canonical_fr(val: &[u8; 32]) -> bool {
    !is_ge_modulus(val)
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

/// Reduce a big-endian value modulo BN254 Fr.
///
/// Uses exact modular reduction (`val mod Fr`), identical to the off-chain reference and to the
/// Groth16 verifier's modular interpretation of scalars. The previous implementation cleared the
/// top byte with a bitwise mask (`result[0] &= 0x2F`), which is NOT congruent mod Fr for
/// non-canonical inputs — so the on-chain Poseidon path could produce a different field element
/// than the circuit/SDK, yielding commitments the wallet can never reproduce.
#[cfg(target_os = "solana")]
#[inline]
fn reduce_to_field(val: &[u8; 32]) -> [u8; 32] {
    reduce_to_field_exact(val)
}

/// Poseidon hash using Solana syscall
/// Inputs are automatically reduced to valid BN254 field elements
#[cfg(target_os = "solana")]
fn poseidon2_hash_syscall(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    use solana_poseidon::{hashv, Endianness, Parameters};

    // Reduce inputs to valid field elements if needed
    let left_reduced = reduce_to_field(left);
    let right_reduced = reduce_to_field(right);

    // Call Poseidon syscall - no fallback, this MUST work
    hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &[&left_reduced, &right_reduced],
    )
    .map(|hash| hash.to_bytes())
    .map_err(|_| ProgramError::InvalidArgument)
}

/// Off-chain implementation using light-poseidon (matches on-chain Poseidon syscall exactly)
#[cfg(not(target_os = "solana"))]
fn poseidon2_hash_reference(left: &[u8; 32], right: &[u8; 32]) -> Result<[u8; 32], ProgramError> {
    use ark_bn254::Fr;
    use light_poseidon::{Poseidon, PoseidonBytesHasher};

    // Reduce inputs to valid field elements (matches on-chain reduce_to_field)
    let left_r = reduce_to_field_exact(left);
    let right_r = reduce_to_field_exact(right);
    let mut poseidon = Poseidon::<Fr>::new_circom(2).map_err(|_| ProgramError::InvalidArgument)?;
    let hash = poseidon
        .hash_bytes_be(&[&left_r, &right_r])
        .map_err(|_| ProgramError::InvalidArgument)?;
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
fn poseidon3_hash_syscall(
    a: &[u8; 32],
    b: &[u8; 32],
    c: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    use solana_poseidon::{hashv, Endianness, Parameters};

    let a_reduced = reduce_to_field(a);
    let b_reduced = reduce_to_field(b);
    let c_reduced = reduce_to_field(c);

    hashv(
        Parameters::Bn254X5,
        Endianness::BigEndian,
        &[&a_reduced, &b_reduced, &c_reduced],
    )
    .map(|hash| hash.to_bytes())
    .map_err(|_| ProgramError::InvalidArgument)
}

/// Off-chain implementation using light-poseidon (matches on-chain Poseidon syscall exactly)
#[cfg(not(target_os = "solana"))]
fn poseidon3_hash_reference(
    a: &[u8; 32],
    b: &[u8; 32],
    c: &[u8; 32],
) -> Result<[u8; 32], ProgramError> {
    use ark_bn254::Fr;
    use light_poseidon::{Poseidon, PoseidonBytesHasher};

    // Reduce inputs to valid field elements (matches on-chain reduce_to_field)
    let a_r = reduce_to_field_exact(a);
    let b_r = reduce_to_field_exact(b);
    let c_r = reduce_to_field_exact(c);
    let mut poseidon = Poseidon::<Fr>::new_circom(3).map_err(|_| ProgramError::InvalidArgument)?;
    let hash = poseidon
        .hash_bytes_be(&[&a_r, &b_r, &c_r])
        .map_err(|_| ProgramError::InvalidArgument)?;
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

const DOMAIN_SEPARATOR_TAG: &[u8; 17] = b"UTXOPIA_DOMAIN_V1";

/// Derive the canonical field element identifying a public or institution pool.
///
/// Layout:
///   "UTXOPIA_DOMAIN_V1" || chain_id_le || program_id || pool_state || kind
/// where kind is 0 for public and 1 for institution.
pub fn compute_domain_separator(
    chain_id: u64,
    program_id: &crate::pinocchio_compat::Pubkey,
    pool_state: &crate::pinocchio_compat::Pubkey,
    permissioned: bool,
) -> [u8; 32] {
    use super::sha256;

    let mut preimage = [0u8; 17 + 8 + 32 + 32 + 1];
    let mut offset = 0;
    preimage[offset..offset + DOMAIN_SEPARATOR_TAG.len()].copy_from_slice(DOMAIN_SEPARATOR_TAG);
    offset += DOMAIN_SEPARATOR_TAG.len();
    preimage[offset..offset + 8].copy_from_slice(&chain_id.to_le_bytes());
    offset += 8;
    preimage[offset..offset + 32].copy_from_slice(program_id.as_ref());
    offset += 32;
    preimage[offset..offset + 32].copy_from_slice(pool_state.as_ref());
    offset += 32;
    preimage[offset] = u8::from(permissioned);

    reduce_to_field_exact(&sha256(&preimage))
}

/// Bind an operation-specific bound-params hash to the exact privacy domain.
///
/// The result occupies the existing Groth16 `boundParamsHash` public input, so
/// no circuit public-input or VK account layout changes are required.
pub fn bind_bound_params_to_domain(
    operation_hash: &[u8; 32],
    chain_id: u64,
    program_id: &crate::pinocchio_compat::Pubkey,
    pool_state: &crate::pinocchio_compat::Pubkey,
    permissioned: bool,
) -> Result<[u8; 32], ProgramError> {
    let domain = compute_domain_separator(chain_id, program_id, pool_state, permissioned);
    poseidon2_hash(&domain, operation_hash)
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

/// Length-prefixed hash of a list of byte-strings (audit #4 parity with the Sui program):
///   sha256( u32_le(count) || for each item [ u32_le(len) || bytes ] )
///
/// Binding the count and per-item length means two different partitions of the same
/// concatenated bytes can never collide — a redeem proof cannot be replayed with the
/// scripts re-sliced into attacker-chosen boundaries. Bounded to the redeem script limits
/// (`MAX_PUBLIC_OUTPUTS` scripts of `MAX_BTC_SCRIPT_LEN` bytes); callers validate both before
/// calling, so the stack buffer never overflows.
fn length_prefixed_hash(items: &[&[u8]]) -> [u8; 32] {
    use super::sha256;
    const CAP: usize = 4 + crate::instructions::joinsplit_common::MAX_PUBLIC_OUTPUTS
        * (4 + crate::constants::MAX_BTC_SCRIPT_LEN);
    let mut buf = [0u8; CAP];
    let mut off = 0usize;
    buf[off..off + 4].copy_from_slice(&(items.len() as u32).to_le_bytes());
    off += 4;
    for it in items {
        buf[off..off + 4].copy_from_slice(&(it.len() as u32).to_le_bytes());
        off += 4;
        buf[off..off + it.len()].copy_from_slice(it);
        off += it.len();
    }
    sha256(&buf[..off])
}

/// Compute bound params hash for redeem (JoinSplit → BTC withdrawal).
/// Must match SDK's `computeBoundParamsHash(createRedeemBoundParams(...))`.
///
/// Layout (109 bytes LE):
///   treeNumber(4) + flag(1) + scriptsHash(32) + chainId(8) + stealthDataHash(32) + requester(32)
///   → SHA256 → mod BN254_SCALAR_FIELD
///
/// For redeem: treeNumber=0, flag=2, scriptsHash=length_prefixed_hash(btc_scripts).
pub fn compute_bound_params_hash_redeem(
    chain_id: u64,
    btc_scripts: &[&[u8]],
    stealth_data_hash: &[u8; 32],
    requester: &[u8; 32],
) -> [u8; 32] {
    use super::sha256;

    // Binds the redemption to the requesting signer in addition to the BTC scripts and stealth
    // data. Without the requester in the preimage, a privileged orderflow attacker could replay
    // the same proof under their own signer, take ownership of the RedemptionRequest PDA, and
    // later cancel it to recover the shielded value.
    let mut buf = [0u8; 109];
    buf[4] = 2; // flag = 2 (redeem)
    let script_hash: [u8; 32] = length_prefixed_hash(btc_scripts);
    buf[5..37].copy_from_slice(&script_hash);
    buf[37..45].copy_from_slice(&chain_id.to_le_bytes());
    buf[45..77].copy_from_slice(stealth_data_hash);
    buf[77..109].copy_from_slice(requester);

    let hash: [u8; 32] = sha256(&buf);
    reduce_to_field_exact(&hash)
}

/// Compute commitment with explicit token_id: Poseidon(npk, token_id, amount)
///
/// Used by multi-token shield/unshield. The token_id is Poseidon(reduce_to_field(mint), 0).
pub fn compute_commitment(
    npk: &[u8; 32],
    token_id: &[u8; 32],
    amount_sats: u64,
) -> Result<[u8; 32], ProgramError> {
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

// A placeholder all-zero `ZERO_HASHES` lived here and was never wired up. The real, Poseidon-
// derived ladder is `state::commitment_tree::ZERO_HASHES`. Two same-named constants where the
// unused one is all zeros is a live trap: one `use crate::utils::crypto::ZERO_HASHES` and every
// empty subtree hashes to zero, making forged membership proofs trivial. Deleted rather than
// fixed — there is no second caller that needs its own copy.

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod tests;
