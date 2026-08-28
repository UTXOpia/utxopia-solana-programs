// The multiplication syscall never reduces its scalar, so the pairing accepts `n` and `n + r`
// alike while `create_nullifier_records` would seed a *different* nullifier PDA from each.
// `parse_joinsplit_prefix` has rejected non-canonical nullifiers and commitments since ced6e47,
// so this guard is the verifier's own copy of that invariant rather than the only line of
// defence — it holds for callers that forget. These tests pin the modulus by the property that
// makes the aliasing work, then drive the real entry point.
use super::*;
use crate::error::UTXOpiaError;
use crate::utils::crypto::BN254_FR_MODULUS;

/// G1 generator (1, 2), 64 bytes big-endian.
const G1_GENERATOR: [u8; 64] = {
    let mut p = [0u8; 64];
    p[31] = 1;
    p[63] = 2;
    p
};

/// Stand-in for a Poseidon nullifier: an arbitrary value comfortably below r.
const NULLIFIER: [u8; 32] = [
    0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8, 0xf9,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0x00,
];

/// x + y as 32 big-endian bytes.
fn add_be(x: &[u8; 32], y: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = x[i] as u16 + y[i] as u16 + carry;
        out[i] = s as u8;
        carry = s >> 8;
    }
    assert_eq!(carry, 0, "sum exceeded 2^256");
    out
}

fn mul(point: &[u8; 64], scalar: &[u8; 32]) -> Vec<u8> {
    let mut input = [0u8; 96];
    input[..64].copy_from_slice(point);
    input[64..].copy_from_slice(scalar);
    alt_bn128_multiplication(&input).expect("scalar multiplication")
}

/// Pins `BN254_FR_MODULUS` by the defining property rather than by restating the bytes:
/// r is the group order, so r * G is the identity. `crypto_tests.rs` covers the ordering
/// boundaries against a literal; this is the one check that would catch the literal itself
/// being wrong.
#[test]
fn scalar_modulus_is_the_group_order() {
    assert_eq!(mul(&G1_GENERATOR, &BN254_FR_MODULUS), vec![0u8; 64]);
}

/// The attack premise: the syscall does not reduce, so n and n + r are the same scalar as far
/// as the pairing is concerned but different bytes as far as a PDA seed is concerned.
#[test]
fn unreduced_scalar_multiplies_to_the_same_point() {
    let replay = add_be(&NULLIFIER, &BN254_FR_MODULUS);
    assert_ne!(NULLIFIER.as_slice(), replay.as_slice());
    assert_eq!(mul(&G1_GENERATOR, &NULLIFIER), mul(&G1_GENERATOR, &replay));
}

/// The guard itself, through the real entry point. The VK material is dummy, so anything that
/// gets past the guard fails with a *different* error — which is what makes this a test of the
/// wiring and not just of `is_in_scalar_field`.
#[test]
fn verify_rejects_the_nullifier_plus_r_replay() {
    // Non-zero A: the identity check runs before the input loop, so an all-zero proof would
    // be rejected there and never reach the guard under test.
    let proof = [7u8; GROTH16_PROOF_SIZE];
    let delta_g2 = [0u8; 128];
    let ic = [[0u8; 64]; 2]; // one public input
    let replay = add_be(&NULLIFIER, &BN254_FR_MODULUS);

    let err = verify_groth16_joinsplit_proof(&proof, &[&replay], &delta_g2, &ic).unwrap_err();
    assert_eq!(err, UTXOpiaError::PublicInputNotInField.into());

    let err = verify_groth16_joinsplit_proof(&proof, &[&NULLIFIER], &delta_g2, &ic).unwrap_err();
    assert_ne!(err, UTXOpiaError::PublicInputNotInField.into());
}

/// A = O makes `e(-A, B)` the identity, which unbinds the proof from B entirely. It was already
/// rejected, but only because negating zero produces bytes the syscall refuses to parse; this
/// pins the rejection to the program's own check.
#[test]
fn verify_rejects_an_identity_proof_a() {
    let mut proof = [0u8; GROTH16_PROOF_SIZE];
    // Leave A zero; give B and C non-zero bytes so A is the only identity point.
    proof[64..].fill(7);
    let delta_g2 = [0u8; 128];
    let ic = [[0u8; 64]; 2];

    let err = verify_groth16_joinsplit_proof(&proof, &[&NULLIFIER], &delta_g2, &ic).unwrap_err();
    assert_eq!(err, UTXOpiaError::InvalidProofPoint.into());
}

/// Negation is an involution on real points, and it is never handed the identity.
#[test]
fn negation_round_trips() {
    let mut point = [0u8; 64];
    point[31] = 1;
    point[63] = 2; // G1 generator
    assert_eq!(negate_g1(&negate_g1(&point)), point);
    assert_ne!(negate_g1(&point), point);
    // -G is a real curve point: the syscall accepts it as a multiplication operand.
    assert_eq!(mul(&negate_g1(&point), &{
        let mut one = [0u8; 32];
        one[31] = 1;
        one
    }), negate_g1(&point).to_vec());
}
