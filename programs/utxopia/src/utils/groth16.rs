//! Groth16 proof verification utilities
//!
//! On-chain Groth16 proof verification using Solana's native BN254 syscalls.
//! Groth16 proofs are ~256 bytes, always fit inline (no buffer variants needed).
//!
//! # Architecture
//! ```text
//! Browser/Mobile (snarkjs)         UTXOpia Program
//! ┌──────────────────────────┐    ┌──────────────────────────┐
//! │ Generate Groth16         │    │                          │
//! │ proof (~256 bytes)       │───>│ verify_groth16_*_proof() │
//! │                          │    │ (solana-bn254 pairing)   │
//! └──────────────────────────┘    └──────────────────────────┘
//! ```

use pinocchio::program_error::ProgramError;
use solana_bn254::prelude::{
    alt_bn128_addition, alt_bn128_multiplication, alt_bn128_pairing, ALT_BN128_PAIRING_ELEMENT_LEN,
};

/// Groth16 proof size (2 G1 points + 1 G2 point = 256 bytes)
pub const GROTH16_PROOF_SIZE: usize = 256;

/// BN254 base field modulus p (big-endian)
/// Used for G1 point negation: -P = (x, p - y)
const BN254_FIELD_MODULUS: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d, 0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
];

/// Negate a G1 point: -P = (x, p - y)
/// Input/output: 64 bytes [x_BE(32), y_BE(32)]
#[inline(always)]
fn negate_g1(point: &[u8; 64]) -> [u8; 64] {
    let mut result = [0u8; 64];
    // x stays the same
    result[..32].copy_from_slice(&point[..32]);

    // y = p - y (big-endian subtraction with wrapping to avoid SBF overflow checks)
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let a = BN254_FIELD_MODULUS[i] as u16;
        let b = (point[32 + i] as u16).wrapping_add(borrow);
        if a >= b {
            result[32 + i] = (a - b) as u8;
            borrow = 0;
        } else {
            result[32 + i] = (a.wrapping_add(256).wrapping_sub(b)) as u8;
            borrow = 1;
        }
    }

    result
}

/// Verify a Groth16 proof with the given verification key components.
///
/// Groth16 verification equation:
///   e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
///
/// Where vk_x = IC[0] + sum(public_input[i] * IC[i+1])
fn verify_groth16_proof(
    proof_bytes: &[u8],
    public_inputs: &[&[u8; 32]],
    alpha_g1: &[u8; 64],
    beta_g2: &[u8; 128],
    gamma_g2: &[u8; 128],
    delta_g2: &[u8; 128],
    ic: &[[u8; 64]],
) -> Result<(), ProgramError> {
    if proof_bytes.len() != GROTH16_PROOF_SIZE {
        pinocchio::msg!("UTXOpia: groth16 bad proof size");
        return Err(ProgramError::InvalidInstructionData);
    }

    let num_inputs = public_inputs.len();
    if ic.len() != num_inputs + 1 {
        pinocchio::msg!("UTXOpia: groth16 IC len mismatch");
        return Err(ProgramError::InvalidInstructionData);
    }

    pinocchio::msg!("UTXOpia: groth16 verifying");

    // Parse proof components
    let pi_a: &[u8] = &proof_bytes[0..64]; // G1 (64 bytes)
    let pi_b: &[u8] = &proof_bytes[64..192]; // G2 (128 bytes)
    let pi_c: &[u8] = &proof_bytes[192..256]; // G1 (64 bytes)

    // Step 1: Negate A
    let mut a_bytes = [0u8; 64];
    a_bytes.copy_from_slice(pi_a);
    let neg_a = negate_g1(&a_bytes);

    // Step 2: Compute vk_x = IC[0] + sum(public_input[i] * IC[i+1])
    // Buffers hoisted outside loop to avoid re-zeroing each iteration
    let mut vk_x = ic[0];
    let mut mul_input = [0u8; 96];
    let mut add_input = [0u8; 128];

    for i in 0..num_inputs {
        // Scalar multiplication: public_input[i] * IC[i+1]
        // Input: [G1_point(64) | scalar_BE(32)] (96 bytes)
        mul_input[..64].copy_from_slice(&ic[i + 1]);
        mul_input[64..96].copy_from_slice(public_inputs[i]);

        let term = alt_bn128_multiplication(&mul_input).map_err(|_| {
            pinocchio::msg!("UTXOpia: groth16 mul failed");
            ProgramError::InvalidInstructionData
        })?;

        // Point addition: vk_x = vk_x + term
        add_input[..64].copy_from_slice(&vk_x);
        add_input[64..128].copy_from_slice(&term);

        let sum = alt_bn128_addition(&add_input).map_err(|_| {
            pinocchio::msg!("UTXOpia: groth16 add failed");
            ProgramError::InvalidInstructionData
        })?;

        vk_x.copy_from_slice(&sum);
    }

    pinocchio::msg!("UTXOpia: groth16 pairing check");

    // Step 3: Build pairing input (4 pairs × 192 bytes = 768 bytes)
    // Pairing check: e(-A, B) * e(alpha, beta) * e(vk_x, gamma) * e(C, delta) == 1
    let mut pairing_input = [0u8; 4 * ALT_BN128_PAIRING_ELEMENT_LEN]; // 768 bytes

    // Pair 1: (-A, B)
    pairing_input[0..64].copy_from_slice(&neg_a);
    pairing_input[64..192].copy_from_slice(pi_b);

    // Pair 2: (alpha, beta)
    pairing_input[192..256].copy_from_slice(alpha_g1);
    pairing_input[256..384].copy_from_slice(beta_g2);

    // Pair 3: (vk_x, gamma)
    pairing_input[384..448].copy_from_slice(&vk_x);
    pairing_input[448..576].copy_from_slice(gamma_g2);

    // Pair 4: (C, delta)
    pairing_input[576..640].copy_from_slice(pi_c);
    pairing_input[640..768].copy_from_slice(delta_g2);

    // Step 4: Verify pairing
    let pairing_result = alt_bn128_pairing(&pairing_input).map_err(|_| {
        pinocchio::msg!("UTXOpia: groth16 pairing syscall failed");
        ProgramError::InvalidInstructionData
    })?;

    // Result is 32 bytes: 31 zero bytes followed by 0x01 for valid proof
    const VALID_PAIRING: [u8; 32] = {
        let mut v = [0u8; 32];
        v[31] = 1;
        v
    };
    if pairing_result.len() != 32 || pairing_result[..] != VALID_PAIRING {
        pinocchio::msg!("UTXOpia: groth16 proof invalid");
        return Err(ProgramError::InvalidInstructionData);
    }

    pinocchio::msg!("UTXOpia: groth16 proof verified");
    Ok(())
}

// =============================================================================
// Shared Verification Key Constants (from same trusted setup ceremony)
// All circuits share identical ALPHA_G1, BETA_G2, and GAMMA_G2.
// Only DELTA_G2 and IC differ per circuit.
// =============================================================================

mod common_vk {
    /// VK alpha (G1 point, 64 bytes) — shared across all circuits
    pub const ALPHA_G1: [u8; 64] = [
        0x2d, 0x4d, 0x9a, 0xa7, 0xe3, 0x02, 0xd9, 0xdf, 0x41, 0x74, 0x9d, 0x55, 0x07, 0x94, 0x9d,
        0x05, 0xdb, 0xea, 0x33, 0xfb, 0xb1, 0x6c, 0x64, 0x3b, 0x22, 0xf5, 0x99, 0xa2, 0xbe, 0x6d,
        0xf2, 0xe2, 0x14, 0xbe, 0xdd, 0x50, 0x3c, 0x37, 0xce, 0xb0, 0x61, 0xd8, 0xec, 0x60, 0x20,
        0x9f, 0xe3, 0x45, 0xce, 0x89, 0x83, 0x0a, 0x19, 0x23, 0x03, 0x01, 0xf0, 0x76, 0xca, 0xff,
        0x00, 0x4d, 0x19, 0x26,
    ];

    /// VK beta (G2 point, 128 bytes) — shared across all circuits
    pub const BETA_G2: [u8; 128] = [
        0x09, 0x67, 0x03, 0x2f, 0xcb, 0xf7, 0x76, 0xd1, 0xaf, 0xc9, 0x85, 0xf8, 0x88, 0x77, 0xf1,
        0x82, 0xd3, 0x84, 0x80, 0xa6, 0x53, 0xf2, 0xde, 0xca, 0xa9, 0x79, 0x4c, 0xbc, 0x3b, 0xf3,
        0x06, 0x0c, 0x0e, 0x18, 0x78, 0x47, 0xad, 0x4c, 0x79, 0x83, 0x74, 0xd0, 0xd6, 0x73, 0x2b,
        0xf5, 0x01, 0x84, 0x7d, 0xd6, 0x8b, 0xc0, 0xe0, 0x71, 0x24, 0x1e, 0x02, 0x13, 0xbc, 0x7f,
        0xc1, 0x3d, 0xb7, 0xab, 0x30, 0x4c, 0xfb, 0xd1, 0xe0, 0x8a, 0x70, 0x4a, 0x99, 0xf5, 0xe8,
        0x47, 0xd9, 0x3f, 0x8c, 0x3c, 0xaa, 0xfd, 0xde, 0xc4, 0x6b, 0x7a, 0x0d, 0x37, 0x9d, 0xa6,
        0x9a, 0x4d, 0x11, 0x23, 0x46, 0xa7, 0x17, 0x39, 0xc1, 0xb1, 0xa4, 0x57, 0xa8, 0xc7, 0x31,
        0x31, 0x23, 0xd2, 0x4d, 0x2f, 0x91, 0x92, 0xf8, 0x96, 0xb7, 0xc6, 0x3e, 0xea, 0x05, 0xa9,
        0xd5, 0x7f, 0x06, 0x54, 0x7a, 0xd0, 0xce, 0xc8,
    ];

    /// VK gamma (G2 point, 128 bytes) — shared across all circuits
    pub const GAMMA_G2: [u8; 128] = [
        0x19, 0x8e, 0x93, 0x93, 0x92, 0x0d, 0x48, 0x3a, 0x72, 0x60, 0xbf, 0xb7, 0x31, 0xfb, 0x5d,
        0x25, 0xf1, 0xaa, 0x49, 0x33, 0x35, 0xa9, 0xe7, 0x12, 0x97, 0xe4, 0x85, 0xb7, 0xae, 0xf3,
        0x12, 0xc2, 0x18, 0x00, 0xde, 0xef, 0x12, 0x1f, 0x1e, 0x76, 0x42, 0x6a, 0x00, 0x66, 0x5e,
        0x5c, 0x44, 0x79, 0x67, 0x43, 0x22, 0xd4, 0xf7, 0x5e, 0xda, 0xdd, 0x46, 0xde, 0xbd, 0x5c,
        0xd9, 0x92, 0xf6, 0xed, 0x09, 0x06, 0x89, 0xd0, 0x58, 0x5f, 0xf0, 0x75, 0xec, 0x9e, 0x99,
        0xad, 0x69, 0x0c, 0x33, 0x95, 0xbc, 0x4b, 0x31, 0x33, 0x70, 0xb3, 0x8e, 0xf3, 0x55, 0xac,
        0xda, 0xdc, 0xd1, 0x22, 0x97, 0x5b, 0x12, 0xc8, 0x5e, 0xa5, 0xdb, 0x8c, 0x6d, 0xeb, 0x4a,
        0xab, 0x71, 0x80, 0x8d, 0xcb, 0x40, 0x8f, 0xe3, 0xd1, 0xe7, 0x69, 0x0c, 0x43, 0xd3, 0x7b,
        0x4c, 0xe6, 0xcc, 0x01, 0x66, 0xfa, 0x7d, 0xaa,
    ];
}

// =============================================================================
// Legacy claim/split VK constants were removed; active proof paths use JoinSplit.

// Circuit-Specific Verify Functions
// =============================================================================

/// Verify a JoinSplit proof with dynamic public inputs
///
/// Public inputs: [merkle_root, bound_params_hash, nullifiers..., commitments_out...]
/// The caller must load the correct DELTA_G2 and IC from the VK registry.
pub fn verify_groth16_joinsplit_proof(
    proof_bytes: &[u8],
    public_inputs: &[&[u8; 32]],
    delta_g2: &[u8; 128],
    ic: &[[u8; 64]],
) -> Result<(), ProgramError> {
    verify_groth16_proof(
        proof_bytes,
        public_inputs,
        &common_vk::ALPHA_G1,
        &common_vk::BETA_G2,
        &common_vk::GAMMA_G2,
        delta_g2,
        ic,
    )
}

// =============================================================================
// JoinSplit VKs are stored in VkRegistry PDA accounts.
// =============================================================================
