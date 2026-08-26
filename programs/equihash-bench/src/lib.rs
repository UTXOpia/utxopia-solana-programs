//! Measurement spike: what does BLAKE2b cost in BPF?
//!
//! Answers the blocking Phase 0 question in docs/MULTI-CHAIN-POOL-DESIGN-2026-08-26.md. Zcash's
//! Equihash-200,9 is built on BLAKE2b, Solana has no BLAKE2b syscall, and verification evaluates
//! roughly 512 compressions per header. Whether that fits in a 1.4M-CU instruction decides
//! whether ZEC can share Bitcoin's trust model or has to be a checkpointed bridge.
//!
//! Instruction data: mode(1) + u16 LE count.
//!   0 = BLAKE2b compressions in BPF
//!   1 = sol_sha256 calls        2 = sol_keccak256 calls        3 = sol_blake3 calls
//! Modes 1-3 exist to price the same work as a syscall: they hash the same 128-byte block, so
//! the difference against mode 0 is exactly what the missing BLAKE2b syscall costs.
//!
//! Original note: The program does nothing else, so
//! the CU it reports minus the entrypoint baseline is the cost of exactly that many compressions.
//! Delete this crate once the number is recorded.

pub mod blake2b;

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::{account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey, ProgramResult};

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

#[cfg(not(feature = "no-entrypoint"))]
fn process_instruction(_id: &Pubkey, _accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    if data.len() < 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if data.len() < 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mode = data[0];
    let rounds = u16::from_le_bytes([data[1], data[2]]);

    let mut block = [0u8; 128];
    let mut out = [0u8; 32];

    match mode {
        0 => {
            let mut h = [0u64; 8];
            // Vary the block so nothing can be hoisted or folded.
            for i in 0..rounds {
                block[0..2].copy_from_slice(&i.to_le_bytes());
                blake2b::compress(&mut h, &block, i as u128, false);
            }
            out[0..8].copy_from_slice(&h[0].to_le_bytes());
        }
        1..=3 => {
            for i in 0..rounds {
                block[0..2].copy_from_slice(&i.to_le_bytes());
                syscall_hash(mode, &block, &mut out);
            }
        }
        _ => return Err(ProgramError::InvalidInstructionData),
    }

    // Consume the result so the loop cannot be optimised away.
    if out[0] == 0xde && out[1] == 0xad {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// The three hashes Solana exposes as syscalls, called through the same shape so the numbers are
/// comparable. All take a slice-of-slices; one 128-byte input each.
#[cfg(not(feature = "no-entrypoint"))]
fn syscall_hash(mode: u8, block: &[u8; 128], out: &mut [u8; 32]) {
    #[repr(C)]
    struct Slice {
        addr: *const u8,
        len: u64,
    }
    // These symbols only exist on the SBF target; the host build links nothing.
    #[cfg(target_os = "solana")]
    extern "C" {
        fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
        fn sol_keccak256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
        fn sol_blake3(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
    }
    #[cfg(not(target_os = "solana"))]
    {
        let _ = (mode, block, &out);
        return;
    }
    #[cfg(target_os = "solana")]
    {
    let s = Slice { addr: block.as_ptr(), len: 128 };
    let vals = &s as *const Slice as *const u8;
    unsafe {
        match mode {
            1 => sol_sha256(vals, 1, out.as_mut_ptr()),
            2 => sol_keccak256(vals, 1, out.as_mut_ptr()),
            _ => sol_blake3(vals, 1, out.as_mut_ptr()),
        };
    }
    }
}
