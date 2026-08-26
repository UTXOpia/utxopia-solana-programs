//! Measurement spike: what does BLAKE2b cost in BPF?
//!
//! Answers the blocking Phase 0 question in docs/MULTI-CHAIN-POOL-DESIGN-2026-08-26.md. Zcash's
//! Equihash-200,9 is built on BLAKE2b, Solana has no BLAKE2b syscall, and verification evaluates
//! roughly 512 compressions per header. Whether that fits in a 1.4M-CU instruction decides
//! whether ZEC can share Bitcoin's trust model or has to be a checkpointed bridge.
//!
//! Instruction data: u16 LE = number of compressions to run. The program does nothing else, so
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
    let rounds = u16::from_le_bytes([data[0], data[1]]);

    let mut h = [0u64; 8];
    let mut block = [0u8; 128];
    // Vary the block so nothing can be hoisted or folded: the counter feeds back into the input.
    for i in 0..rounds {
        block[0..2].copy_from_slice(&i.to_le_bytes());
        blake2b::compress(&mut h, &block, i as u128, false);
    }
    // Consume the result so the whole loop cannot be optimised away.
    if h[0] == 0xdead_beef_dead_beef {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}
