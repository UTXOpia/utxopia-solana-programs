//! BTC Light Client Program
//!
//! Permissionless Bitcoin light client with hash-based PDAs.
//! Manages block headers, height indices, and SPV verification.

mod constants;
mod instructions;
mod state;
mod utils;

// A deployable artifact must name its network. Without this, a bare `cargo build-sbf`
// ships `process_reinitialize` — which rewrites the chain head — into whatever cluster
// the operator happens to deploy to, and `network_allowed_in_build` simultaneously
// accepts NETWORK_REGTEST. Scoped to the SBF target so host `cargo test` is unaffected.
#[cfg(all(
    target_os = "solana",
    not(any(
        feature = "mainnet",
        feature = "devnet",
        feature = "localnet",
        feature = "devnet-regtest"
    ))
))]
compile_error!(
    "on-chain build must name its network: --features mainnet|devnet|devnet-regtest|localnet"
);

#[cfg(all(
    feature = "mainnet",
    any(feature = "devnet", feature = "localnet", feature = "devnet-regtest")
))]
compile_error!("feature `mainnet` is mutually exclusive with `devnet`/`localnet`/`devnet-regtest`");

use pinocchio::{
    account_info::AccountInfo, entrypoint, program_error::ProgramError, pubkey::Pubkey,
    ProgramResult,
};

#[cfg(not(feature = "mainnet"))]
use instructions::process_reinitialize;
use instructions::{
    process_extend_blockchain, process_initialize, process_prune_obsolete_blocks,
    process_verify_transaction,
};

entrypoint!(process_instruction);

fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match data[0] {
        0 => process_initialize(program_id, accounts, &data[1..]),
        1 => process_extend_blockchain(program_id, accounts, &data[1..]),
        2 => process_verify_transaction(program_id, accounts, &data[1..]),
        3 => process_prune_obsolete_blocks(program_id, accounts, &data[1..]),
        #[cfg(not(feature = "mainnet"))]
        4 => process_reinitialize(program_id, accounts, &data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
