//! BTC Light Client Program
//!
//! Permissionless Bitcoin light client with hash-based PDAs.
//! Manages block headers, height indices, and SPV verification.

mod constants;
mod state;
mod utils;
mod instructions;

use pinocchio::{
    account_info::AccountInfo,
    entrypoint,
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use instructions::{
    process_initialize,
    process_extend_blockchain,
    process_verify_transaction,
    process_prune_obsolete_blocks,
    process_reinitialize,
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
        4 => process_reinitialize(program_id, accounts, &data[1..]),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
