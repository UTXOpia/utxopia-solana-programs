//! Initialize the active commitment tree PDA (disc 28)
//!
//! Authority-only. Creates the commitment tree PDA at the pool's current
//! `active_tree_index` when it is missing. Needed when a pool was initialized
//! under the legacy plain-seed tree scheme and the program was later upgraded
//! to the indexed-seed scheme, leaving the active-index tree PDA uncreated.
//!
//! Accounts:
//! 0. [writable] Pool state PDA
//! 1. [writable] Commitment tree PDA at active index (to be created)
//! 2. [signer]   Authority
//! 3. []         System program

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{CommitmentTree, PoolState, COMMITMENT_TREE_DISCRIMINATOR};
use crate::utils::{
    create_pda_account, validate_account_writable, validate_program_owner, validate_system_program,
};

pub fn process_init_tree(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let tree_info = &accounts[1];
    let authority = &accounts[2];
    let system_program = &accounts[3];

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_program_owner(pool_state_info, program_id)?;
    validate_account_writable(tree_info)?;
    validate_system_program(system_program)?;

    let active_index = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
        pool.active_tree_index()
    };

    // Verify tree PDA matches active index
    let index_bytes = active_index.to_le_bytes();
    let tree_seeds: &[&[u8]] = &[CommitmentTree::SEED_PREFIX, &index_bytes];
    let (expected_pda, bump) = find_program_address(tree_seeds, program_id);
    if tree_info.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // If already initialized, nothing to do.
    if tree_info.data_len() > 0 {
        let tree_data = tree_info.try_borrow_data()?;
        if !tree_data.is_empty() && tree_data[0] == COMMITMENT_TREE_DISCRIMINATOR {
            return Err(UTXOpiaError::AlreadyInitialized.into());
        }
    }

    // Create the commitment tree PDA at the active index
    let rent = Rent::get()?;
    let tree_lamports = rent.minimum_balance(CommitmentTree::LEN);
    let bump_bytes = [bump];
    let signer_seeds: &[&[u8]] = &[CommitmentTree::SEED_PREFIX, &index_bytes, &bump_bytes];

    create_pda_account(
        authority,
        tree_info,
        program_id,
        tree_lamports,
        CommitmentTree::LEN as u64,
        signer_seeds,
    )?;

    {
        let mut tree_data = tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::init(&mut tree_data)?;
        tree.bump = bump;
    }

    pinocchio::msg!("UTXOpia: active tree initialized");
    Ok(())
}
