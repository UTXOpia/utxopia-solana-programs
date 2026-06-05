//! Rotate commitment tree (disc 20)
//!
//! Authority-only instruction. When the active commitment tree is full
//! (next_index >= 2^16), creates a new tree PDA with the next index
//! and updates the pool's active_tree_index.
//!
//! Old trees remain on-chain as frozen, read-only state. Their current_root
//! is still valid for spending notes (proofs reference a specific tree).
//!
//! Accounts:
//! 0. [writable] Pool state PDA
//! 1. [writable] Current commitment tree (must be full)
//! 2. [writable] New commitment tree PDA (to be created)
//! 3. [signer]   Authority
//! 4. []         System program

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{CommitmentTree, PoolState};
use crate::utils::{
    create_pda_account, validate_account_writable, validate_program_owner, validate_system_program,
};

pub fn process_rotate_tree(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let current_tree_info = &accounts[1];
    let new_tree_info = &accounts[2];
    let authority = &accounts[3];
    let system_program = &accounts[4];

    // Validate
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(current_tree_info, program_id)?;
    validate_account_writable(pool_state_info)?;
    validate_account_writable(new_tree_info)?;
    validate_system_program(system_program)?;

    // Read pool state
    let current_index = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        pool.active_tree_index()
    };

    // Verify current tree PDA matches active index
    let current_index_bytes = current_index.to_le_bytes();
    let current_tree_seeds: &[&[u8]] = &[CommitmentTree::SEED_PREFIX, &current_index_bytes];
    let (expected_current_pda, _) = find_program_address(current_tree_seeds, program_id);
    if current_tree_info.key() != &expected_current_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Verify current tree is full
    {
        let tree_data = current_tree_info.try_borrow_data()?;
        let tree = CommitmentTree::from_bytes(&tree_data)?;
        if tree.next_index() < CommitmentTree::MAX_LEAVES {
            pinocchio::msg!("UTXOpia: tree not full yet");
            return Err(ProgramError::InvalidInstructionData);
        }
    }

    // Derive new tree PDA
    let new_index = current_index.wrapping_add(1);
    let new_index_bytes = new_index.to_le_bytes();
    let new_tree_seeds: &[&[u8]] = &[CommitmentTree::SEED_PREFIX, &new_index_bytes];
    let (expected_new_pda, new_bump) = find_program_address(new_tree_seeds, program_id);
    if new_tree_info.key() != &expected_new_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Create new tree PDA
    let rent = Rent::get()?;
    let tree_lamports = rent.minimum_balance(CommitmentTree::LEN);
    let new_bump_bytes = [new_bump];
    let new_signer_seeds: &[&[u8]] = &[
        CommitmentTree::SEED_PREFIX,
        &new_index_bytes,
        &new_bump_bytes,
    ];

    create_pda_account(
        authority,
        new_tree_info,
        program_id,
        tree_lamports,
        CommitmentTree::LEN as u64,
        new_signer_seeds,
    )?;

    // Initialize new tree
    {
        let mut tree_data = new_tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::init(&mut tree_data)?;
        tree.bump = new_bump;
    }

    // Update pool state
    {
        let mut pool_data = pool_state_info.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;
        pool.set_active_tree_index(new_index);
    }

    pinocchio::msg!("UTXOpia: tree rotated");
    Ok(())
}
