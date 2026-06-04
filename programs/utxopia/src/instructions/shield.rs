//! Shield SPL tokens into the privacy pool.
//!
//! User deposits SPL tokens, which become a shielded commitment in the Merkle tree.
//! No ZK proof needed — the program computes the commitment directly.
//!
//! # Accounts
//! 0. `[signer]`   User
//! 1. `[writable]` User's token account (source)
//! 2. `[]`         Pool state PDA (read deposit_fee_bps, check paused)
//! 3. `[writable]` TokenConfig PDA (check enabled, limits, update total_shielded)
//! 4. `[writable]` Vault token account (destination)
//! 5. `[writable]` Commitment tree
//! 6. `[]`         Token-2022 program

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{CommitmentTree, PoolState, TokenConfig};
use crate::utils::{
    crypto::compute_commitment,
    events::{emit_stealth_announcement, emit_shield_meta, ANNOUNCEMENT_TYPE_DEPOSIT},
    transfer_token_user,
    validate_account_writable, validate_active_tree_pda, validate_program_owner,
    validate_token_owner, validate_any_token_program_key,
};

/// Instruction data: amount(8) + npk(32) + ephemeral_pub(32) = 72 bytes
const DATA_LEN: usize = 72;

pub fn process_shield(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() < DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let user = &accounts[0];
    let user_token_account = &accounts[1];
    let pool_state_info = &accounts[2];
    let token_config_info = &accounts[3];
    let vault = &accounts[4];
    let commitment_tree_info = &accounts[5];
    let token_program = &accounts[6];

    // Parse instruction data
    let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let npk: &[u8; 32] = data[8..40].try_into().unwrap();
    let ephemeral_pub: &[u8; 32] = data[40..72].try_into().unwrap();

    // Validate signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate account owners
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(token_config_info, program_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_token_owner(user_token_account)?;
    validate_token_owner(vault)?;
    validate_any_token_program_key(token_program)?;
    validate_account_writable(user_token_account)?;
    validate_account_writable(token_config_info)?;
    validate_account_writable(vault)?;
    validate_account_writable(commitment_tree_info)?;

    // Read pool state — check paused, validate active tree, read deposit_fee_bps
    let deposit_fee_bps = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }
        validate_active_tree_pda(commitment_tree_info, program_id, pool.active_tree_index())?;
        pool.deposit_fee_bps()
    };

    // Read token config — validate enabled, limits, vault, mint
    let (token_id, shielded_amount, protocol_fee) = {
        let tc_data = token_config_info.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;

        if !tc.is_enabled() {
            return Err(UTXOpiaError::TokenDisabled.into());
        }

        // Validate vault matches
        if vault.key().as_ref() != tc.vault {
            return Err(UTXOpiaError::InvalidVault.into());
        }

        // Validate user token account mint matches token_config mint
        {
            let uta_data = user_token_account.try_borrow_data()?;
            if uta_data.len() < 32 {
                return Err(ProgramError::InvalidAccountData);
            }
            if uta_data[0..32] != tc.mint {
                return Err(UTXOpiaError::InvalidMint.into());
            }
        }

        // Validate amount limits
        if amount < tc.min_deposit() || amount > tc.max_deposit() {
            return Err(UTXOpiaError::AmountOutOfRange.into());
        }

        // Compute fee
        let fee = (amount as u128 * deposit_fee_bps as u128 / 10_000) as u64;
        let shielded = amount
            .checked_sub(fee)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // Check deposit cap
        if tc
            .total_shielded()
            .checked_add(shielded)
            .ok_or(ProgramError::ArithmeticOverflow)?
            > tc.deposit_cap()
        {
            return Err(UTXOpiaError::DepositCapExceeded.into());
        }

        let mut tid = [0u8; 32];
        tid.copy_from_slice(&tc.token_id);
        (tid, shielded, fee)
    };

    // Transfer tokens from user → vault (user signs, no PDA needed)
    transfer_token_user(token_program, user_token_account, vault, user, amount)?;

    // Compute commitment: Poseidon(npk, token_id, shielded_amount)
    let commitment = compute_commitment(npk, &token_id, shielded_amount)?;

    // Insert into Merkle tree
    let leaf_index = {
        let mut tree_data = commitment_tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;
        tree.insert_leaf(&commitment)?;
        tree.next_index() - 1
    };

    // Emit stealth announcement v2 with token_id
    let amount_bytes = shielded_amount.to_le_bytes();
    emit_stealth_announcement(
        ANNOUNCEMENT_TYPE_DEPOSIT,
        ephemeral_pub,
        &amount_bytes,
        &commitment,
        leaf_index as u32,
        &token_id,
    );

    // Emit shield metadata (gross amount + fee) for indexer
    emit_shield_meta(amount, protocol_fee, &token_id);

    // Update token config: total_shielded and accumulated_fees
    {
        let mut tc_data = token_config_info.try_borrow_mut_data()?;
        let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;
        tc.add_shielded(shielded_amount)?;
        tc.add_fees(protocol_fee)?;
    }

    pinocchio::msg!("UTXOpia: shielded tokens");
    Ok(())
}
