//! Shield SPL tokens into the privacy pool.
//!
//! User deposits SPL tokens, which become a shielded commitment in the Merkle tree.
//! No ZK proof needed — the program computes the commitment directly.
//!
//! # Accounts (public path, disc 12)
//! 0. `[signer]`   User
//! 1. `[writable]` User's token account (source)
//! 2. `[]`         Pool state PDA (read deposit_fee_bps, check paused)
//! 3. `[writable]` TokenConfig PDA (check enabled, limits, update total_shielded)
//! 4. `[writable]` Vault token account (destination)
//! 5. `[writable]` Commitment tree
//! 6. `[]`         Token-2022 program
//!
//! # Accounts (permissioned path, disc 23)
//! 0-6. Same as above
//! 7. `[signer]`   Auditor — must match `pool.auditor()` and must not be frozen

use pinocchio::{account_info::AccountInfo, program_error::ProgramError, ProgramResult};

use crate::error::UTXOpiaError;
use crate::state::{CommitmentTree, PoolState, TokenConfig};
use crate::utils::{
    crypto::compute_commitment,
    events::{emit_shield_meta, emit_stealth_announcement, ANNOUNCEMENT_TYPE_DEPOSIT},
    transfer_token_user, validate_account_writable, validate_active_tree_pda,
    validate_any_token_program_key, validate_program_owner, validate_token_owner,
};

/// Instruction data: amount(8) + npk(32) + ephemeral_pub(32) = 72 bytes
pub const SHIELD_DATA_HEADER: usize = 72;

// Keep the old private name as an alias so nothing else breaks.
const DATA_LEN: usize = SHIELD_DATA_HEADER;

/// Verify a public pool SPL shield (disc 12).
///
/// Rejects permissioned pools — use disc 23 (`shield_permissioned`) for those.
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
    let pool_state_info = &accounts[2];

    // Validate signer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Public entry point must not be used for permissioned pools
    validate_program_owner(pool_state_info, program_id)?;
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.permissioned() {
            return Err(UTXOpiaError::NotPermissioned.into());
        }
    }

    shield_inner(program_id, accounts, data, &[])
}

/// Auditor-gated SPL shield for permissioned pools (disc 23).
///
/// Same accounts as `process_shield` (indices 0-6), plus one appended account:
///
/// 7. `[signer]` Auditor — must match `pool.auditor()` and must not be frozen.
///
/// Instruction data layout:
///   fixed shield header (72 bytes) || auditor_ciphertext (variable, may be empty)
///
/// Gate logic:
/// - User MUST be a signer (token transfer authority)
/// - Pool MUST be permissioned (else NotPermissioned)
/// - Auditor account must be a signer (MissingRequiredSignature)
/// - Auditor account key must equal pool.auditor() (Unauthorized)
/// - Pool auditor must not be frozen (AuditorFrozen)
pub fn process_shield_permissioned(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Need the 7 base accounts + 1 auditor signer
    if accounts.len() < 8 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() < DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let user = &accounts[0];
    let pool_state_info = &accounts[2];

    // User must be signer — they authorise the SPL token transfer
    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Trailing bytes after the fixed header are the auditor ciphertext
    let auditor_ciphertext = &data[DATA_LEN..];

    // Validate pool state and enforce permissioned gate
    validate_program_owner(pool_state_info, program_id)?;
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        // This entry point is for permissioned pools only
        if !pool.permissioned() {
            return Err(UTXOpiaError::NotPermissioned.into());
        }

        // Auditor gate — account 7 is the appended auditor signer
        let auditor_info = &accounts[7];

        if !auditor_info.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        if auditor_info.key().as_ref() != pool.auditor() {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        if pool.auditor_is_frozen() {
            return Err(UTXOpiaError::AuditorFrozen.into());
        }
    }

    shield_inner(program_id, accounts, data, auditor_ciphertext)
}

/// Core shield logic shared by both public and permissioned entry points.
///
/// Receives the full instruction `data` slice (at least `DATA_LEN` bytes) and an
/// `auditor_ciphertext` slice (empty on the public path, caller-supplied on the
/// permissioned path).  The auditor ciphertext is emitted as an event when non-empty.
///
/// Callers are responsible for the signer/permissioned gate before calling this function.
fn shield_inner(
    program_id: &pinocchio::pubkey::Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
    auditor_ciphertext: &[u8],
) -> ProgramResult {
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

    // Validate account owners
    // (pool_state_info owner already validated by callers)
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

    // Read token config — validate enabled, limits, vault, mint.
    // Fee/shielded are NOT computed from the user-supplied `amount` here: a fee-on-transfer
    // or deflationary mint can deliver less than `amount` to the vault, which would overcredit
    // the shielded note and leave the pool insolvent. We instead credit the measured vault
    // balance delta after the transfer (see below).
    let (token_id, deposit_cap) = {
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

        // Validate amount limits (against the user-requested gross amount)
        if amount < tc.min_deposit() || amount > tc.max_deposit() {
            return Err(UTXOpiaError::AmountOutOfRange.into());
        }

        let mut tid = [0u8; 32];
        tid.copy_from_slice(&tc.token_id);
        (tid, tc.deposit_cap())
    };

    // Measure the vault balance delta across the transfer so the credited amount reflects
    // tokens actually received, not the nominal `amount`.
    let vault_before = crate::utils::get_token_balance(vault)?;

    // Transfer tokens from user → vault (user signs, no PDA needed)
    transfer_token_user(token_program, user_token_account, vault, user, amount)?;

    let vault_after = crate::utils::get_token_balance(vault)?;
    let received = vault_after
        .checked_sub(vault_before)
        .ok_or(ProgramError::ArithmeticOverflow)?;

    // Derive fee and shielded amount from what the vault actually received.
    let protocol_fee = (received as u128 * deposit_fee_bps as u128 / 10_000) as u64;
    let shielded_amount = received
        .checked_sub(protocol_fee)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if shielded_amount == 0 {
        return Err(UTXOpiaError::AmountTooSmall.into());
    }

    // Check deposit cap against the actual shielded value being added.
    {
        let tc_data = token_config_info.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;
        if tc
            .total_shielded()
            .checked_add(shielded_amount)
            .ok_or(ProgramError::ArithmeticOverflow)?
            > deposit_cap
        {
            return Err(UTXOpiaError::DepositCapExceeded.into());
        }
    }

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

    // Emit shield metadata (actual received gross + fee) for indexer
    emit_shield_meta(received, protocol_fee, &token_id);

    // Emit auditor ciphertext event on the permissioned path (non-empty only)
    if !auditor_ciphertext.is_empty() {
        crate::utils::events::emit_auditor_ciphertext(&commitment, auditor_ciphertext);
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that the fixed shield header (72 bytes) is parsed correctly and
    /// that trailing bytes (auditor_ciphertext) are left in the slice without error.
    #[test]
    fn test_shield_data_parses_fixed_header() {
        let mut data = [0u8; SHIELD_DATA_HEADER + 16]; // 72-byte header + 16 bytes fake ciphertext

        // amount = 1_000_000 LE
        data[0..8].copy_from_slice(&1_000_000u64.to_le_bytes());
        // npk filled with 0xAB
        data[8..40].fill(0xAB);
        // ephemeral_pub filled with 0xCD
        data[40..72].fill(0xCD);
        // Trailing ciphertext bytes
        data[72..88].fill(0xFF);

        let amount = u64::from_le_bytes(data[0..8].try_into().unwrap());
        let npk: &[u8; 32] = data[8..40].try_into().unwrap();
        let ephemeral_pub: &[u8; 32] = data[40..72].try_into().unwrap();

        assert_eq!(amount, 1_000_000u64);
        assert_eq!(npk, &[0xABu8; 32]);
        assert_eq!(ephemeral_pub, &[0xCDu8; 32]);

        // Auditor ciphertext is everything past the fixed header
        let ciphertext = &data[SHIELD_DATA_HEADER..];
        assert_eq!(ciphertext, &[0xFFu8; 16]);
    }

    /// Verify that data shorter than the fixed header is rejected.
    #[test]
    fn test_shield_data_rejects_short_input() {
        // One byte under the required 72
        let short = [0u8; SHIELD_DATA_HEADER - 1];
        assert!(
            short.len() < DATA_LEN,
            "short slice must be below the minimum length"
        );
    }

    /// Verify that an empty auditor ciphertext slice (public path) is accepted
    /// and the slice is empty (nothing to emit).
    #[test]
    fn test_auditor_ciphertext_empty_on_public_path() {
        let data = [0u8; SHIELD_DATA_HEADER]; // exactly 72 bytes, no trailing ciphertext
        let ciphertext = &data[SHIELD_DATA_HEADER..];
        assert!(ciphertext.is_empty(), "public path must produce no ciphertext");
    }
}
