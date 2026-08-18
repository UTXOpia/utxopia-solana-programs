//! Account validation utilities for security checks
//!
//! CRITICAL: These functions must be called BEFORE deserializing any account data.
//! Without owner validation, attackers can pass fake accounts with crafted data.

use crate::pinocchio_compat::{account_owner, AccountInfo, ProgramError, Pubkey};
use pinocchio::{
    cpi::{Seed, Signer},
    ProgramResult,
};

use crate::constants::{TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID};
use crate::error::UTXOpiaError;

/// Derive the UTXO reservation key for a redemption from its (globally-unique) PDA address.
///
/// Reserved UTXOs are bound to this value at mark_processing and checked at approve / complete /
/// cancel. Using the redemption PDA (unique per requester+nonce) instead of the caller-chosen
/// nonce alone closes the cross-request confusion where two different users picking the same
/// nonce shared a reservation id (audit f26). Stored in the existing 8-byte UtxoRecord field as
/// the first 8 bytes of sha256(pda); a 64-bit collision/grind buys an attacker nothing and is
/// infeasible, and this keeps the on-chain layout unchanged.
#[inline]
pub fn redemption_reservation_key(redemption_pda: &Pubkey) -> u64 {
    let h = crate::utils::bitcoin::sha256(redemption_pda.as_ref());
    u64::from_le_bytes(h[..8].try_into().unwrap())
}

// ============================================================================
// PDA CREATION HELPER (shared across all instructions)
// ============================================================================

/// Create a PDA account via CPI to system program.
///
/// This is a shared helper to eliminate duplication across instruction files.
/// Previously duplicated across account-creating instruction handlers.
///
/// # Security: pre-funded PDA poisoning resistance
/// A bare `CreateAccount` fails if the target PDA already holds lamports
/// (`SystemError::AccountAlreadyInUse`). Because every PDA address here is
/// deterministic, a griefer can transfer 1 lamport to the known address before
/// initialization and permanently block creation (DoS). To stay resilient we
/// fall back to `Transfer` (top up rent) + `Allocate` + `Assign` — all signed by
/// the PDA seeds — when the account is already funded but still uninitialized.
#[inline]
pub fn create_pda_account<'a>(
    payer: &'a AccountInfo,
    pda_account: &'a AccountInfo,
    program_id: &Pubkey,
    lamports: u64,
    space: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    // Convert seeds to Pinocchio format
    // PolicyApproval uses four namespace seeds plus its bump. Keep this
    // helper large enough for every PDA family accepted by the program.
    if signer_seeds.len() > 5 {
        return Err(ProgramError::MaxSeedLengthExceeded);
    }
    let seeds: [Seed; 5] = [
        if !signer_seeds.is_empty() {
            Seed::from(signer_seeds[0])
        } else {
            Seed::from(&[][..])
        },
        if signer_seeds.len() > 1 {
            Seed::from(signer_seeds[1])
        } else {
            Seed::from(&[][..])
        },
        if signer_seeds.len() > 2 {
            Seed::from(signer_seeds[2])
        } else {
            Seed::from(&[][..])
        },
        if signer_seeds.len() > 3 {
            Seed::from(signer_seeds[3])
        } else {
            Seed::from(&[][..])
        },
        if signer_seeds.len() > 4 {
            Seed::from(signer_seeds[4])
        } else {
            Seed::from(&[][..])
        },
    ];

    let signers = [Signer::from(&seeds[..signer_seeds.len()])];

    if pda_account.lamports() == 0 {
        pinocchio_system::instructions::CreateAccount {
            from: payer,
            to: pda_account,
            lamports,
            space,
            owner: program_id,
        }
        .invoke_signed(&signers)
    } else {
        // Pre-funded PDA: a bare CreateAccount would fail, so reconstruct the
        // account in place. Top up rent (if short), allocate space, then assign
        // ownership to this program — all authorized by the PDA seeds.
        let current = pda_account.lamports();
        if lamports > current {
            pinocchio_system::instructions::Transfer {
                from: payer,
                to: pda_account,
                lamports: lamports - current,
            }
            .invoke()?;
        }
        if (pda_account.data_len() as u64) < space {
            pinocchio_system::instructions::Allocate {
                account: pda_account,
                space,
            }
            .invoke_signed(&signers)?;
        }
        if !pda_account.owned_by(program_id) {
            pinocchio_system::instructions::Assign {
                account: pda_account,
                owner: program_id,
            }
            .invoke_signed(&signers)?;
        }
        Ok(())
    }
}

// ============================================================================
// BATCH VALIDATION HELPERS
// ============================================================================

/// Validate multiple accounts are owned by program and writable
///
/// Combines owner + writable validation for common patterns.
/// Reduces boilerplate in instruction handlers.
#[inline]
pub fn validate_program_accounts_writable(
    accounts: &[&AccountInfo],
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    for account in accounts {
        validate_program_owner(account, program_id)?;
        validate_account_writable(account)?;
    }
    Ok(())
}

/// Validate multiple accounts are owned by program (read-only)
#[inline]
pub fn validate_program_accounts(
    accounts: &[&AccountInfo],
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    for account in accounts {
        validate_program_owner(account, program_id)?;
    }
    Ok(())
}

// ============================================================================
// SINGLE ACCOUNT VALIDATION
// ============================================================================

/// Validate that an account is owned by the program
///
/// # Security
/// This MUST be called before deserializing any program-owned account (PoolState,
/// CommitmentTree, NullifierRecord, DepositRecord, RedemptionRequest, etc.)
///
/// Without this check, an attacker can:
/// 1. Create a fake account with crafted data matching expected discriminator
/// 2. Pass it to an instruction
/// 3. Have the program trust the fake data
#[inline(always)]
pub fn validate_program_owner(
    account: &AccountInfo,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    let owner = account_owner(account);
    if owner != program_id {
        return Err(UTXOpiaError::InvalidAccountOwner.into());
    }
    Ok(())
}

/// Validate that an account is owned by Token-2022 program
#[inline(always)]
pub fn validate_token_2022_owner(account: &AccountInfo) -> Result<(), ProgramError> {
    if !account.owned_by(&Pubkey::new_from_array(TOKEN_2022_PROGRAM_ID)) {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

/// Validate that an account is owned by either Token or Token-2022 program
#[inline(always)]
pub fn validate_token_owner(account: &AccountInfo) -> Result<(), ProgramError> {
    let owner = account_owner(account).as_ref();
    if owner != TOKEN_2022_PROGRAM_ID && owner != TOKEN_PROGRAM_ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

/// Validate that an account key matches the Token-2022 program ID
#[inline(always)]
pub fn validate_token_program_key(account: &AccountInfo) -> Result<(), ProgramError> {
    if account.address().as_ref() != TOKEN_2022_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

/// Validate that an account key matches either Token or Token-2022 program ID
#[inline(always)]
pub fn validate_any_token_program_key(account: &AccountInfo) -> Result<(), ProgramError> {
    let key = account.address().as_ref();
    if key != TOKEN_2022_PROGRAM_ID && key != TOKEN_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

/// Validate that an account is the System Program
#[inline(always)]
pub fn validate_system_program(account: &AccountInfo) -> Result<(), ProgramError> {
    const SYSTEM_PROGRAM_ID: [u8; 32] = [0; 32];
    if account.address().as_ref() != SYSTEM_PROGRAM_ID {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

/// Validate multiple program-owned accounts at once
///
/// # Arguments
/// * `accounts` - Slice of accounts to validate
/// * `program_id` - The program ID that should own these accounts
#[inline(always)]
pub fn validate_program_owners(
    accounts: &[&AccountInfo],
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    for account in accounts {
        validate_program_owner(account, program_id)?;
    }
    Ok(())
}

/// Validate that an account is writable
///
/// # Security
/// This MUST be called before any `try_borrow_mut()` operation.
/// Without this check, silent state corruption can occur if a read-only
/// account is passed where a writable one is expected.
#[inline(always)]
pub fn validate_account_writable(account: &AccountInfo) -> Result<(), ProgramError> {
    if !account.is_writable() {
        return Err(UTXOpiaError::AccountNotWritable.into());
    }
    Ok(())
}

/// Validate that a token account belongs to the expected mint
///
/// # Security
/// This prevents token account spoofing attacks where an attacker
/// passes a token account for a different mint.
///
/// # Token Account Layout (Token-2022)
/// - Bytes 0-32: mint pubkey
/// - Bytes 32-64: owner pubkey
/// - Bytes 64-72: amount (u64)
#[inline(always)]
pub fn validate_token_mint(
    token_account: &AccountInfo,
    expected_mint: &Pubkey,
) -> Result<(), ProgramError> {
    let data = token_account.try_borrow()?;
    if data.len() < 32 {
        return Err(UTXOpiaError::InvalidAccountData.into());
    }

    let mint_bytes: [u8; 32] = data[0..32]
        .try_into()
        .map_err(|_| UTXOpiaError::InvalidAccountData)?;

    if mint_bytes != expected_mint.as_ref() {
        return Err(UTXOpiaError::InvalidMint.into());
    }
    Ok(())
}

/// Validate that two accounts are different (prevent duplicate mutable account attacks)
///
/// # Security
/// Passing the same account for multiple parameters can cause the program
/// to overwrite its own changes, leading to unexpected behavior.
#[inline(always)]
pub fn validate_accounts_different(
    account1: &AccountInfo,
    account2: &AccountInfo,
) -> Result<(), ProgramError> {
    if account1.address() == account2.address() {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}

/// Validate that an account is initialized (has discriminator set)
///
/// # Security
/// Prevents use of uninitialized accounts that may contain garbage data.
#[inline(always)]
pub fn validate_initialized(
    account: &AccountInfo,
    expected_discriminator: u8,
) -> Result<(), ProgramError> {
    let data = account.try_borrow()?;
    if data.is_empty() || data[0] != expected_discriminator {
        return Err(UTXOpiaError::NotInitialized.into());
    }
    Ok(())
}

/// Validate that an account is NOT initialized (for safe initialization)
///
/// # Security
/// Prevents reinitialization attacks that could overwrite existing data.
#[inline(always)]
pub fn validate_not_initialized(
    account: &AccountInfo,
    discriminator: u8,
) -> Result<(), ProgramError> {
    let data = account.try_borrow()?;
    if !data.is_empty() && data[0] == discriminator {
        return Err(UTXOpiaError::AlreadyInitialized.into());
    }
    Ok(())
}

/// Securely close an account (prevents revival attacks)
///
/// # Security
/// 1. Marks account as closed with special discriminator
/// 2. Transfers all lamports to destination
/// 3. Zeroes remaining data to prevent data leakage
///
/// This prevents "revival attacks" where a closed account is
/// refunded within the same transaction.
pub fn close_account_securely(
    account: &AccountInfo,
    destination: &AccountInfo,
) -> Result<(), ProgramError> {
    // Mark as closed with special discriminator
    {
        let mut data = account.try_borrow_mut()?;
        if !data.is_empty() {
            data[0] = 0xFF; // Closed account marker
                            // Zero remaining data for security
            for byte in data[1..].iter_mut() {
                *byte = 0;
            }
        }
    }

    // Transfer all lamports to destination
    let account_lamports = account.lamports();
    if account_lamports > 0 {
        // Subtract from source
        account.set_lamports(0);
        // Add to destination
        destination.set_lamports(
            destination
                .lamports()
                .checked_add(account_lamports)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
    }

    Ok(())
}

/// Parse the upgrade authority out of a `BPFLoaderUpgradeable` ProgramData account.
///
/// Layout: `u32` enum tag (3 = ProgramData) + `u64` deploy slot + `Option<Pubkey>` authority
/// (1-byte tag + 32 bytes). A finalized program has tag 0 and no authority — every caller here
/// treats that as "nobody is authorized", which is what makes `set-upgrade-authority --final`
/// a permanent freeze of the admin-only instructions.
fn programdata_upgrade_authority(data: &[u8]) -> Result<&[u8], ProgramError> {
    if data.len() < 45 || data[0..4] != [3, 0, 0, 0] || data[12] != 1 {
        return Err(UTXOpiaError::Unauthorized.into());
    }
    Ok(&data[13..45])
}

/// Require `signer` to be this program's upgrade authority.
///
/// The only global admin identity a pool-less resource can have. Whoever holds it can already
/// redeploy the program and rewrite every rule, so gating on it adds no new trust — but it stops
/// a caller-supplied `pool_state` (which anyone can create, since `INITIALIZE` is permissionless)
/// or a bare `is_signer()` check from standing in for "the protocol admin".
pub fn validate_upgrade_authority(
    program_id: &Pubkey,
    program_data: &AccountInfo,
    signer: &AccountInfo,
) -> ProgramResult {
    use crate::constants::BPF_LOADER_UPGRADEABLE_ID;
    use crate::pinocchio_compat::find_program_address;

    if !signer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let loader = Pubkey::new_from_array(BPF_LOADER_UPGRADEABLE_ID);
    let (expected, _) = find_program_address(&[program_id.as_ref()], &loader);
    if program_data.address() != &expected || !program_data.owned_by(&loader) {
        return Err(ProgramError::InvalidArgument);
    }

    let data = program_data.try_borrow()?;
    if programdata_upgrade_authority(&data)? != signer.address().as_ref() {
        return Err(UTXOpiaError::Unauthorized.into());
    }
    Ok(())
}

/// Validate a mint-namespaced pool: ["pool_state", zkbtc_mint].
pub fn validate_pool_state_pda(
    pool_account: &AccountInfo,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    use crate::pinocchio_compat::find_program_address;
    use crate::state::PoolState;

    validate_program_owner(pool_account, program_id)?;
    let pool_data = pool_account.try_borrow()?;
    let pool = PoolState::from_bytes(&pool_data)?;
    let (namespaced, bump) =
        find_program_address(&[PoolState::SEED, &pool.zkbtc_mint], program_id);
    if pool_account.address() != &namespaced || pool.bump != bump {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

/// Return signer material after validating the pool PDA.
pub fn validated_pool_signer(
    pool_account: &AccountInfo,
    program_id: &Pubkey,
) -> Result<([u8; 32], u8), ProgramError> {
    validate_pool_state_pda(pool_account, program_id)?;
    let pool_data = pool_account.try_borrow()?;
    let pool = crate::state::PoolState::from_bytes(&pool_data)?;
    Ok((pool.zkbtc_mint, pool.bump))
}

/// Validate ["token_config", pool_state, mint].
pub fn validate_token_config_pda(
    token_config_account: &AccountInfo,
    pool_account: &AccountInfo,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    use crate::pinocchio_compat::find_program_address;
    use crate::state::TokenConfig;

    validate_program_owner(token_config_account, program_id)?;
    validate_pool_state_pda(pool_account, program_id)?;
    let data = token_config_account.try_borrow()?;
    let config = TokenConfig::from_bytes(&data)?;
    let (expected, bump) = find_program_address(
        &[
            TokenConfig::SEED,
            pool_account.address().as_ref(),
            &config.mint,
        ],
        program_id,
    );
    if token_config_account.address() != &expected || config.bump != bump {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

/// Validate ["pool_config", pool_state].
pub fn validate_pool_config_pda(
    pool_config_account: &AccountInfo,
    pool_account: &AccountInfo,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    use crate::pinocchio_compat::find_program_address;
    use crate::state::PoolConfig;

    validate_program_owner(pool_config_account, program_id)?;
    validate_pool_state_pda(pool_account, program_id)?;
    let expected = find_program_address(
        &[PoolConfig::SEED, pool_account.address().as_ref()],
        program_id,
    )
    .0;
    if pool_config_account.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

/// Validate ["redemption", pool_state, requester, request_id].
pub fn validate_redemption_pda(
    redemption_account: &AccountInfo,
    pool_account: &AccountInfo,
    program_id: &Pubkey,
) -> Result<(), ProgramError> {
    use crate::pinocchio_compat::find_program_address;
    use crate::state::RedemptionRequest;

    validate_program_owner(redemption_account, program_id)?;
    validate_pool_state_pda(pool_account, program_id)?;
    let data = redemption_account.try_borrow()?;
    let redemption = RedemptionRequest::from_bytes(&data)?;
    let nonce = redemption.request_id().to_le_bytes();
    let expected = find_program_address(
        &[
            RedemptionRequest::SEED,
            pool_account.address().as_ref(),
            &redemption.requester,
            &nonce,
        ],
        program_id,
    )
    .0;
    if redemption_account.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

/// Validate that a commitment tree account matches its pool and active tree index.
pub fn validate_active_tree_pda(
    tree_account: &AccountInfo,
    pool_account: &AccountInfo,
    program_id: &Pubkey,
    active_index: u32,
) -> Result<(), ProgramError> {
    use crate::pinocchio_compat::find_program_address;
    use crate::state::CommitmentTree;

    let index_bytes = active_index.to_le_bytes();
    validate_pool_state_pda(pool_account, program_id)?;
    let indexed_seeds: &[&[u8]] = &[
        CommitmentTree::SEED_PREFIX,
        pool_account.address().as_ref(),
        &index_bytes,
    ];
    let (expected_pda, _) = find_program_address(indexed_seeds, program_id);

    if tree_account.address() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    Ok(())
}

/// Validate that a frozen (historical) tree account is a valid commitment tree PDA
/// with an index less than the active index.
///
/// Returns the tree's current_root for root verification.
pub fn validate_frozen_tree(
    tree_account: &AccountInfo,
    pool_account: &AccountInfo,
    program_id: &Pubkey,
    active_index: u32,
    expected_root: &[u8; 32],
) -> Result<bool, ProgramError> {
    use crate::pinocchio_compat::find_program_address;
    use crate::state::{CommitmentTree, COMMITMENT_TREE_DISCRIMINATOR};

    validate_program_owner(tree_account, program_id)?;

    let tree_data = tree_account.try_borrow()?;
    if tree_data.is_empty() || tree_data[0] != COMMITMENT_TREE_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }

    let tree = CommitmentTree::from_bytes(&tree_data)?;

    // O(1) validation (audit f23): the tree stores its own rotation index, so we derive and
    // compare a SINGLE PDA instead of looping 0..active_index (which exhausted the compute
    // budget after enough rotations and bricked old-note spends). The stored index must be a
    // genuinely frozen tree (strictly less than the active index), and the derived PDA must
    // match the supplied account — so the index can't be forged. A frozen tree no longer
    // mutates, so accepting any root still in its history is safe.
    let idx = tree.tree_index();
    if idx >= active_index {
        return Err(ProgramError::InvalidSeeds);
    }
    let idx_bytes = idx.to_le_bytes();
    validate_pool_state_pda(pool_account, program_id)?;
    let seeds: &[&[u8]] = &[
        CommitmentTree::SEED_PREFIX,
        pool_account.address().as_ref(),
        &idx_bytes,
    ];
    let (pda, _) = find_program_address(seeds, program_id);
    if tree_account.address() != &pda {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(tree.is_valid_root(expected_root))
}

#[cfg(test)]
#[path = "validation_tests.rs"]
mod tests;
