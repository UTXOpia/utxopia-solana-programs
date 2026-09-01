//! Place queued commitments into the active tree and close their accounts.
//!
//! **Permissionless on purpose.** Anyone may call this, including the owner of
//! the note being merged. That is what makes a `QueuedLeaf` recoverable without
//! a timeout escape hatch: no operator can strand an output note by declining to
//! merge it, because the holder can merge it themselves.
//!
//! It also means self-merging is a privacy cost, not a feature. A user who signs
//! their own merge links their Solana identity to that specific leaf, and the
//! timing says they are in a hurry to spend it. The account layout therefore
//! separates the fee payer from the rent recipients so a relayer can merge on
//! everyone's behalf — that is the intended path, and self-merge is the escape
//! hatch. Merge often enough that nobody needs the escape hatch: cadence is a
//! privacy parameter here, not just a UX one.
//!
//! Rent goes back to the payer recorded in each `QueuedLeaf`, never to the
//! caller, so racing to merge earns nothing.
//!
//! This is also where `pool_state.nullifier_count` is applied. Bumping it per
//! spend is what keeps `pool_state` a shared write lock on the hot path; each
//! spend records its `nullifier_debt` instead and merge pays the sum. Merge
//! already takes the tree's lock and runs once per batch, so the write costs
//! nothing that was not already serialised.
//!
//! Instruction data: none beyond the discriminator. What gets merged, and in
//! what order, is the account list — leaf `i` lands at `first_leaf_index + i`.
//!
//! Accounts:
//! 0. caller           (signer, writable — pays the fee; a relayer or the holder)
//! 1. pool_state       (writable — nullifier_count)
//! 2. commitment_tree  (writable — the active tree)
//! 3.. pairs of (queued_leaf writable, rent_recipient writable), 1..=MAX_MERGE_LEAVES

use crate::error::UTXOpiaError;
use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError, Pubkey};
use crate::state::{CommitmentTree, PoolState, QueuedLeaf};
use crate::utils::{
    close_account_securely, validate_account_writable, validate_active_tree_pda,
    validate_program_owner,
};
use pinocchio::ProgramResult;

const FIXED_ACCOUNTS: usize = 3;

/// One merge is bounded by the transaction account limit, not by CU: each leaf
/// costs two accounts. 24 leaves is 51 accounts with the fixed three, which
/// leaves room under the legacy 64-account cap without an address table. The
/// per-leaf log entry is 32 bytes, so a full batch stays far inside the 10 KB
/// log budget too.
///
/// A relayer that paid for every queued transact passes the same rent recipient
/// for all of them; Solana counts that as one unique account, so the practical
/// ceiling in the common relayed case is the 24 leaves, not the account list.
pub const MAX_MERGE_LEAVES: usize = crate::utils::events::MAX_MERGE_BATCH;

pub fn process_merge_queued_leaves(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < FIXED_ACCOUNTS + 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let tail = accounts.len() - FIXED_ACCOUNTS;
    if tail % 2 != 0 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let leaf_count = tail / 2;
    if leaf_count > MAX_MERGE_LEAVES {
        return Err(UTXOpiaError::ExcessiveReservedInputs.into());
    }

    let caller = &accounts[0];
    let pool_state_info = &accounts[1];
    let commitment_tree_info = &accounts[2];

    if !caller.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_account_writable(pool_state_info)?;
    validate_account_writable(commitment_tree_info)?;

    // A paused pool must not grow its tree; queued leaves keep until it resumes.
    let active_tree_index = {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }
        pool.active_tree_index()
    };
    validate_active_tree_pda(
        commitment_tree_info,
        pool_state_info,
        program_id,
        active_tree_index,
    )?;

    // Pass 1 — validate everything and copy the commitments out, so no account
    // borrow is still open when the tree is written.
    let mut commitments = [[0u8; 32]; MAX_MERGE_LEAVES];
    let mut nullifier_debt: u32 = 0;
    for i in 0..leaf_count {
        let leaf_info = &accounts[FIXED_ACCOUNTS + i * 2];
        let rent_recipient = &accounts[FIXED_ACCOUNTS + i * 2 + 1];

        validate_program_owner(leaf_info, program_id)?;
        validate_account_writable(leaf_info)?;
        validate_account_writable(rent_recipient)?;

        let leaf_data = leaf_info.try_borrow()?;
        QueuedLeaf::validate(&leaf_data)?;

        // Refuse to flush across a rotation. Leaf indices restart at 0 in a new
        // tree and nullifiers are scoped per tree, so a commitment proved against
        // tree N must never land in tree N+1 — it would be unspendable, and the
        // note silently lost.
        if QueuedLeaf::tree_index(&leaf_data) != active_tree_index {
            return Err(UTXOpiaError::InvalidPDA.into());
        }

        let commitment = QueuedLeaf::commitment(&leaf_data);
        let (expected_pda, _bump) = find_program_address(
            &[
                QueuedLeaf::SEED,
                pool_state_info.address().as_ref(),
                commitment.as_ref(),
            ],
            program_id,
        );
        if leaf_info.address() != &expected_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        // Rent follows the recorded payer, not the caller.
        if rent_recipient.address().as_ref() != QueuedLeaf::payer(&leaf_data).as_ref() {
            return Err(UTXOpiaError::InvalidPDA.into());
        }

        // One account must not be counted twice. Nullifiers are
        // Poseidon(nullifyingKey, leafIndex) — position, not content
        // (joinsplit.circom:42) — so a leaf placed at two indices yields two
        // distinct spendable nullifiers for one deposit of value.
        //
        // Deliberately compares ADDRESSES, not commitments. Two *different*
        // deposits that happen to collide on a commitment are two real notes and
        // both belong in the tree at their own leaves; only re-counting a single
        // account is theft. The PDA is seeded on the commitment today, which
        // makes the two checks equivalent, but the address is the invariant that
        // stays right if that seeding ever changes.
        //
        // O(n^2) over at most MAX_MERGE_LEAVES is not worth avoiding.
        for prior in 0..i {
            if accounts[FIXED_ACCOUNTS + prior * 2].address() == leaf_info.address() {
                return Err(UTXOpiaError::NullifierAlreadyUsed.into());
            }
        }

        commitments[i] = *commitment;
        // u8 per leaf, at most MAX_MERGE_LEAVES of them, so this cannot overflow
        // a u32 — and `add_nullifiers` saturates anyway.
        nullifier_debt += QueuedLeaf::nullifier_debt(&leaf_data) as u32;
    }

    // Pass 2 — one batched insert, one root-history slot.
    let refs: [&[u8; 32]; MAX_MERGE_LEAVES] = core::array::from_fn(|i| &commitments[i]);
    let first_leaf_index = {
        let mut tree_data = commitment_tree_info.try_borrow_mut()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;
        tree.insert_leaves_batch(&refs[..leaf_count])?
    };

    crate::utils::events::emit_leaves_merged(first_leaf_index, &refs[..leaf_count]);

    // Settle the nullifier accounting the spends deferred. Saturating, and never
    // able to abort the merge — the same property the inline bump had.
    if nullifier_debt > 0 {
        let mut pool_data = pool_state_info.try_borrow_mut()?;
        PoolState::from_bytes_mut(&mut pool_data)?.add_nullifiers(nullifier_debt);
    }

    // Pass 3 — close each leaf to its recorded payer. Last, so a failure in any
    // validation above leaves every queued leaf untouched.
    for i in 0..leaf_count {
        let leaf_info = &accounts[FIXED_ACCOUNTS + i * 2];
        let rent_recipient = &accounts[FIXED_ACCOUNTS + i * 2 + 1];
        close_account_securely(leaf_info, rent_recipient)?;
    }

    Ok(())
}
