//! JoinSplit Transact instruction (Railgun-aligned)
//!
//! Unified instruction that replaces claim, spend_split, and spend_partial_public.
//! Supports N inputs and M outputs with a single Groth16 proof.
//!
//! Supports two modes:
//! - **Inline proof**: proof_source=0, proof is in instruction data
//! - **Buffer proof**: proof_source=1, proof omitted from ix data, read from
//!   proof_buffer account (ChadBuffer) appended after stealth accounts.
//!   Saves 256 bytes of instruction data for large JoinSplits.
//!
//! Instruction Data Layout:
//! - [0]     n_inputs:         u8
//! - [1]     n_outputs:        u8
//! - [2]     n_public_outputs: u8  (must be 0 for transact)
//! - [3]     proof_source:     u8  (0=inline, 1=buffer account)
//! - If proof_source=0:
//!   - [4..260]  proof:        [u8; 256]  (Groth16 proof)
//! - If proof_source=1:
//!   - proof is read from the proof_buffer account (last account)
//! - [..]     merkle_root:     [u8; 32]
//! - [..]     bound_params_hash: [u8; 32]
//! - [..]     nullifiers:      [[u8; 32]; n_inputs]
//! - [..]     commitments_out: [[u8; 32]; n_outputs]
//! - [..]     stealth_data:    [ephemeral_pub(32) + encrypted_amount(8) + encrypted_token_id(32)] × n_outputs
//!
//! Sender memos are detected by comparing `data.len()` to `expected_len` vs
//! `expected_len + n_outputs * 80`. Older clients omit the memos; the contract
//! handles both. Commitment + leafIndex used as AAD inside the memo are filled
//! in by the contract from the public inputs and tree insertion result.
//!
//! Accounts:
//! 0. pool_state         (writable)
//! 1. commitment_tree    (writable)
//! 2. vk_registry        (read)
//! 3. user               (signer, payer)
//! 4. system_program     (read)
//!    5..5+n_inputs         nullifier_records (writable, PDA)
//!    [optional]            relayer (signer, payer — if present after nullifiers)
//!    [optional]            proof_buffer (read, only when proof_source=1, last account)

use crate::pinocchio_compat::{AccountInfo, ProgramError, Pubkey};
use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::instructions::joinsplit_common::{
    jsflags, NullifierAccounting, resolve_joinsplit_tail, PolicyTail,
    create_nullifier_records, looks_like_commitment_tree, parse_header, parse_prefix,
    validate_account_count, validate_public_outputs, verify_vk_merkle_and_proof, JoinSplitHeader,
    STEALTH_DATA_PER_OUTPUT,
};
use crate::state::{CommitmentTree, QueuedLeaf, NullifierOperationType, PoolState};
use crate::utils::{
    create_pda_account,
    validate_account_writable, validate_active_tree_pda, validate_program_owner,
    validate_system_program,
};

pub fn process_transact(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let header = parse_header(data)?;
    validate_public_outputs(header, true)?;
    let JoinSplitHeader {
        n_inputs,
        n_outputs,
        flags,
        ..
    } = header;

    let min_accounts = 5 + n_inputs;
    validate_account_count(accounts.len(), min_accounts, flags & jsflags::PROOF_IN_BUFFER)?;
    let mut proof_buf = [0u8; crate::utils::groth16::GROTH16_PROOF_SIZE];
    let prefix = parse_prefix(data, accounts, header, n_outputs, &mut proof_buf)?;
    let mut nullifiers_buf = [0u8; crate::instructions::joinsplit_common::MAX_JOINSPLIT_SIZE * 32];
    let stealth_data_start = prefix.stealth_data_start;
    let stealth_data_end = prefix.stealth_data_end;

    // Sender memos are intentionally disabled until a circuit/protocol version
    // commits their hash. Accepting unbound trailing memos lets a relay strip
    // or replace the sender's outgoing-view data.
    if data.len() != stealth_data_end {
        return Err(ProgramError::InvalidInstructionData);
    }

    let pool_state_info = &accounts[0];
    let commitment_tree_info = &accounts[1];
    let vk_registry_info = &accounts[2];
    let user = &accounts[3];
    let system_program = &accounts[4];

    // Validate accounts
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_program_owner(vk_registry_info, program_id)?;
    validate_system_program(system_program)?;
    // Writability is demanded only where this instruction actually writes. A
    // queued spend touches neither shared account — the tree is read for
    // `is_valid_root` and pool_state for its policy flags — and requiring them
    // writable anyway would take both locks and destroy the parallelism the
    // queue exists for. Sealevel serialises on the declared metas, not on what
    // the program ends up doing.
    if header.has(jsflags::QUEUED_LEAVES) {
        if pool_state_info.is_writable() || commitment_tree_info.is_writable() {
            return Err(UTXOpiaError::InvalidPDA.into());
        }
    } else {
        validate_account_writable(pool_state_info)?;
        validate_account_writable(commitment_tree_info)?;
    }

    // Validate pool is not paused + tree PDA matches active index
    let (active_index, permissioned, policy_authority) = {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }
        if pool.permissioned() && pool.auditor_is_frozen() {
            return Err(UTXOpiaError::AuditorFrozen.into());
        }
        validate_active_tree_pda(
            commitment_tree_info,
            pool_state_info,
            program_id,
            pool.active_tree_index(),
        )?;

        // Bind the proof to the exact public/institution pool. A matching Merkle
        // root in another tree is insufficient because its domain field differs.
        let stealth_data_hash = crate::utils::sha256(&data[stealth_data_start..stealth_data_end]);
        let operation_hash = crate::utils::crypto::compute_bound_params_hash_private_transfer(
            crate::constants::CHAIN_ID,
            &stealth_data_hash,
        );
        let expected = crate::utils::crypto::bind_bound_params_to_domain(
            &operation_hash,
            crate::constants::CHAIN_ID,
            program_id,
            pool_state_info.address(),
            pool.permissioned(),
        )?;
        if *prefix.bound_params_hash != expected {
            return Err(UTXOpiaError::InvalidBoundParams.into());
        }

        (
            pool.active_tree_index(),
            pool.permissioned(),
            *pool.auditor(),
        )
    };

    // Explicit account layout. The flags byte says what is present; this walk
    // reads fixed slots in order and must land exactly on the end of the list.
    //
    //   [0..5] [5..5+N nullifiers] [relayer?] [frozen source tree?]
    //   [approval, policy_program if permissioned] [proof_buffer?]
    //
    // A flag only selects which slot to read — each one is still validated below
    // exactly as before, so a caller that mislabels an account breaks only its
    // own transaction. What this replaces is the previous reconstruction of the
    // same layout by counting backwards and asking whether an account "looks
    // like" a CommitmentTree, where adding any optional account perturbed the
    // arithmetic recovering the others.
    // transact has no ragequit: an internal transfer has no external destination
    // for the exit registry to bound, so a permissioned pool always needs the
    // approval pair. PolicyTail cross-checks the flag against pool state.
    let policy_tail = PolicyTail::from_flags(flags, permissioned, 0)?;
    if matches!(policy_tail, PolicyTail::Ragequit(_)) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let tail = resolve_joinsplit_tail(flags, min_accounts, policy_tail, n_outputs, accounts.len())?;
    // Deferred placement. The outputs become QueuedLeaf PDAs — accounts unique to
    // this transaction — instead of leaves written into the shared tree, so two
    // queued spends share no writable account and Sealevel can run them together.
    //
    // The caller must also pass commitment_tree as READONLY for that to hold: the
    // program stops writing it here, but a writable meta still takes the lock and
    // silently costs the parallelism this whole path exists for. The tree is still
    // needed, read-only, for `is_valid_root`.
    let queued = header.has(jsflags::QUEUED_LEAVES);
    let (relayer_at, source_tree_at) = (tail.relayer, tail.source_tree);
    let (approval_at, policy_program_at) = match tail.verified_pair() {
        Some((a, p)) => (Some(a), Some(p)),
        None => (None, None),
    };
    let approval_info = approval_at.map(|i| &accounts[i]);
    let policy_program_info = policy_program_at.map(|i| &accounts[i]);

    // Declared, still verified: it must be a program-owned CommitmentTree and
    // must not be the active one, or a caller could pass the active tree twice
    // and prove membership against a root it also just wrote.
    let source_tree_info = match source_tree_at.map(|i| &accounts[i]) {
        Some(a) => {
            if a.address() == commitment_tree_info.address()
                || !looks_like_commitment_tree(a, program_id)
            {
                return Err(UTXOpiaError::InvalidPDA.into());
            }
            Some(a)
        }
        None => None,
    };

    let payer = match relayer_at.map(|i| &accounts[i]) {
        Some(relayer) => {
            if !relayer.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            relayer
        }
        None => {
            if !user.is_signer() {
                return Err(ProgramError::MissingRequiredSignature);
            }
            user
        }
    };

    // Circulation inside a permissioned pool always needs the auditor: there is
    // no external destination here for a registry to bound, so `transact` has no
    // ragequit. Funds are still never trapped — the holder can unshield or
    // redeem out to a registered destination without any approval at all.
    crate::instructions::resolve_spend_path(
        permissioned,
        approval_info.is_some(),
        policy_program_info.is_some(),
        crate::instruction::TRANSACT,
    )?;
    if let (Some(approval), Some(policy_program)) = (approval_info, policy_program_info) {
        crate::instructions::consume_policy_approval(
            program_id,
            approval,
            policy_program,
            pool_state_info,
            user.address(),
            &policy_authority,
            crate::instruction::TRANSACT,
            // An internal transfer reveals no amount and no external
            // destination, so the only thing the auditor is deciding is whether
            // this participant may spend these particular notes at all — which
            // is exactly what the nullifiers name.
            &[crate::instructions::joinsplit_common::nullifiers_concat(
                &prefix,
                n_inputs,
                &mut nullifiers_buf,
            )],
        )?;
    }

    let source_tree_index = verify_vk_merkle_and_proof(
        program_id,
        pool_state_info,
        vk_registry_info,
        commitment_tree_info,
        active_index,
        source_tree_info,
        header,
        &prefix,
    )?;

    solana_program_log::log!("UTXOpia: transact");

    // Get rent for PDA creation
    let rent = Rent::get()?;
    create_nullifier_records(
        program_id,
        accounts,
        5,
        &prefix.nullifiers[..n_inputs],
        pool_state_info,
        source_tree_index,
        payer,
        &rent,
        NullifierOperationType::PrivateTransfer as u8,
        crate::instruction::TRANSACT,
        if queued { NullifierAccounting::DeferToQueue } else { NullifierAccounting::ApplyNow },
    )?;

    // Place the outputs: into the tree now, or into per-transaction PDAs that a
    // later `merge_queued_leaves` inserts as one batch.
    //
    // The announcement goes out either way, but a queued one carries
    // UNPLACED_LEAF_INDEX: the index does not exist yet. The recipient still
    // discovers the note immediately — only spending it waits for the merge.
    let first_leaf_index = if queued {
        let rent = Rent::get()?;
        let queued_start = tail
            .queued_leaves_start
            .ok_or(ProgramError::NotEnoughAccountKeys)?;
        for (i, commitment) in prefix.commitments_out.iter().take(n_outputs).enumerate() {
            let leaf_info = &accounts[queued_start + i];
            validate_account_writable(leaf_info)?;

            let (expected_pda, bump) = crate::pinocchio_compat::find_program_address(
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

            let stealth_offset = stealth_data_start + i * STEALTH_DATA_PER_OUTPUT;
            let ephemeral_pub: &[u8; 32] = data[stealth_offset..stealth_offset + 32]
                .try_into()
                .unwrap();
            let encrypted_amount: &[u8; 8] = data[stealth_offset + 32..stealth_offset + 40]
                .try_into()
                .unwrap();
            let encrypted_token_id: &[u8; 32] = data[stealth_offset + 40..stealth_offset + 72]
                .try_into()
                .unwrap();

            let bump_bytes = [bump];
            create_pda_account(
                payer,
                leaf_info,
                program_id,
                rent.try_minimum_balance(QueuedLeaf::LEN)?,
                QueuedLeaf::LEN as u64,
                &[
                    QueuedLeaf::SEED,
                    pool_state_info.address().as_ref(),
                    commitment.as_ref(),
                    &bump_bytes,
                ],
            )?;

            {
                let mut leaf_data = leaf_info.try_borrow_mut()?;
                QueuedLeaf::init(
                    &mut leaf_data,
                    bump,
                    active_index,
                    commitment,
                    payer.address().as_ref().try_into().unwrap(),
                    ephemeral_pub,
                    encrypted_amount,
                    encrypted_token_id,
                    // Exactly one leaf carries the whole spend's nullifier debt;
                    // splitting it across siblings would double-count on merge.
                    if i == 0 { n_inputs as u8 } else { 0 },
                )?;
            }

            crate::utils::events::emit_stealth_announcement(
                crate::utils::events::ANNOUNCEMENT_TYPE_TRANSFER,
                ephemeral_pub,
                encrypted_amount,
                *commitment,
                crate::utils::events::UNPLACED_LEAF_INDEX,
                encrypted_token_id,
            );
        }
        None
    } else {
        let mut tree_data = commitment_tree_info.try_borrow_mut()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;

        // One history slot for the whole batch, not one per output — see
        // `insert_leaves_batch` and _handoff/HANDOFF.md §12.
        // Defensive: an outputless spend inserts nothing, so it must not push a
        // root (or trip the empty-batch guard). `transact` forbids public
        // outputs, so n_outputs is normally >= 1.
        Some(if n_outputs > 0 {
            tree.insert_leaves_batch(&prefix.commitments_out[..n_outputs])?
        } else {
            tree.next_index()
        })
    };

    if let Some(first_leaf_index) = first_leaf_index {
        for (i, commitment) in prefix.commitments_out.iter().take(n_outputs).enumerate() {
            let leaf_index = first_leaf_index + i as u64;

            let stealth_offset = stealth_data_start + i * STEALTH_DATA_PER_OUTPUT;
            let ephemeral_pub: &[u8; 32] = data[stealth_offset..stealth_offset + 32]
                .try_into()
                .unwrap();
            let encrypted_amount: &[u8; 8] = data[stealth_offset + 32..stealth_offset + 40]
                .try_into()
                .unwrap();
            let encrypted_token_id: &[u8; 32] = data[stealth_offset + 40..stealth_offset + 72]
                .try_into()
                .unwrap();

            crate::utils::events::emit_stealth_announcement(
                crate::utils::events::ANNOUNCEMENT_TYPE_TRANSFER,
                ephemeral_pub,
                encrypted_amount,
                *commitment,
                leaf_index as u32,
                encrypted_token_id,
            );
        }
    }

    Ok(())
}
