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
//! - [..]     sender_memos (OPTIONAL): [nonce(24) + ciphertext_and_tag(56)] × n_outputs
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

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::instructions::joinsplit_common::{
    create_nullifier_records, looks_like_commitment_tree, parse_header, parse_prefix,
    validate_account_count, validate_public_outputs, verify_vk_merkle_and_proof, JoinSplitHeader,
    STEALTH_DATA_PER_OUTPUT,
};
use crate::state::{CommitmentTree, NullifierOperationType, PoolState};
use crate::utils::{
    validate_account_writable, validate_active_tree_pda, validate_program_owner,
    validate_system_program,
};

/// Sender-memo data per output (optional trailing section): nonce (24) + ciphertext_and_tag (56).
/// The contract fills in `commitment` and `leaf_index` (from public inputs + tree insertion)
/// when emitting the on-chain event, so the user can't lie about either.
const SENDER_MEMO_DATA_PER_OUTPUT: usize = 80;

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
        proof_source,
        ..
    } = header;

    let min_accounts = 5 + n_inputs;
    validate_account_count(accounts.len(), min_accounts, proof_source)?;
    let mut proof_buf = [0u8; crate::utils::groth16::GROTH16_PROOF_SIZE];
    let prefix = parse_prefix(data, accounts, header, n_outputs, &mut proof_buf)?;
    let stealth_data_start = prefix.stealth_data_start;
    let stealth_data_end = prefix.stealth_data_end;

    // Detect optional sender-memo section by exact data length match.
    // Older clients send no memo bytes (data ends at stealth_data_end); newer
    // clients append exactly n_outputs * SENDER_MEMO_DATA_PER_OUTPUT bytes.
    // Anything else trailing is rejected; future extensions should be versioned.
    let sender_memos_len = n_outputs * SENDER_MEMO_DATA_PER_OUTPUT;
    if data.len() != stealth_data_end && data.len() != stealth_data_end + sender_memos_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    let has_sender_memos = data.len() == stealth_data_end + sender_memos_len;
    let sender_memos_start = stealth_data_end;

    // Verify bound params hash — includes stealth data hash to prevent relayer tampering
    {
        let stealth_data_hash = crate::utils::sha256(&data[stealth_data_start..stealth_data_end]);
        let expected = crate::utils::crypto::compute_bound_params_hash_private_transfer(
            crate::constants::CHAIN_ID,
            &stealth_data_hash,
        );
        if *prefix.bound_params_hash != expected {
            return Err(UTXOpiaError::InvalidBoundParams.into());
        }
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
    validate_account_writable(pool_state_info)?;
    validate_account_writable(commitment_tree_info)?;

    // Validate pool is not paused + tree PDA matches active index
    let active_index = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }
        validate_active_tree_pda(commitment_tree_info, program_id, pool.active_tree_index())?;
        pool.active_tree_index()
    };

    // Optional account layout after nullifiers:
    //   [5..5+N nullifiers] [optional relayer] [optional frozen source tree] [optional proof_buffer]
    // The frozen source tree (a previous, rotated-out CommitmentTree) lets notes committed before a
    // tree rotation still be spent — its root proves membership while new outputs go to the active
    // tree. It is identified by being a program-owned CommitmentTree, so it is unambiguous against a
    // relayer (signer) or proof_buffer (ChadBuffer-owned).
    let has_proof_buffer = proof_source == 1;
    let pb = usize::from(has_proof_buffer);
    let source_tree_info = accounts
        .len()
        .checked_sub(1 + pb)
        .filter(|&i| i >= 5 + n_inputs)
        .map(|i| &accounts[i])
        .filter(|a| a.key() != commitment_tree_info.key() && looks_like_commitment_tree(a, program_id));
    let frozen = usize::from(source_tree_info.is_some());

    let extra_accounts_after_nullifiers = accounts.len() - (5 + n_inputs);
    let has_relayer = extra_accounts_after_nullifiers > frozen + pb;
    let payer = if has_relayer {
        let relayer = &accounts[5 + n_inputs];
        if !relayer.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        relayer
    } else {
        if !user.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        user
    };

    verify_vk_merkle_and_proof(
        program_id,
        vk_registry_info,
        commitment_tree_info,
        active_index,
        source_tree_info,
        header,
        &prefix,
    )?;

    pinocchio::msg!("UTXOpia: transact");

    // Get rent for PDA creation
    let rent = Rent::get()?;
    create_nullifier_records(
        program_id,
        accounts,
        5,
        &prefix.nullifiers[..n_inputs],
        payer,
        &rent,
        NullifierOperationType::PrivateTransfer as u8,
        crate::instruction::TRANSACT,
    )?;

    // Insert output commitments into Merkle tree and emit stealth announcements
    {
        let mut tree_data = commitment_tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;

        for (i, commitment) in prefix.commitments_out.iter().take(n_outputs).enumerate() {
            let leaf_index = tree.insert_leaf(commitment)?;

            // Parse stealth data for this output
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

            // Emit stealth announcement — token_id is encrypted (only recipient can decrypt)
            crate::utils::events::emit_stealth_announcement(
                crate::utils::events::ANNOUNCEMENT_TYPE_TRANSFER,
                ephemeral_pub,
                encrypted_amount,
                prefix.commitments_out[i],
                leaf_index as u32,
                encrypted_token_id,
            );

            // Optionally emit sender memo (Phase 2): user's own outgoing-view
            // copy of the output. AEAD-encrypted under `ovk`, bound to this
            // leaf via commitment + leaf_index AAD.
            if has_sender_memos {
                let memo_offset = sender_memos_start + i * SENDER_MEMO_DATA_PER_OUTPUT;
                let memo_nonce: &[u8; 24] = data[memo_offset..memo_offset + 24].try_into().unwrap();
                let memo_ct_and_tag: &[u8; 56] =
                    data[memo_offset + 24..memo_offset + 80].try_into().unwrap();
                crate::utils::events::emit_sender_memo(
                    memo_nonce,
                    memo_ct_and_tag,
                    prefix.commitments_out[i],
                    leaf_index as u32,
                );
            }
        }
    }

    Ok(())
}
