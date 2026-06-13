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
    pubkey::{find_program_address, Pubkey},
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{
    CommitmentTree, NullifierOperationType, NullifierRecord, PoolState, VkRegistry,
    NULLIFIER_RECORD_DISCRIMINATOR,
};
use crate::utils::groth16::GROTH16_PROOF_SIZE;
use crate::utils::{
    create_pda_account, validate_account_writable, validate_active_tree_pda,
    validate_program_owner, validate_system_program,
};

/// Maximum supported N + M (reduced from 14 to fit Solana tx limit)
const MAX_JOINSPLIT_SIZE: usize = crate::constants::MAX_SAFE_JOINSPLIT_SIZE;

/// Stealth data per output: ephemeral_pub (32) + encrypted_amount (8) + encrypted_token_id (32)
const STEALTH_DATA_PER_OUTPUT: usize = 72;

/// Sender-memo data per output (optional trailing section): nonce (24) + ciphertext_and_tag (56).
/// The contract fills in `commitment` and `leaf_index` (from public inputs + tree insertion)
/// when emitting the on-chain event, so the user can't lie about either.
const SENDER_MEMO_DATA_PER_OUTPUT: usize = 80;

/// Authority prefix size in ChadBuffer accounts
const CHADBUFFER_AUTHORITY_SIZE: usize = 32;

pub fn process_transact(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Parse header: n_inputs(1) + n_outputs(1) + n_public_outputs(1) + proof_source(1)
    if data.len() < 4 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let n_inputs = data[0] as usize;
    let n_outputs = data[1] as usize;
    let n_public_outputs = data[2] as usize;
    let proof_source = data[3]; // 0 = inline, 1 = buffer account
    if proof_source > 1 {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Transact requires n_public_outputs == 0 (all outputs go to tree)
    if n_public_outputs != 0 {
        return Err(ProgramError::InvalidInstructionData);
    }

    if n_inputs == 0 || n_outputs == 0 || n_inputs + n_outputs > MAX_JOINSPLIT_SIZE {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Calculate expected data length
    let proof_data_size = if proof_source == 0 {
        GROTH16_PROOF_SIZE
    } else {
        0
    };
    let header_size = 4 + proof_data_size + 32 + 32;
    let nullifiers_size = n_inputs * 32;
    let commitments_size = n_outputs * 32;
    let stealth_size = n_outputs * STEALTH_DATA_PER_OUTPUT;
    let expected_len = header_size + nullifiers_size + commitments_size + stealth_size;

    if data.len() < expected_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Validate account count before any optional proof-buffer access. Otherwise a
    // malformed buffered-proof call with too few accounts can make the last
    // required account look like the proof buffer, or underflow on an empty list.
    let min_accounts = 5 + n_inputs;
    let required_accounts = min_accounts + usize::from(proof_source == 1);
    if accounts.len() < required_accounts {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // Parse instruction data (skip 4-byte header)
    let mut offset = 4;

    // Read proof: inline or from buffer account
    let proof_buf: [u8; GROTH16_PROOF_SIZE];
    let proof_bytes: &[u8] = if proof_source == 0 {
        let p = &data[offset..offset + GROTH16_PROOF_SIZE];
        offset += GROTH16_PROOF_SIZE;
        p
    } else {
        // proof_source == 1: read from last account (proof_buffer)
        let buf_idx = accounts.len() - 1;
        let buf_info = &accounts[buf_idx];
        // Validate buffer is owned by ChadBuffer program
        crate::utils::chadbuffer::validate_chadbuffer_owner(buf_info)?;
        let buf_data = buf_info.try_borrow_data()?;
        if buf_data.len() < CHADBUFFER_AUTHORITY_SIZE + GROTH16_PROOF_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        let src =
            &buf_data[CHADBUFFER_AUTHORITY_SIZE..CHADBUFFER_AUTHORITY_SIZE + GROTH16_PROOF_SIZE];
        proof_buf = src.try_into().unwrap();
        &proof_buf
    };

    let merkle_root: &[u8; 32] = data[offset..offset + 32].try_into().unwrap();
    offset += 32;

    let bound_params_hash: &[u8; 32] = data[offset..offset + 32].try_into().unwrap();
    offset += 32;

    // Parse nullifiers (stack-allocated, no heap)
    const ZERO_REF: &[u8; 32] = &[0u8; 32];
    let mut nullifiers: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];
    for nullifier in nullifiers.iter_mut().take(n_inputs) {
        *nullifier = data[offset..offset + 32].try_into().unwrap();
        offset += 32;
    }

    // Parse output commitments (stack-allocated, no heap)
    let mut commitments_out: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];
    for commitment in commitments_out.iter_mut().take(n_outputs) {
        *commitment = data[offset..offset + 32].try_into().unwrap();
        offset += 32;
    }

    // Parse stealth data
    let stealth_data_start = offset;
    let stealth_data_len = n_outputs * STEALTH_DATA_PER_OUTPUT;
    let stealth_data_end = stealth_data_start + stealth_data_len;

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
        if *bound_params_hash != expected {
            return Err(UTXOpiaError::InvalidBoundParams.into());
        }
    }

    let pool_state_info = &accounts[0];
    let commitment_tree_info = &accounts[1];
    let vk_registry_info = &accounts[2];
    let user = &accounts[3];
    let system_program = &accounts[4];

    // Check for optional relayer account (after nullifiers, before optional proof_buffer)
    // Account layout: [5..5+N nullifiers] [optional relayer] [optional proof_buffer]
    let extra_accounts_after_nullifiers = accounts.len() - (5 + n_inputs);
    let has_proof_buffer = proof_source == 1;
    let has_relayer = if has_proof_buffer {
        extra_accounts_after_nullifiers > 1
    } else {
        extra_accounts_after_nullifiers > 0
    };
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

    // Validate accounts
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_program_owner(vk_registry_info, program_id)?;
    validate_system_program(system_program)?;
    validate_account_writable(pool_state_info)?;
    validate_account_writable(commitment_tree_info)?;

    // Validate pool is not paused + tree PDA matches active index
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }
        validate_active_tree_pda(commitment_tree_info, program_id, pool.active_tree_index())?;
    }

    // Validate VK registry for this (N, M) variant
    {
        let vk_data = vk_registry_info.try_borrow_data()?;
        let vk = VkRegistry::from_bytes(&vk_data)?;

        if vk.n_inputs != n_inputs as u8 || vk.n_outputs != n_outputs as u8 {
            return Err(UTXOpiaError::InvalidVkRegistry.into());
        }
    }

    // Validate Merkle root
    {
        let tree_data = commitment_tree_info.try_borrow_data()?;
        let tree = CommitmentTree::from_bytes(&tree_data)?;
        if !tree.is_valid_root(merkle_root) {
            return Err(UTXOpiaError::InvalidMerkleProof.into());
        }
    }

    // Build public inputs array for verification (stack-allocated)
    // Max public inputs: root + boundParams + nullifiers + commitments.
    const MAX_PUBLIC_INPUTS: usize = 2 + MAX_JOINSPLIT_SIZE;
    let mut public_inputs: [&[u8; 32]; MAX_PUBLIC_INPUTS] = [ZERO_REF; MAX_PUBLIC_INPUTS];
    let mut pi_len = 0;
    public_inputs[pi_len] = merkle_root;
    pi_len += 1;
    public_inputs[pi_len] = bound_params_hash;
    pi_len += 1;
    for nullifier in nullifiers.iter().take(n_inputs) {
        public_inputs[pi_len] = *nullifier;
        pi_len += 1;
    }
    for commitment in commitments_out.iter().take(n_outputs) {
        public_inputs[pi_len] = *commitment;
        pi_len += 1;
    }

    // Load VK and verify Groth16 proof
    let (delta_g2, ic) = crate::utils::groth16::load_joinsplit_vk(n_inputs as u8, n_outputs as u8)?;

    crate::utils::groth16::verify_groth16_joinsplit_proof(
        proof_bytes,
        &public_inputs[..pi_len],
        delta_g2,
        ic,
    )?;

    pinocchio::msg!("UTXOpia: transact");

    // Get rent for PDA creation
    let rent = Rent::get()?;

    // Process nullifiers: validate PDAs, check uniqueness, create accounts
    // Collect hashes for batched event emission
    const ZERO_HASH: &[u8; 32] = &[0u8; 32];
    let mut null_hashes: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_HASH; MAX_JOINSPLIT_SIZE];

    for (i, nullifier) in nullifiers.iter().take(n_inputs).enumerate() {
        let nullifier_info = &accounts[5 + i];
        validate_account_writable(nullifier_info)?;

        // Derive and validate nullifier PDA
        let nullifier_seeds: &[&[u8]] = &[NullifierRecord::SEED, nullifier.as_ref()];
        let (expected_pda, bump) = find_program_address(nullifier_seeds, program_id);
        if nullifier_info.key() != &expected_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        // Check if nullifier already spent (account exists and initialized)
        {
            let nullifier_data = nullifier_info.try_borrow_data()?;
            if !nullifier_data.is_empty() && nullifier_data[0] == NULLIFIER_RECORD_DISCRIMINATOR {
                return Err(UTXOpiaError::NullifierAlreadyUsed.into());
            }
        }

        // Create nullifier PDA account
        let bump_bytes = [bump];
        let signer_seeds: &[&[u8]] = &[NullifierRecord::SEED, nullifier.as_ref(), &bump_bytes];

        create_pda_account(
            payer,
            nullifier_info,
            program_id,
            rent.minimum_balance(NullifierRecord::LEN),
            NullifierRecord::LEN as u64,
            signer_seeds,
        )?;

        // Initialize nullifier record (slim: discriminator only)
        {
            let mut nullifier_data = nullifier_info.try_borrow_mut_data()?;
            NullifierRecord::init(&mut nullifier_data)?;
        }

        null_hashes[i] = *nullifier;
    }

    // Emit nullifiers batch (single sol_log_data call)
    crate::utils::events::emit_nullifiers_batch(
        &null_hashes[..n_inputs],
        NullifierOperationType::PrivateTransfer as u8,
        crate::instruction::TRANSACT,
    );

    // Insert output commitments into Merkle tree and emit stealth announcements
    {
        let mut tree_data = commitment_tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;

        for (i, commitment) in commitments_out.iter().take(n_outputs).enumerate() {
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
                commitments_out[i],
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
                    commitments_out[i],
                    leaf_index as u32,
                );
            }
        }
    }

    Ok(())
}
