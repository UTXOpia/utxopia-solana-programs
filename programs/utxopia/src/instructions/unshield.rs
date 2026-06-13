//! Multi-output Unshield instruction (disc=14)
//!
//! Unshield SPL tokens from the privacy pool. User provides JoinSplit ZK proof;
//! the last `n_public_outputs` outputs are burn commitments Poseidon(0, token_id, amount_k).
//! Revealed amounts minus fees are transferred from token vault to recipients.
//!
//! Instruction Data Layout (4-byte common header):
//! - [0]     n_inputs:           u8
//! - [1]     n_outputs:          u8
//! - [2]     n_public_outputs:   u8  (1..3)
//! - [3]     proof_source:       u8  (0=inline, 1=buffer account)
//! - If proof_source=0:
//!   - [4..260]  proof:          [u8; 256]  (Groth16 proof)
//! - If proof_source=1:
//!   - proof is read from the proof_buffer account (last account)
//! - [..]     merkle_root:       [u8; 32]
//! - [..]     bound_params_hash: [u8; 32]
//! - [..]     nullifiers:        [[u8; 32]; n_inputs]
//! - [..]     commitments_out:   [[u8; 32]; n_outputs]
//! - [..]     stealth_data:      [ephemeral_pub(32) + encrypted_amount(8) + encrypted_token_id(32)] × n_tree_outputs
//! - [..]     amounts:           [u64 LE; n_public_outputs]  (per-output unshield amounts)
//!
//! Accounts:
//! 0. pool_state           (read)
//! 1. commitment_tree      (writable)
//! 2. vk_registry          (read)
//! 3. user                 (signer, payer)
//! 4. system_program       (read)
//! 5. token_config         (writable)
//! 6. vault                (writable) — token-specific vault
//! 7. token_program        (read)
//!    8..8+P                  recipient_token_accounts (writable, one per public output)
//!    8+P..8+P+N             nullifier_records (writable, PDA)
//!    [optional]              proof_buffer (read, only when proof_source=1, last account)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{
    CommitmentTree, NullifierOperationType, NullifierRecord, PoolState, TokenConfig, VkRegistry,
    NULLIFIER_RECORD_DISCRIMINATOR,
};
use crate::utils::groth16::GROTH16_PROOF_SIZE;
use crate::utils::token::transfer_zkbtc;
use crate::utils::{
    create_pda_account, validate_account_writable, validate_active_tree_pda,
    validate_any_token_program_key, validate_program_owner, validate_system_program,
    validate_token_owner,
};

/// Maximum supported N + M
const MAX_JOINSPLIT_SIZE: usize = crate::constants::MAX_SAFE_JOINSPLIT_SIZE;

/// Stealth data per output: ephemeral_pub (32) + encrypted_amount (8) + encrypted_token_id (32)
const STEALTH_DATA_PER_OUTPUT: usize = 72;

/// Maximum number of public outputs per unshield
const MAX_PUBLIC_OUTPUTS: usize = 3;

/// Number of fixed accounts before recipient token accounts
/// pool_state(0), commitment_tree(1), vk_registry(2), user(3), system_program(4),
/// token_config(5), vault(6), token_program(7)
const FIXED_ACCOUNTS: usize = 8;

/// Authority prefix size in ChadBuffer accounts
const CHADBUFFER_AUTHORITY_SIZE: usize = 32;

pub fn process_unshield(
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

    if n_inputs == 0 || n_outputs == 0 || n_inputs + n_outputs > MAX_JOINSPLIT_SIZE {
        return Err(ProgramError::InvalidInstructionData);
    }
    if n_public_outputs == 0
        || n_public_outputs > MAX_PUBLIC_OUTPUTS
        || n_public_outputs > n_outputs
    {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Tree outputs = n_outputs - n_public_outputs
    let n_tree_outputs = n_outputs - n_public_outputs;

    // Calculate expected data length
    let proof_data_size = if proof_source == 0 {
        GROTH16_PROOF_SIZE
    } else {
        0
    };
    let header_size = 4 + proof_data_size + 32 + 32;
    let nullifiers_size = n_inputs * 32;
    let commitments_size = n_outputs * 32;
    let stealth_size = n_tree_outputs * STEALTH_DATA_PER_OUTPUT;
    let amounts_size = n_public_outputs * 8; // u64 LE per public output
    let expected_len =
        header_size + nullifiers_size + commitments_size + stealth_size + amounts_size;

    if data.len() < expected_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Validate account count before any optional proof-buffer access. Buffered
    // proofs require one account beyond the fixed, recipient, and nullifier set.
    let min_accounts = FIXED_ACCOUNTS + n_public_outputs + n_inputs;
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

    // Parse nullifiers
    const ZERO_REF: &[u8; 32] = &[0u8; 32];
    let mut nullifiers: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];
    for nullifier in nullifiers.iter_mut().take(n_inputs) {
        *nullifier = data[offset..offset + 32].try_into().unwrap();
        offset += 32;
    }

    // Parse output commitments (all n_outputs)
    let mut commitments_out: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];
    for commitment in commitments_out.iter_mut().take(n_outputs) {
        *commitment = data[offset..offset + 32].try_into().unwrap();
        offset += 32;
    }

    // Parse stealth data for tree outputs only
    let stealth_data_start = offset;
    let stealth_data_len = n_tree_outputs * STEALTH_DATA_PER_OUTPUT;
    let stealth_data_end = stealth_data_start + stealth_data_len;
    offset += stealth_data_len;

    // Parse per-output unshield amounts
    let mut unshield_amounts: [u64; MAX_PUBLIC_OUTPUTS] = [0u64; MAX_PUBLIC_OUTPUTS];
    for amount in unshield_amounts.iter_mut().take(n_public_outputs) {
        *amount = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
        offset += 8;
    }
    if offset != data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let pool_state_info = &accounts[0];
    let commitment_tree_info = &accounts[1];
    let vk_registry_info = &accounts[2];
    let user = &accounts[3];
    let system_program = &accounts[4];
    let token_config_info = &accounts[5];
    let vault = &accounts[6];
    let token_program = &accounts[7];

    // Validate core accounts
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_program_owner(vk_registry_info, program_id)?;
    validate_program_owner(token_config_info, program_id)?;
    validate_system_program(system_program)?;
    validate_token_owner(vault)?;
    validate_any_token_program_key(token_program)?;
    validate_account_writable(commitment_tree_info)?;
    validate_account_writable(token_config_info)?;
    validate_account_writable(vault)?;

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate recipient token accounts
    for k in 0..n_public_outputs {
        let recipient = &accounts[FIXED_ACCOUNTS + k];
        validate_token_owner(recipient)?;
        validate_account_writable(recipient)?;
    }

    // Verify bound params hash — binds recipient addresses + stealth data to proof.
    // destinations_hash = SHA256(owner_1 || owner_2 || ...)
    {
        let mut owners_concat = [0u8; MAX_PUBLIC_OUTPUTS * 32]; // stack-allocated
        for k in 0..n_public_outputs {
            let recipient = &accounts[FIXED_ACCOUNTS + k];
            let uta_data = recipient.try_borrow_data()?;
            if uta_data.len() < 64 {
                return Err(ProgramError::InvalidAccountData);
            }
            owners_concat[k * 32..(k + 1) * 32].copy_from_slice(&uta_data[32..64]);
        }
        let stealth_data_hash = crate::utils::sha256(&data[stealth_data_start..stealth_data_end]);
        let expected = crate::utils::crypto::compute_bound_params_hash_unshield(
            crate::constants::CHAIN_ID,
            &owners_concat[..n_public_outputs * 32],
            &stealth_data_hash,
        );
        if *bound_params_hash != expected {
            return Err(UTXOpiaError::InvalidBoundParams.into());
        }
    }

    // Read pool state — check paused, validate active tree, get withdrawal_fee_bps
    let withdrawal_fee_bps = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }
        validate_active_tree_pda(commitment_tree_info, program_id, pool.active_tree_index())?;
        pool.withdrawal_fee_bps()
    };

    // Read token config — get token_id, validate vault
    let token_id = {
        let tc_data = token_config_info.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;

        if !tc.is_enabled() {
            return Err(UTXOpiaError::TokenDisabled.into());
        }

        // Validate vault matches
        if vault.key().as_ref() != tc.vault {
            return Err(UTXOpiaError::InvalidVault.into());
        }

        tc.token_id
    };

    // Derive pool PDA for signing vault transfer
    let pool_seeds: &[&[u8]] = &[PoolState::SEED];
    let (expected_pool_pda, pool_bump) = find_program_address(pool_seeds, program_id);
    if pool_state_info.key() != &expected_pool_pda {
        return Err(ProgramError::InvalidSeeds);
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

    // Build public inputs
    const MAX_PI: usize = 2 + MAX_JOINSPLIT_SIZE;
    let mut public_inputs: [&[u8; 32]; MAX_PI] = [ZERO_REF; MAX_PI];
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

    // Verify burn commitments: last n_public_outputs = Poseidon(0, token_id, amount_k)
    {
        let zero_npk = [0u8; 32];
        for (k, amount) in unshield_amounts.iter().take(n_public_outputs).enumerate() {
            let idx = n_tree_outputs + k; // public outputs are at the end
            let expected_commitment =
                crate::utils::crypto::compute_commitment(&zero_npk, &token_id, *amount)?;
            if *commitments_out[idx] != expected_commitment {
                return Err(UTXOpiaError::InvalidCommitment.into());
            }
        }
    }

    // Get clock and rent for PDA creation
    let clock = Clock::get()?;
    let rent = Rent::get()?;

    // Process nullifiers
    let nullifier_base = FIXED_ACCOUNTS + n_public_outputs;
    for (i, nullifier) in nullifiers.iter().take(n_inputs).enumerate() {
        let nullifier_info = &accounts[nullifier_base + i];
        validate_account_writable(nullifier_info)?;

        let nullifier_seeds: &[&[u8]] = &[NullifierRecord::SEED, nullifier.as_ref()];
        let (expected_pda, nbump) = find_program_address(nullifier_seeds, program_id);
        if nullifier_info.key() != &expected_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        {
            let nullifier_data = nullifier_info.try_borrow_data()?;
            if !nullifier_data.is_empty() && nullifier_data[0] == NULLIFIER_RECORD_DISCRIMINATOR {
                return Err(UTXOpiaError::NullifierAlreadyUsed.into());
            }
        }

        let bump_bytes = [nbump];
        let signer_seeds: &[&[u8]] = &[NullifierRecord::SEED, nullifier.as_ref(), &bump_bytes];

        create_pda_account(
            user,
            nullifier_info,
            program_id,
            rent.minimum_balance(NullifierRecord::LEN),
            NullifierRecord::LEN as u64,
            signer_seeds,
        )?;

        {
            let mut nullifier_data = nullifier_info.try_borrow_mut_data()?;
            NullifierRecord::init(&mut nullifier_data)?;
        }
    }

    // Emit nullifiers batch
    crate::utils::events::emit_nullifiers_batch(
        &nullifiers[..n_inputs],
        NullifierOperationType::FullWithdrawal as u8,
        crate::instruction::UNSHIELD,
    );

    // Insert tree outputs into Merkle tree
    {
        let mut tree_data = commitment_tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;

        for (i, commitment) in commitments_out.iter().take(n_tree_outputs).enumerate() {
            let leaf_index = tree.insert_leaf(commitment)?;

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
                commitments_out[i],
                leaf_index as u32,
                encrypted_token_id,
            );
        }
    }

    // Compute total amount, fees, and transfer payouts
    let mut total_amount: u64 = 0;
    let mut total_protocol_fee: u64 = 0;

    let pool_bump_bytes = [pool_bump];
    let pool_signer_seeds: &[&[u8]] = &[PoolState::SEED, &pool_bump_bytes];

    for k in 0..n_public_outputs {
        let amount = unshield_amounts[k];
        let protocol_fee = (amount as u128 * withdrawal_fee_bps as u128 / 10_000) as u64;
        let payout = amount
            .checked_sub(protocol_fee)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        total_amount = total_amount
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        total_protocol_fee = total_protocol_fee
            .checked_add(protocol_fee)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        let recipient = &accounts[FIXED_ACCOUNTS + k];

        // Emit unshield metadata per output
        crate::utils::events::emit_unshield_meta(
            amount,
            protocol_fee,
            payout,
            user.key().as_ref().try_into().unwrap(),
            &token_id,
        );

        // Transfer payout from vault to recipient (signed by pool PDA)
        transfer_zkbtc(
            token_program,
            vault,
            recipient,
            pool_state_info,
            payout,
            pool_signer_seeds,
        )?;
    }

    // Update token config: decrement total_shielded by sum, add total fees
    {
        let mut tc_data = token_config_info.try_borrow_mut_data()?;
        let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;
        tc.sub_shielded(total_amount)?;
        tc.add_fees(total_protocol_fee)?;
    }

    let _ = clock; // suppress unused warning

    pinocchio::msg!("UTXOpia: unshield");
    Ok(())
}
