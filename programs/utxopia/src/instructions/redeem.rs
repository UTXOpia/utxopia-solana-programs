//! Multi-output Redeem instruction (disc=15)
//!
//! JoinSplit N→M where the last `n_public_outputs` outputs create RedemptionRequest PDAs
//! for BTC withdrawal — atomic private transfer + BTC redemption in one tx.
//!
//! The last n_public_outputs commitments are verified in the ZK proof but NOT inserted
//! into the Merkle tree. Instead, RedemptionRequest PDAs are created for each.
//! Remaining tree outputs go into the tree as normal (change notes).
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
//! - For each public output:
//!   - amount:       u64 (8 bytes LE)
//!   - script_len:   u8
//!   - script:       [u8; script_len] (variable, max 62)
//!   - nonce:        u64 (8 bytes LE)
//!
//! Accounts:
//! 0. pool_state           (writable)
//! 1. commitment_tree      (writable)
//! 2. vk_registry          (read)
//! 3. user                 (signer, payer)
//! 4. system_program       (read)
//! 5. token_config         (read) — for token_id + enabled check
//!    6..6+N                  nullifier_records (writable PDA)
//!    6+N..6+N+P             redemption_request PDAs (writable)
//!    [optional]              proof_buffer (read, only when proof_source=1, last account)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::instructions::joinsplit_common::{
    create_nullifier_records, looks_like_commitment_tree, parse_header, parse_prefix, read_u64_le,
    take_bytes, validate_account_count, validate_public_outputs, verify_vk_merkle_and_proof,
    JoinSplitHeader, MAX_PUBLIC_OUTPUTS, STEALTH_DATA_PER_OUTPUT,
};
use crate::state::{
    CommitmentTree, NullifierOperationType, PoolState, RedemptionRequest, RedemptionStatus,
    TokenConfig, REDEMPTION_REQUEST_DISCRIMINATOR,
};
use crate::utils::{
    create_pda_account, validate_account_writable, validate_active_tree_pda,
    validate_program_owner, validate_system_program,
};

/// Number of fixed accounts before nullifiers (pool_state, tree, vk, user, system, token_config)
const FIXED_ACCOUNTS: usize = 6;

pub fn process_redeem(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    let header = parse_header(data)?;
    validate_public_outputs(header, false)?;
    let JoinSplitHeader {
        n_inputs,
        n_outputs,
        n_public_outputs,
        proof_source,
    } = header;

    // Tree outputs = n_outputs - n_public_outputs
    let n_tree_outputs = n_outputs - n_public_outputs;

    let min_accounts = FIXED_ACCOUNTS + n_inputs + n_public_outputs;
    validate_account_count(accounts.len(), min_accounts, proof_source)?;
    let mut proof_buf = [0u8; crate::utils::groth16::GROTH16_PROOF_SIZE];
    let prefix = parse_prefix(data, accounts, header, n_tree_outputs, &mut proof_buf)?;
    let stealth_data_start = prefix.stealth_data_start;
    let stealth_data_end = prefix.stealth_data_end;
    let mut offset = stealth_data_end;

    // Parse per-output redeem data (amount + script + nonce)
    let mut redeem_amounts: [u64; MAX_PUBLIC_OUTPUTS] = [0u64; MAX_PUBLIC_OUTPUTS];
    let mut btc_script_starts: [usize; MAX_PUBLIC_OUTPUTS] = [0; MAX_PUBLIC_OUTPUTS];
    let mut btc_script_lens: [usize; MAX_PUBLIC_OUTPUTS] = [0; MAX_PUBLIC_OUTPUTS];
    let mut request_nonces: [u64; MAX_PUBLIC_OUTPUTS] = [0u64; MAX_PUBLIC_OUTPUTS];

    for k in 0..n_public_outputs {
        // Amount
        redeem_amounts[k] = read_u64_le(data, &mut offset)?;

        // BTC script (variable length)
        let script_len = take_bytes(data, &mut offset, 1)?[0] as usize;

        if script_len == 0 || script_len > crate::constants::MAX_BTC_SCRIPT_LEN {
            return Err(UTXOpiaError::InvalidBtcAddress.into());
        }

        btc_script_starts[k] = offset;
        btc_script_lens[k] = script_len;
        take_bytes(data, &mut offset, script_len)?;

        // Request nonce
        request_nonces[k] = read_u64_le(data, &mut offset)?;
    }
    if offset != data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Verify bound params hash — binds BTC scripts + stealth data to proof.
    // destinations_hash = SHA256(script_1 || script_2 || ...)
    {
        // Concatenate all scripts for hashing
        let scripts_total_len: usize = btc_script_lens.iter().take(n_public_outputs).sum();
        // Use a stack buffer for concatenated scripts (max 3 * 62 = 186 bytes)
        let mut scripts_concat = [0u8; MAX_PUBLIC_OUTPUTS * 62];
        let mut soff = 0usize;
        for k in 0..n_public_outputs {
            let s = &data[btc_script_starts[k]..btc_script_starts[k] + btc_script_lens[k]];
            scripts_concat[soff..soff + btc_script_lens[k]].copy_from_slice(s);
            soff += btc_script_lens[k];
        }

        let stealth_data_hash = crate::utils::sha256(&data[stealth_data_start..stealth_data_end]);
        // Bind the proof to the requesting signer (accounts[3]) so it cannot be replayed under a
        // different signer to hijack ownership of the resulting RedemptionRequest PDAs.
        let expected = crate::utils::crypto::compute_bound_params_hash_redeem(
            crate::constants::CHAIN_ID,
            &scripts_concat[..scripts_total_len],
            &stealth_data_hash,
            accounts[3].key(),
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
    let token_config_info = &accounts[5];

    // Validate core accounts
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_program_owner(vk_registry_info, program_id)?;
    validate_program_owner(token_config_info, program_id)?;
    validate_system_program(system_program)?;
    validate_account_writable(pool_state_info)?;
    validate_account_writable(commitment_tree_info)?;

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Read token_id; re-derive the ["token_config", mint] PDA so a caller can't
    // pass an arbitrary program-owned config (makes the recorded token_id trustworthy).
    let token_id = {
        let tc_data = token_config_info.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;
        if !tc.is_enabled() {
            return Err(UTXOpiaError::TokenDisabled.into());
        }
        let (expected_tc_pda, _) = find_program_address(&[TokenConfig::SEED, &tc.mint], program_id);
        if token_config_info.key() != &expected_tc_pda {
            return Err(ProgramError::InvalidSeeds);
        }
        tc.token_id
    };

    // Validate pool is not paused, validate active tree, read state
    let (pending_redemptions, total_shielded, active_index) = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }
        validate_active_tree_pda(commitment_tree_info, program_id, pool.active_tree_index())?;
        (
            pool.pending_redemptions(),
            pool.total_shielded(),
            pool.active_tree_index(),
        )
    };

    // Optional frozen source tree for spending notes committed before a tree rotation; appended
    // just before the optional proof_buffer and identified by being a program-owned CommitmentTree.
    let pb = usize::from(proof_source == 1);
    let source_tree_info = accounts
        .len()
        .checked_sub(1 + pb)
        .filter(|&i| i >= min_accounts)
        .map(|i| &accounts[i])
        .filter(|a| {
            a.key() != commitment_tree_info.key() && looks_like_commitment_tree(a, program_id)
        });

    // Validate total redeem amount
    let mut total_redeem: u64 = 0;
    for amount in redeem_amounts.iter().take(n_public_outputs) {
        if *amount == 0 {
            return Err(UTXOpiaError::ZeroAmount.into());
        }
        total_redeem = total_redeem
            .checked_add(*amount)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    if total_redeem > total_shielded {
        return Err(UTXOpiaError::InsufficientFunds.into());
    }

    verify_vk_merkle_and_proof(
        program_id,
        vk_registry_info,
        commitment_tree_info,
        active_index,
        source_tree_info,
        header,
        &prefix,
    )?;

    // Verify burn commitments: last n_public_outputs = Poseidon(0, token_id, amount_k)
    {
        let zero_npk = [0u8; 32];
        for (k, amount) in redeem_amounts.iter().take(n_public_outputs).enumerate() {
            let idx = n_tree_outputs + k;
            let expected_commitment =
                crate::utils::crypto::compute_commitment(&zero_npk, &token_id, *amount)?;
            if *prefix.commitments_out[idx] != expected_commitment {
                return Err(UTXOpiaError::InvalidCommitment.into());
            }
        }
    }

    // Get clock and rent for PDA creation
    let clock = Clock::get()?;
    let rent = Rent::get()?;

    create_nullifier_records(
        program_id,
        accounts,
        FIXED_ACCOUNTS,
        &prefix.nullifiers[..n_inputs],
        user,
        &rent,
        NullifierOperationType::FullWithdrawal as u8,
        crate::instruction::REDEEM,
    )?;

    // Insert tree outputs into Merkle tree
    {
        let mut tree_data = commitment_tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;

        for (i, commitment) in prefix
            .commitments_out
            .iter()
            .take(n_tree_outputs)
            .enumerate()
        {
            let leaf_index = tree.insert_leaf(commitment)?;

            let stealth_offset = stealth_data_start + i * STEALTH_DATA_PER_OUTPUT;
            let ephemeral_pub: &[u8; 32] = data[stealth_offset..stealth_offset + 32]
                .try_into()
                .unwrap();
            let encrypted_amount: &[u8; 8] = data[stealth_offset + 32..stealth_offset + 40]
                .try_into()
                .unwrap();

            crate::utils::events::emit_stealth_announcement(
                crate::utils::events::ANNOUNCEMENT_TYPE_TRANSFER,
                ephemeral_pub,
                encrypted_amount,
                prefix.commitments_out[i],
                leaf_index as u32,
                &token_id,
            );
        }
    }

    // Create RedemptionRequest PDAs — one per public output
    let redemption_base = FIXED_ACCOUNTS + n_inputs;
    for k in 0..n_public_outputs {
        let redemption_info = &accounts[redemption_base + k];
        validate_account_writable(redemption_info)?;

        let nonce_bytes = request_nonces[k].to_le_bytes();
        let redemption_seeds: &[&[u8]] =
            &[RedemptionRequest::SEED, user.key().as_ref(), &nonce_bytes];
        let (expected_redemption_pda, redemption_bump) =
            find_program_address(redemption_seeds, program_id);
        if redemption_info.key() != &expected_redemption_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        {
            let redemption_data = redemption_info.try_borrow_data()?;
            if !redemption_data.is_empty() && redemption_data[0] == REDEMPTION_REQUEST_DISCRIMINATOR
            {
                return Err(UTXOpiaError::AlreadyInitialized.into());
            }
        }

        let redemption_bump_bytes = [redemption_bump];
        let redemption_signer_seeds: &[&[u8]] = &[
            RedemptionRequest::SEED,
            user.key().as_ref(),
            &nonce_bytes,
            &redemption_bump_bytes,
        ];

        create_pda_account(
            user,
            redemption_info,
            program_id,
            rent.minimum_balance(RedemptionRequest::LEN),
            RedemptionRequest::LEN as u64,
            redemption_signer_seeds,
        )?;

        // Compute service fee from pool config (locked at request time)
        let service_fee = {
            let pool_data = pool_state_info.try_borrow_data()?;
            let pool = PoolState::from_bytes(&pool_data)?;
            pool.compute_service_fee(redeem_amounts[k])
        };
        if service_fee >= redeem_amounts[k] {
            return Err(UTXOpiaError::AmountTooSmall.into());
        }

        {
            let mut redemption_data = redemption_info.try_borrow_mut_data()?;
            let redemption = RedemptionRequest::init(&mut redemption_data)?;
            redemption.set_request_id(request_nonces[k]);
            redemption.requester.copy_from_slice(user.key().as_ref());
            redemption.set_amount_sats(redeem_amounts[k]);
            redemption.set_service_fee(service_fee);
            let btc_script = &data[btc_script_starts[k]..btc_script_starts[k] + btc_script_lens[k]];
            redemption.set_btc_script(btc_script)?;
            redemption.set_status(RedemptionStatus::Pending);
            // Record the token so cancel_redemption can only re-mint this token.
            redemption.set_token_id(&token_id);
        }

        // Emit per-output metadata
        let btc_script = &data[btc_script_starts[k]..btc_script_starts[k] + btc_script_lens[k]];
        let payout = redeem_amounts[k]
            .checked_sub(service_fee)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        crate::utils::events::emit_unshield_meta(
            redeem_amounts[k],
            service_fee,
            payout,
            user.key().as_ref().try_into().unwrap(),
            &token_id,
        );

        // Read fee config for event
        let (fee_base, fee_bps) = {
            let pool_data = pool_state_info.try_borrow_data()?;
            let pool = PoolState::from_bytes(&pool_data)?;
            (pool.service_fee_base(), pool.withdrawal_fee_bps())
        };

        crate::utils::events::emit_redemption_requested(
            user.key().as_ref().try_into().unwrap(),
            redeem_amounts[k],
            request_nonces[k],
            fee_base,
            fee_bps,
            btc_script,
        );
    }

    // Update pool state: decrement total_shielded by sum, increment pending_redemptions
    {
        let mut pool_data = pool_state_info.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;
        pool.sub_shielded(total_redeem)?;
        pool.set_pending_redemptions(pending_redemptions.saturating_add(n_public_outputs as u64));
        pool.set_last_update(clock.unix_timestamp);
    }

    pinocchio::msg!("UTXOpia: redeem");
    Ok(())
}
