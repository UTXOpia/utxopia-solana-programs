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
//! 0. pool_state           (writable; sync zkBTC total_shielded)
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

use crate::pinocchio_compat::{account_owner, AccountInfo, ProgramError, Pubkey};
use pinocchio::{
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::instructions::joinsplit_common::{
    create_nullifier_records, looks_like_commitment_tree, parse_header, parse_prefix, read_u64_le,
    validate_account_count, validate_public_outputs, verify_vk_merkle_and_proof, JoinSplitHeader,
    MAX_PUBLIC_OUTPUTS, STEALTH_DATA_PER_OUTPUT,
};
use crate::state::{CommitmentTree, NullifierOperationType, PoolState, TokenConfig};
use crate::utils::token::{is_native_sol_account, transfer_zkbtc, unwrap_lamports_signed};
use crate::utils::{
    validate_account_writable, validate_active_tree_pda, validate_any_token_program_key,
    validate_pool_state_pda, validate_program_owner, validate_system_program,
    validate_token_config_pda, validate_token_owner,
};

/// Number of fixed accounts before recipient token accounts
/// pool_state(0), commitment_tree(1), vk_registry(2), user(3), system_program(4),
/// token_config(5), vault(6), token_program(7)
const FIXED_ACCOUNTS: usize = 8;

pub fn process_unshield(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
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

    let min_accounts = FIXED_ACCOUNTS + n_public_outputs + n_inputs;
    validate_account_count(accounts.len(), min_accounts, proof_source)?;
    let mut proof_buf = [0u8; crate::utils::groth16::GROTH16_PROOF_SIZE];
    let prefix = parse_prefix(data, accounts, header, n_tree_outputs, &mut proof_buf)?;
    let stealth_data_start = prefix.stealth_data_start;
    let stealth_data_end = prefix.stealth_data_end;
    let mut nullifiers_buf = [0u8; crate::instructions::joinsplit_common::MAX_JOINSPLIT_SIZE * 32];
    let mut offset = stealth_data_end;

    // Parse per-output unshield amounts
    let mut unshield_amounts: [u64; MAX_PUBLIC_OUTPUTS] = [0u64; MAX_PUBLIC_OUTPUTS];
    for amount in unshield_amounts.iter_mut().take(n_public_outputs) {
        *amount = read_u64_le(data, &mut offset)?;
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
    validate_account_writable(pool_state_info)?;
    validate_account_writable(commitment_tree_info)?;
    validate_token_config_pda(token_config_info, pool_state_info, program_id)?;
    validate_account_writable(token_config_info)?;
    validate_account_writable(vault)?;

    if !user.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Native SOL is inferred from the registered vault's canonical native mint.
    // Instruction data and proof format stay unchanged: the proof already binds
    // the recipient's 32-byte Solana address.
    let native_sol = is_native_sol_account(vault, token_program)?;
    let (permissioned, policy_authority) = {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        (pool.permissioned(), *pool.auditor())
    };

    // Validate public destinations. SPL outputs use token accounts; native SOL
    // outputs use the proof-bound recipient account directly.
    for k in 0..n_public_outputs {
        let recipient = &accounts[FIXED_ACCOUNTS + k];
        validate_account_writable(recipient)?;
        // Reject recipient == vault: a self-transfer moves no tokens, but the note is still
        // nullified and total_shielded decremented below, permanently stranding the payout
        // (audit f29; mirrors the guard in claim_fees.rs).
        if recipient.address() == vault.address() {
            return Err(ProgramError::InvalidArgument);
        }
        if native_sol {
            // Never unwrap into another token-owned account. This also prevents
            // treating a wSOL ATA as a native destination by mistake.
            let owner = account_owner(recipient).as_ref();
            if owner == crate::constants::TOKEN_PROGRAM_ID
                || owner == crate::constants::TOKEN_2022_PROGRAM_ID
            {
                return Err(ProgramError::InvalidAccountOwner);
            }
        } else {
            validate_token_owner(recipient)?;
            if !recipient.owned_by(token_program.address()) {
                return Err(ProgramError::InvalidAccountOwner);
            }
        }
    }

    // Collect the public destinations: the token account's owner for SPL, the
    // account itself for native SOL. Read before anything expensive, because two
    // later steps need them — the ragequit gate matches them against the exit
    // registry, and the bound-params hash binds them to the proof.
    let mut owners_concat = [0u8; MAX_PUBLIC_OUTPUTS * 32]; // stack-allocated
    for k in 0..n_public_outputs {
        let recipient = &accounts[FIXED_ACCOUNTS + k];
        if native_sol {
            owners_concat[k * 32..(k + 1) * 32].copy_from_slice(recipient.address().as_ref());
        } else {
            let uta_data = recipient.try_borrow()?;
            if uta_data.len() < 64 {
                return Err(ProgramError::InvalidAccountData);
            }
            owners_concat[k * 32..(k + 1) * 32].copy_from_slice(&uta_data[32..64]);
        }
    }

    // Read pool state — check paused, validate active tree, get withdrawal_fee_bps
    let (withdrawal_fee_bps, active_index, zkbtc_mint, auditor_frozen) = {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }
        validate_active_tree_pda(
            commitment_tree_info,
            pool_state_info,
            program_id,
            pool.active_tree_index(),
        )?;
        (
            pool.withdrawal_fee_bps(),
            pool.active_tree_index(),
            pool.zkbtc_mint,
            permissioned && pool.auditor_is_frozen(),
        )
    };

    // Optional frozen source tree (for spending notes committed before a tree rotation): appended
    // just before the optional proof_buffer (which parse_prefix reads as the last account).
    // Identified by being a program-owned CommitmentTree, so it cannot be confused with the buffer.
    let pb = usize::from(proof_source == 1);
    // A permissioned exit appends either the approval pair (verified) or one
    // registry entry per public output (ragequit). Which is in play is read off
    // the tail account the same way the frozen source tree is: the policy
    // program's id is fixed and known, so it cannot be confused with a PDA.
    let verified = permissioned
        && accounts
            .len()
            .checked_sub(1 + pb)
            .is_some_and(|i| {
                accounts[i].address()
                    == &Pubkey::new_from_array(crate::constants::POLICY_PROGRAM_ID)
            });
    let policy = match (permissioned, verified) {
        (false, _) => 0,
        (true, true) => 2,
        (true, false) => n_public_outputs,
    };
    if permissioned && accounts.len() < min_accounts + policy + pb {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let approval_info = verified
        .then(|| accounts.get(accounts.len() - 2 - pb))
        .flatten();
    let policy_program_info = verified
        .then(|| accounts.get(accounts.len() - 1 - pb))
        .flatten();
    let source_tree_info = accounts
        .len()
        .checked_sub(1 + pb + policy)
        .filter(|&i| i >= min_accounts)
        .map(|i| &accounts[i])
        .filter(|a| {
            a.address() != commitment_tree_info.address()
                && looks_like_commitment_tree(a, program_id)
        });

    // Read token config — get token_id, validate vault
    let (token_id, is_pool_zkbtc) = {
        let tc_data = token_config_info.try_borrow()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;

        if !tc.is_enabled() {
            return Err(UTXOpiaError::TokenDisabled.into());
        }

        // Validate vault matches
        if vault.address().as_ref() != tc.vault {
            return Err(UTXOpiaError::InvalidVault.into());
        }

        (tc.token_id, tc.mint == zkbtc_mint)
    };

    // Derive pool PDA for signing vault transfer
    validate_pool_state_pda(pool_state_info, program_id)?;
    let pool_bump = {
        let pool_data = pool_state_info.try_borrow()?;
        PoolState::from_bytes(&pool_data)?.bump
    };

    // Verified: the auditor decided this spend, so the destination is theirs to
    // allow. Ragequit: nobody decided anything, so the destination must already
    // be registered. An auditor can bound where an unapproved exit lands, never
    // whether it happens.
    let spend_path = crate::instructions::resolve_spend_path(
        permissioned,
        approval_info.is_some(),
        policy_program_info.is_some(),
        crate::instruction::UNSHIELD,
    )?;
    match spend_path {
        crate::instructions::SpendPath::Open => {}
        crate::instructions::SpendPath::Verified => {
            // Freezing halts the approved flow: an approval issued before the
            // freeze must not still spend through it.
            if auditor_frozen {
                return Err(UTXOpiaError::AuditorFrozen.into());
            }
            crate::instructions::consume_policy_approval(
                program_id,
                approval_info.ok_or(ProgramError::NotEnoughAccountKeys)?,
                policy_program_info.ok_or(ProgramError::NotEnoughAccountKeys)?,
                pool_state_info,
                user.address(),
                &policy_authority,
                crate::instruction::UNSHIELD,
                // Which notes, how much, and to whom — everything past
                // `stealth_data_end` is the per-output amounts, and the owners
                // are the destinations the payout actually credits.
                &[
                    crate::instructions::joinsplit_common::nullifiers_concat(
                        &prefix,
                        n_inputs,
                        &mut nullifiers_buf,
                    ),
                    &data[stealth_data_end..],
                    &owners_concat[..n_public_outputs * 32],
                ],
            )?;
        }
        crate::instructions::SpendPath::Ragequit => {
            // Deliberately ignores `auditor_frozen`. Freezing is the auditor's
            // strongest lever and it still stops short of the exit: a frozen
            // pool that could not be ragequit out of is a pool whose operator
            // can prevent withdrawal, which is the one power they must not have.
            //
            // `is_paused` above is deliberately NOT waived the same way. It is
            // the protocol-wide emergency stop for an active exploit, not a
            // compliance lever, and halting a drain means halting every exit.
            let base = accounts
                .len()
                .checked_sub(n_public_outputs + pb)
                .ok_or(ProgramError::NotEnoughAccountKeys)?;
            for k in 0..n_public_outputs {
                let owner: &[u8; 32] = owners_concat[k * 32..(k + 1) * 32].try_into().unwrap();
                crate::instructions::assert_exit_destination_registered(
                    program_id,
                    pool_state_info.address(),
                    &accounts[base + k],
                    crate::state::EXIT_KIND_SOLANA_OWNER,
                    owner,
                )?;
            }
        }
    }

    // Bind the destinations and stealth data to the proof. Authorization is
    // settled above so an unauthorized spend never reaches the hashing.
    {
        let stealth_data_hash = crate::utils::sha256(&data[stealth_data_start..stealth_data_end]);
        let operation_hash = crate::utils::crypto::compute_bound_params_hash_unshield(
            crate::constants::CHAIN_ID,
            &owners_concat[..n_public_outputs * 32],
            &stealth_data_hash,
        );
        let expected = crate::utils::crypto::bind_bound_params_to_domain(
            &operation_hash,
            crate::constants::CHAIN_ID,
            program_id,
            pool_state_info.address(),
            permissioned,
        )?;
        if *prefix.bound_params_hash != expected {
            return Err(UTXOpiaError::InvalidBoundParams.into());
        }
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

    // Verify burn commitments: last n_public_outputs = Poseidon(0, token_id, amount_k)
    {
        let zero_npk = [0u8; 32];
        for (k, amount) in unshield_amounts.iter().take(n_public_outputs).enumerate() {
            let idx = n_tree_outputs + k; // public outputs are at the end
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

    let nullifier_base = FIXED_ACCOUNTS + n_public_outputs;
    create_nullifier_records(
        program_id,
        accounts,
        nullifier_base,
        &prefix.nullifiers[..n_inputs],
        pool_state_info,
        source_tree_index,
        user,
        &rent,
        NullifierOperationType::FullWithdrawal as u8,
        crate::instruction::UNSHIELD,
    )?;

    // Insert tree outputs into Merkle tree
    {
        let mut tree_data = commitment_tree_info.try_borrow_mut()?;
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
            let encrypted_token_id: &[u8; 32] = data[stealth_offset + 40..stealth_offset + 72]
                .try_into()
                .unwrap();

            crate::utils::events::emit_stealth_announcement(
                crate::utils::events::ANNOUNCEMENT_TYPE_TRANSFER,
                ephemeral_pub,
                encrypted_amount,
                prefix.commitments_out[i],
                leaf_index as u32,
                encrypted_token_id,
            );
        }
    }

    // Compute total amount, fees, and transfer payouts
    let mut total_amount: u64 = 0;
    let mut total_protocol_fee: u64 = 0;

    let pool_bump_bytes = [pool_bump];
    let pool_signer_seeds: &[&[u8]] =
        &[PoolState::SEED, &zkbtc_mint, &pool_bump_bytes];

    for k in 0..n_public_outputs {
        let amount = unshield_amounts[k];
        let protocol_fee = crate::utils::policy::compute_bps_fee(amount, withdrawal_fee_bps);
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
        let recipient_address: [u8; 32] = if native_sol {
            recipient.address().as_ref().try_into().unwrap()
        } else {
            let recipient_data = recipient.try_borrow()?;
            recipient_data[32..64]
                .try_into()
                .map_err(|_| ProgramError::InvalidAccountData)?
        };

        // Emit unshield metadata per output
        crate::utils::events::emit_unshield_meta(
            amount,
            protocol_fee,
            payout,
            &recipient_address,
            &token_id,
        );

        if native_sol {
            // Partial unwrap keeps the pool vault open and sends the exact net
            // payout as lamports to the proof-bound recipient.
            unwrap_lamports_signed(
                token_program,
                vault,
                recipient,
                pool_state_info,
                payout,
                pool_signer_seeds,
            )?;
        } else {
            transfer_zkbtc(
                token_program,
                vault,
                recipient,
                pool_state_info,
                payout,
                pool_signer_seeds,
            )?;
        }
    }

    // Update token config: decrement total_shielded by sum, add total fees
    let token_total_shielded = {
        let mut tc_data = token_config_info.try_borrow_mut()?;
        let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;
        tc.sub_shielded(total_amount)?;
        tc.add_fees(total_protocol_fee)?;
        tc.total_shielded()
    };
    if is_pool_zkbtc {
        let mut pool_data = pool_state_info.try_borrow_mut()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;
        // Reconcile legacy SPL shields that predate PoolState accounting.
        pool.set_total_shielded(token_total_shielded);
        pool.set_last_update(clock.unix_timestamp);
    }

    solana_program_log::log!("UTXOpia: unshield");
    Ok(())
}
