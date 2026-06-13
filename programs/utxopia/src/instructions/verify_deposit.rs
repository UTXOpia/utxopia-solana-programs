//! Verify Deposit instruction (Pinocchio)
//!
//! OP_RETURN-free deposit flow:
//! 1. User generates npk client-side, relayer creates DepositIntent PDA
//! 2. User sends BTC (no OP_RETURN needed)
//! 3. Backend detects deposit, sweeps UTXO to pool wallet
//! 4. Backend calls btc-light-client's verify_transaction to create VerifiedTransaction PDA
//! 5. Backend uploads sweep TX to ChadBuffer
//! 6. Backend calls this instruction — npk + ephemeral_pub read from DepositIntent PDA
//!
//! This instruction:
//! - Checks VerifiedTransaction PDA exists (btc-light-client already verified SPV for sweep TX)
//! - Verifies sufficient confirmations via light client tip height
//! - Reads npk + ephemeral_pub from DepositIntent PDA (instead of deposit TX OP_RETURN)
//! - Extracts deposit amount trustlessly from the SPV-verified sweep raw transaction
//! - Computes commitment ON-CHAIN: Poseidon(npk, ZKBTC_TOKEN_ID, amount)
//! - Inserts commitment into Merkle tree
//! - Emits stealth announcement as sol_log_data event (type=0, plaintext amount)
//! - Mints zkBTC to pool vault
//! - Closes DepositIntent PDA (returns rent to authority)
//!
//! Instruction Data (80 bytes):
//! - [0-31]   sweep_txid        (32 bytes) - Sweep tx ID (internal byte order)
//! - [32-39]  block_height      (8 bytes)  - Block containing sweep tx (cross-check)
//! - [40-43]  sweep_tx_size     (4 bytes)  - Raw sweep tx size in ChadBuffer
//! - [44-75]  deposit_txid      (32 bytes) - Deposit tx ID (internal byte order)
//! - [76-79]  deposit_tx_size   (4 bytes)  - Raw deposit tx size in ChadBuffer

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{
    deposit_receipt::DEPOSIT_RECEIPT_DISCRIMINATOR, light_client_tip_height,
    pool_config::POOL_CONFIG_DISCRIMINATOR, CommitmentTree, DepositIntent, DepositReceipt,
    PoolConfig, PoolState, TokenConfig, VerifiedTransactionView,
};
use crate::utils::bitcoin::{compute_tx_hash, ParsedTransaction};
use crate::utils::chadbuffer::read_transaction_from_buffer;
use crate::utils::crypto::compute_commitment;
use crate::utils::events::ANNOUNCEMENT_TYPE_DEPOSIT;
use crate::utils::secp256k1::{extract_p2tr_output_key, verify_taproot_output_key};
use crate::utils::{
    create_pda_account, mint_zkbtc, validate_account_writable, validate_any_token_program_key,
    validate_program_owner, validate_system_program, validate_token_owner,
};

use super::complete_deposit::DEMO_REQUIRED_CONFIRMATIONS;

/// Instruction data for verify_deposit (OP_RETURN-free)
pub struct VerifyDepositData {
    pub sweep_txid: [u8; 32],
    pub block_height: u64,
    pub sweep_tx_size: u32,
    pub deposit_txid: [u8; 32],
    /// Size of deposit TX in ChadBuffer.
    pub deposit_tx_size: u32,
}

impl VerifyDepositData {
    pub const FULL_SIZE: usize = 32 + 8 + 4 + 32 + 4; // 80 bytes

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::FULL_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut sweep_txid = [0u8; 32];
        sweep_txid.copy_from_slice(&data[0..32]);

        let block_height = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let sweep_tx_size = u32::from_le_bytes(data[40..44].try_into().unwrap());

        let mut deposit_txid = [0u8; 32];
        deposit_txid.copy_from_slice(&data[44..76]);

        let deposit_tx_size = u32::from_le_bytes(data[76..80].try_into().unwrap());

        Ok(Self {
            sweep_txid,
            block_height,
            sweep_tx_size,
            deposit_txid,
            deposit_tx_size,
        })
    }
}

/// Verify an OP_RETURN-free deposit using DepositIntent PDA + VerifiedTransaction PDA
///
/// Reads npk + ephemeral_pub from DepositIntent PDA instead of deposit TX OP_RETURN.
/// After verification, closes DepositIntent PDA and returns rent to authority.
///
/// # Accounts
/// 0.  `[writable]` Pool state
/// 1.  `[]` VerifiedTransaction PDA (owned by btc-light-client)
/// 2.  `[]` Light client (owned by btc-light-client, for confirmation count)
/// 3.  `[writable]` Commitment tree
/// 4.  `[]` Sweep TX buffer (ChadBuffer)
/// 5.  `[signer]` Authority (pool authority, pays for storage)
/// 6.  `[]` System program
/// 7.  `[writable]` zkBTC mint
/// 8.  `[writable]` Pool vault token account
/// 9.  `[]` Token-2022 program
/// 10. `[writable]` DepositIntent PDA
/// 11. `[writable]` Deposit receipt PDA (prevents duplicate verification)
/// 12. `[]`         TokenConfig PDA (for token_id)
/// 13. `[]`         PoolConfig PDA (for Taproot npk verification)
/// 14. `[]`         Deposit TX buffer (ChadBuffer, for Taproot verification)
pub fn process_verify_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 15 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let verified_tx_info = &accounts[1];
    let light_client_info = &accounts[2];
    let commitment_tree_info = &accounts[3];
    let tx_buffer_info = &accounts[4];
    let authority = &accounts[5];
    let system_program = &accounts[6];
    let zkbtc_mint = &accounts[7];
    let pool_vault = &accounts[8];
    let token_program = &accounts[9];
    let deposit_intent_info = &accounts[10];
    let deposit_receipt_info = &accounts[11];
    let token_config_info = &accounts[12];

    // Parse instruction data
    let ix_data = VerifyDepositData::from_bytes(data)?;

    // Validate account owners
    validate_program_owner(pool_state_info, program_id)?;
    let btc_lc_id: &Pubkey = &crate::constants::BTC_LIGHT_CLIENT_PROGRAM_ID;
    validate_program_owner(verified_tx_info, btc_lc_id)?;
    validate_program_owner(light_client_info, btc_lc_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_program_owner(deposit_intent_info, program_id)?;
    validate_program_owner(token_config_info, program_id)?;
    validate_token_owner(zkbtc_mint)?;
    validate_token_owner(pool_vault)?;
    validate_any_token_program_key(token_program)?;
    validate_system_program(system_program)?;

    // SECURITY: Validate writable accounts
    validate_account_writable(pool_state_info)?;
    validate_account_writable(commitment_tree_info)?;
    validate_account_writable(zkbtc_mint)?;
    validate_account_writable(pool_vault)?;
    validate_account_writable(deposit_intent_info)?;
    validate_account_writable(deposit_receipt_info)?;

    // Authority must be signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate authority matches pool and get bump + bounds
    let (pool_bump, min_deposit, max_deposit) = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }

        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        (pool.bump, pool.min_deposit(), pool.max_deposit())
    };

    // Read token config — get token_id for commitment
    let token_id = {
        let tc_data = token_config_info.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;
        tc.token_id
    };

    // --- Deposit receipt dedup check ---
    {
        let receipt_seeds: &[&[u8]] = &[DepositReceipt::SEED, &ix_data.deposit_txid];
        let (expected_receipt_pda, receipt_bump) = find_program_address(receipt_seeds, program_id);
        if deposit_receipt_info.key() != &expected_receipt_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        // Check if deposit was already verified
        {
            let receipt_data = deposit_receipt_info.try_borrow_data()?;
            if !receipt_data.is_empty() && receipt_data[0] == DEPOSIT_RECEIPT_DISCRIMINATOR {
                return Err(UTXOpiaError::DuplicateDeposit.into());
            }
        }

        // Create deposit receipt PDA
        let rent = Rent::get()?;
        let bump_bytes = [receipt_bump];
        let signer_seeds: &[&[u8]] = &[DepositReceipt::SEED, &ix_data.deposit_txid, &bump_bytes];

        create_pda_account(
            authority,
            deposit_receipt_info,
            program_id,
            rent.minimum_balance(DepositReceipt::LEN),
            DepositReceipt::LEN as u64,
            signer_seeds,
        )?;

        let mut receipt_data = deposit_receipt_info.try_borrow_mut_data()?;
        DepositReceipt::init(&mut receipt_data)?;
    }

    // --- VerifiedTransaction PDA check ---
    {
        let vt_data = verified_tx_info.try_borrow_data()?;
        let vt = VerifiedTransactionView::from_bytes(&vt_data)?;

        if *vt.txid() != ix_data.sweep_txid {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }

        if vt.block_height() as u64 != ix_data.block_height {
            return Err(UTXOpiaError::InvalidBlockHeader.into());
        }
    }

    // Verify sufficient confirmations
    {
        let lc_data = light_client_info.try_borrow_data()?;
        let tip = light_client_tip_height(&lc_data)?;
        let confirmations = if ix_data.block_height > tip {
            0
        } else {
            tip - ix_data.block_height + 1
        };
        if confirmations < DEMO_REQUIRED_CONFIRMATIONS {
            return Err(UTXOpiaError::InsufficientConfirmations.into());
        }
    }

    // --- Read and verify sweep TX from ChadBuffer ---
    crate::utils::chadbuffer::validate_chadbuffer_owner(tx_buffer_info)?;
    let sweep_buffer_data = tx_buffer_info
        .try_borrow_data()
        .map_err(|_| UTXOpiaError::InvalidBlockHeader)?;

    let sweep_raw_tx =
        read_transaction_from_buffer(&sweep_buffer_data, ix_data.sweep_tx_size as usize)?;

    // Verify sweep transaction hash matches sweep_txid
    let computed_sweep_hash = compute_tx_hash(sweep_raw_tx);
    if computed_sweep_hash != ix_data.sweep_txid {
        return Err(UTXOpiaError::InvalidSpvProof.into());
    }

    // Parse sweep TX and extract deposit amount
    let sweep_parsed =
        ParsedTransaction::parse(sweep_raw_tx).map_err(|_| UTXOpiaError::InvalidSpvProof)?;

    // --- Read npk + ephemeral_pub from DepositIntent PDA ---
    let (ephemeral_pub, npk) = {
        let intent_data = deposit_intent_info.try_borrow_data()?;
        let intent = DepositIntent::from_bytes(&intent_data)?;

        // Verify DepositIntent PDA address
        let intent_seeds: &[&[u8]] = &[DepositIntent::SEED, &intent.npk];
        let (expected_intent_pda, _) = find_program_address(intent_seeds, program_id);
        if deposit_intent_info.key() != &expected_intent_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        (intent.ephemeral_pub, intent.npk)
    };

    // --- Taproot npk ↔ deposit address verification + exact outpoint linkage ---
    // The txid-only check is insufficient when a BTC transaction has
    // multiple outputs. Require the raw deposit tx, identify the exact credited
    // output, then prove the sweep spends that output index.
    if ix_data.deposit_tx_size == 0 {
        return Err(UTXOpiaError::InvalidSpvProof.into());
    }
    let pool_config_info = &accounts[13];
    let deposit_tx_buffer_info = &accounts[14];

    validate_program_owner(pool_config_info, program_id)?;
    crate::utils::chadbuffer::validate_chadbuffer_owner(deposit_tx_buffer_info)?;

    let ika_xonly = {
        let config_data = pool_config_info.try_borrow_data()?;
        if config_data.len() < PoolConfig::LEN || config_data[0] != POOL_CONFIG_DISCRIMINATOR {
            return Err(ProgramError::UninitializedAccount);
        }
        let config = PoolConfig::from_bytes(&config_data)?;
        if !config.has_ika_dwallet() || *config.get_ika_dwallet_xonly_pubkey() == [0u8; 32] {
            return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
        }
        *config.get_ika_dwallet_xonly_pubkey()
    };

    let deposit_buffer_data = deposit_tx_buffer_info
        .try_borrow_data()
        .map_err(|_| UTXOpiaError::InvalidSpvProof)?;
    let deposit_raw_tx =
        read_transaction_from_buffer(&deposit_buffer_data, ix_data.deposit_tx_size as usize)?;

    let computed_deposit_hash = compute_tx_hash(deposit_raw_tx);
    if computed_deposit_hash != ix_data.deposit_txid {
        return Err(UTXOpiaError::InvalidSpvProof.into());
    }

    let deposit_parsed =
        ParsedTransaction::parse(deposit_raw_tx).map_err(|_| UTXOpiaError::InvalidSpvProof)?;

    let mut matched_vout: Option<u32> = None;
    for (vout, output) in deposit_parsed.outputs().enumerate() {
        if let Some(output_key) = extract_p2tr_output_key(output.script_pubkey) {
            if verify_taproot_output_key(&ika_xonly, &npk, &output_key).is_ok() {
                matched_vout = Some(vout as u32);
                break;
            }
        }
    }
    let deposit_vout = matched_vout.ok_or(UTXOpiaError::TaprootVerificationFailed)?;

    if !sweep_parsed.find_input_with_prev_outpoint(&ix_data.deposit_txid, deposit_vout) {
        return Err(UTXOpiaError::InvalidSpvProof.into());
    }

    // Extract deposit amount from sweep TX's deposit output (largest P2TR output)
    let deposit_output = sweep_parsed
        .find_deposit_output()
        .ok_or(UTXOpiaError::InvalidSpvProof)?;
    let amount_sats = deposit_output.value;

    // Validate extracted amount is within bounds
    if amount_sats < min_deposit {
        return Err(UTXOpiaError::AmountTooSmall.into());
    }
    if amount_sats > max_deposit {
        return Err(UTXOpiaError::AmountTooLarge.into());
    }

    // Compute commitment ON-CHAIN: Poseidon(npk, token_id, amount)
    let commitment = compute_commitment(&npk, &token_id, amount_sats)?;

    // Insert commitment into Merkle tree
    let leaf_index = {
        let mut tree_data = commitment_tree_info.try_borrow_mut_data()?;
        let tree = CommitmentTree::from_bytes_mut(&mut tree_data)?;

        if !tree.has_capacity() {
            return Err(UTXOpiaError::TreeFull.into());
        }

        tree.insert_leaf(&commitment)?
    };

    let clock = Clock::get()?;

    // Emit stealth announcement as log event (LeafInserted merged into announcement)
    let amount_bytes = amount_sats.to_le_bytes();
    crate::utils::events::emit_stealth_announcement(
        ANNOUNCEMENT_TYPE_DEPOSIT,
        &ephemeral_pub,
        &amount_bytes,
        &commitment,
        leaf_index as u32,
        &token_id,
    );

    // Emit deposit verified event (BTC txids + amount for indexer)
    // Deposit TX amount is parsed from the raw transaction during completion.
    crate::utils::events::emit_deposit_verified(
        &ix_data.sweep_txid,
        &ix_data.deposit_txid,
        amount_sats,
        leaf_index as u32,
        0,
    );

    // Mint zkBTC to pool vault
    let pool_bump_bytes = [pool_bump];
    let pool_signer_seeds: &[&[u8]] = &[PoolState::SEED, &pool_bump_bytes];

    mint_zkbtc(
        token_program,
        zkbtc_mint,
        pool_vault,
        pool_state_info,
        amount_sats,
        pool_signer_seeds,
    )?;

    // Update pool statistics
    {
        let mut pool_data = pool_state_info.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;

        pool.increment_deposit_count()?;
        pool.add_minted(amount_sats)?;
        pool.add_shielded(amount_sats)?;
        pool.set_last_update(clock.unix_timestamp);
    }

    // Update token config: keep total_shielded symmetric with unshield.sub_shielded.
    // Without this, an unshield against a verified-deposit note would underflow on the
    // TokenConfig.total_shielded counter.
    {
        let mut tc_data = token_config_info.try_borrow_mut_data()?;
        let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;
        tc.add_shielded(amount_sats)?;
    }

    // Close DepositIntent PDA — return rent to authority
    {
        let dest_starting_lamports = authority.lamports();
        let intent_lamports = deposit_intent_info.lamports();

        // Transfer lamports
        unsafe {
            *authority.borrow_mut_lamports_unchecked() = dest_starting_lamports
                .checked_add(intent_lamports)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            *deposit_intent_info.borrow_mut_lamports_unchecked() = 0;
        }

        // Zero out data
        let mut intent_data = deposit_intent_info.try_borrow_mut_data()?;
        intent_data.fill(0);
    }

    pinocchio::msg!("UTXOpia: deposit verified");

    Ok(())
}
