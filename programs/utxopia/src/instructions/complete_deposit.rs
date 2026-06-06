//! Verify Stealth Deposit instruction (Pinocchio)
//!
//! Trustless note-public-key deposit flow:
//! 1. User generates note_public_key client-side, sends BTC with OP_RETURN(ephemeral_pubkey || note_public_key)
//! 2. Backend detects the direct Ika-vault deposit and verifies it in-place
//! 3. Backend calls btc-light-client's verify_transaction to create VerifiedTransaction PDA
//! 4. Backend uploads the deposit TX to a ChadBuffer account
//! 5. Backend calls this instruction — note_public_key + ephemeral_pubkey extracted ON-CHAIN from deposit TX
//!
//! This instruction:
//! - Checks VerifiedTransaction PDA exists (btc-light-client already verified SPV for deposit TX)
//! - Verifies sufficient confirmations via light client tip height
//! - Reads deposit TX from its ChadBuffer, extracts note_public_key + ephemeral_pubkey from OP_RETURN.
//!   For direct-to-pool deposits, `deposit_tx_size = 0` and the SPV-verified tx
//!   itself is treated as the deposit tx.
//! - Extracts credited amount trustlessly from the SPV-verified transaction output.
//! - Applies Solana-side deposit fees and computes commitment ON-CHAIN:
//!   Poseidon(note_public_key, ZKBTC_TOKEN_ID, gross_amount - fee)
//! - Inserts commitment into Merkle tree
//! - Emits stealth announcement as sol_log_data event (type=0, plaintext amount)
//! - Mints zkBTC collateral equal to the shielded note amount to the pool vault
//!
//! Instruction Data (80 bytes, fixed):
//! - [0-31]   sweep_txid        (32 bytes) - SPV-verified tx ID; direct mode uses deposit_txid
//! - [32-39]  block_height      (8 bytes)  - Block containing the verified tx
//! - [40-43]  sweep_tx_size     (4 bytes)  - Raw verified tx size in ChadBuffer
//! - [44-47]  deposit_tx_size   (4 bytes)  - Raw deposit tx size in ChadBuffer
//! - [48-79]  deposit_txid      (32 bytes) - Deposit tx ID (internal byte order)

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    ProgramResult,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
};

use crate::error::UTXOpiaError;
use crate::state::{
    CommitmentTree, DepositReceipt, PoolConfig, PoolState, TokenConfig, UtxoRecord,
    VerifiedTransactionView, light_client_tip_height,
    deposit_receipt::DEPOSIT_RECEIPT_DISCRIMINATOR,
    pool_config::POOL_CONFIG_DISCRIMINATOR,
};
use crate::utils::events::ANNOUNCEMENT_TYPE_DEPOSIT;
use crate::utils::crypto::compute_commitment;
use crate::utils::bitcoin::{compute_tx_hash, sha256, DepositOpReturn, ParsedTransaction};
use crate::utils::chadbuffer::read_transaction_from_buffer;
use crate::utils::{
    create_pda_account, mint_zkbtc, validate_active_tree_pda, validate_program_owner,
    validate_system_program, validate_token_owner, validate_any_token_program_key,
    validate_account_writable,
};

/// Required confirmations for deposits
#[cfg(feature = "devnet")]
pub const DEMO_REQUIRED_CONFIRMATIONS: u64 = 1;

#[cfg(not(feature = "devnet"))]
pub const DEMO_REQUIRED_CONFIRMATIONS: u64 = 6;

/// Instruction data for complete_deposit (trustless note_public_key extraction)
///
/// The commitment is computed ON-CHAIN: Poseidon(note_public_key, ZKBTC_TOKEN_ID, amount)
/// note_public_key + ephemeral_pubkey are extracted ON-CHAIN from the deposit TX's OP_RETURN.
/// Amount is extracted from the SPV-verified deposit transaction.
pub struct CompleteDepositData {
    pub sweep_txid: [u8; 32],
    pub block_height: u64,
    pub sweep_tx_size: u32,
    pub deposit_tx_size: u32,
    pub deposit_txid: [u8; 32],
}

impl CompleteDepositData {
    pub const HEADER_SIZE: usize = 32 + 8 + 4 + 4 + 32; // 80 bytes

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::HEADER_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut sweep_txid = [0u8; 32];
        sweep_txid.copy_from_slice(&data[0..32]);

        let block_height = u64::from_le_bytes(data[32..40].try_into().unwrap());
        let sweep_tx_size = u32::from_le_bytes(data[40..44].try_into().unwrap());
        let deposit_tx_size = u32::from_le_bytes(data[44..48].try_into().unwrap());

        let mut deposit_txid = [0u8; 32];
        deposit_txid.copy_from_slice(&data[48..80]);

        Ok(Self {
            sweep_txid,
            block_height,
            sweep_tx_size,
            deposit_tx_size,
            deposit_txid,
        })
    }
}

/// Verify a note-public-key stealth deposit using VerifiedTransaction PDA
///
/// Trustlessly extracts note_public_key + ephemeral_pubkey from the deposit TX's OP_RETURN.
/// Verifies the sweep TX spends from the deposit TX (input linkage).
/// Computes commitment on-chain, inserts into Merkle tree, emits stealth announcement event.
///
/// # Accounts
/// 0.  `[writable]` Pool state
/// 1.  `[]` VerifiedTransaction PDA (owned by btc-light-client)
/// 2.  `[]` Light client (owned by btc-light-client, for confirmation count)
/// 3.  `[writable]` Commitment tree
/// 4.  `[]` Verified/deposit TX buffer (ChadBuffer)
/// 5.  `[signer]` Authority (pool authority, pays for storage)
/// 6.  `[]` System program
/// 7.  `[writable]` zkBTC mint
/// 8.  `[writable]` Pool vault token account
/// 9.  `[]` Token-2022 program
/// 10. `[]` Deposit TX buffer (ChadBuffer)
/// 11. `[writable]` Deposit receipt PDA (prevents duplicate verification)
/// 12. `[writable]` UTXO record PDA (tracks pool BTC UTXO)
/// 13. `[writable]` TokenConfig PDA (for token_id, fees, total_shielded tracking)
/// 14. `[]` PoolConfig PDA (optional, enforces sweep output is pool-controlled)
///
/// # Instruction data
/// - CompleteDepositData (80 bytes, fixed)
pub fn process_complete_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 14 {
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
    let deposit_tx_buffer_info = &accounts[10];
    let deposit_receipt_info = &accounts[11];
    let utxo_record_info = &accounts[12];
    let token_config_info = &accounts[13];

    // Parse instruction data (no trailing merkle proof)
    let ix_data = CompleteDepositData::from_bytes(data)?;

    // Validate account owners
    validate_program_owner(pool_state_info, program_id)?;
    // VerifiedTransaction and Light client are owned by btc-light-client program
    let btc_lc_id: &Pubkey = &crate::constants::BTC_LIGHT_CLIENT_PROGRAM_ID;
    validate_program_owner(verified_tx_info, btc_lc_id)?;
    validate_program_owner(light_client_info, btc_lc_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_token_owner(zkbtc_mint)?;
    validate_token_owner(pool_vault)?;
    validate_any_token_program_key(token_program)?;
    validate_system_program(system_program)?;

    // SECURITY: Validate writable accounts
    validate_account_writable(pool_state_info)?;
    validate_account_writable(commitment_tree_info)?;
    validate_account_writable(zkbtc_mint)?;
    validate_account_writable(pool_vault)?;
    validate_account_writable(deposit_receipt_info)?;
    validate_account_writable(utxo_record_info)?;
    validate_program_owner(token_config_info, program_id)?;
    validate_account_writable(token_config_info)?;

    // Authority must be signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate authority matches pool and get bump + bounds + fee bps
    let (pool_bump, min_deposit, max_deposit, deposit_fee_bps) = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }

        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        validate_active_tree_pda(commitment_tree_info, program_id, pool.active_tree_index())?;
        (pool.bump, pool.min_deposit(), pool.max_deposit(), pool.deposit_fee_bps())
    };

    // Read token config for token_id and service_fee
    let (token_id, service_fee) = {
        let tc_data = token_config_info.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;
        (tc.token_id, tc.service_fee())
    };

    // --- Deposit receipt dedup check ---
    // Derive deposit receipt PDA from deposit_txid and verify it doesn't already exist
    {
        let receipt_seeds: &[&[u8]] = &[DepositReceipt::SEED, &ix_data.deposit_txid];
        let (expected_receipt_pda, receipt_bump) = find_program_address(receipt_seeds, program_id);
        if deposit_receipt_info.key() != &expected_receipt_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        // Check if deposit was already verified (account exists and initialized)
        {
            let receipt_data = deposit_receipt_info.try_borrow_data()?;
            if !receipt_data.is_empty() && receipt_data[0] == DEPOSIT_RECEIPT_DISCRIMINATOR {
                return Err(UTXOpiaError::DuplicateDeposit.into());
            }
        }

        // Create deposit receipt PDA to prevent future duplicates
        let rent = Rent::get()?;
        let bump_bytes = [receipt_bump];
        let signer_seeds: &[&[u8]] = &[
            DepositReceipt::SEED,
            &ix_data.deposit_txid,
            &bump_bytes,
        ];

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
    // Parse the VerifiedTransaction PDA and verify the SPV-verified txid matches.
    {
        let vt_data = verified_tx_info.try_borrow_data()?;
        let vt = VerifiedTransactionView::from_bytes(&vt_data)?;

        // Verify txid matches (both in internal byte order)
        if *vt.txid() != ix_data.sweep_txid {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }

        // Cross-check block height
        if vt.block_height() as u64 != ix_data.block_height {
            return Err(UTXOpiaError::InvalidBlockHeader.into());
        }
    }

    // Verify sufficient confirmations via light client tip height
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

    // --- Read and verify SPV-verified TX from ChadBuffer ---
    crate::utils::chadbuffer::validate_chadbuffer_owner(tx_buffer_info)?;
    let sweep_buffer_data = tx_buffer_info
        .try_borrow_data()
        .map_err(|_| UTXOpiaError::InvalidBlockHeader)?;

    let sweep_raw_tx = read_transaction_from_buffer(&sweep_buffer_data, ix_data.sweep_tx_size as usize)?;

    // Verify sweep transaction hash matches sweep_txid
    let computed_sweep_hash = compute_tx_hash(sweep_raw_tx);
    if computed_sweep_hash != ix_data.sweep_txid {
        return Err(UTXOpiaError::InvalidSpvProof.into());
    }

    // Parse SPV-verified TX and extract deposit amount
    let sweep_parsed = ParsedTransaction::parse(sweep_raw_tx)
        .map_err(|_| UTXOpiaError::InvalidSpvProof)?;

    // --- Read and verify deposit TX from ChadBuffer ---
    // Direct-to-pool mode: deposit_tx_size == 0 means the SPV-verified tx is
    // itself the deposit tx, so no second ChadBuffer is needed.
    let direct_to_pool = ix_data.deposit_tx_size == 0;
    let deposit_buffer_data = if direct_to_pool {
        None
    } else {
        crate::utils::chadbuffer::validate_chadbuffer_owner(deposit_tx_buffer_info)?;
        Some(
            deposit_tx_buffer_info
                .try_borrow_data()
                .map_err(|_| UTXOpiaError::InvalidBlockHeader)?,
        )
    };
    let deposit_raw_tx = if direct_to_pool {
        if ix_data.deposit_txid != ix_data.sweep_txid {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }
        sweep_raw_tx
    } else {
        let raw = read_transaction_from_buffer(
            deposit_buffer_data
                .as_ref()
                .ok_or(UTXOpiaError::InvalidBlockHeader)?,
            ix_data.deposit_tx_size as usize,
        )?;

        // Verify deposit transaction hash matches deposit_txid
        let computed_deposit_hash = compute_tx_hash(raw);
        if computed_deposit_hash != ix_data.deposit_txid {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }
        raw
    };

    // Parse deposit TX
    let deposit_parsed = ParsedTransaction::parse(deposit_raw_tx)
        .map_err(|_| UTXOpiaError::InvalidSpvProof)?;

    // --- Extract note_public_key + ephemeral_pubkey from deposit TX OP_RETURN ---
    let DepositOpReturn { pool_tag, ephemeral_pubkey, note_public_key } = deposit_parsed
        .find_deposit_op_return()
        .ok_or(UTXOpiaError::InvalidStealthOpReturn)?;
    if pool_tag != expected_pool_tag(program_id, pool_state_info.key(), zkbtc_mint.key()) {
        return Err(UTXOpiaError::InvalidStealthOpReturn.into());
    }

    // --- Verify sweep TX spends the exact credited deposit outpoint ---
    // A txid-only linkage is insufficient when the deposit transaction has
    // multiple outputs. Bind the sweep to the specific output that supplied the
    // user's original deposit value.
    let original_deposit_output = if direct_to_pool {
        None
    } else {
        let (output, deposit_vout) = deposit_parsed
            .find_deposit_output_with_vout()
            .ok_or(UTXOpiaError::InvalidSpvProof)?;
        if !sweep_parsed.find_input_with_prev_outpoint(&ix_data.deposit_txid, deposit_vout) {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }
        Some(output)
    };

    // Extract pool output amount and vout. In direct mode this is the user's
    // deposit output to the Ika vault. If PoolConfig is supplied, require the
    // output script to match its pool_script so the recorded UTXO is controlled
    // by the configured pool/Ika wallet.
    let (deposit_output, sweep_vout) = if accounts.len() >= 15 {
        let pool_config_info = &accounts[14];
        validate_program_owner(pool_config_info, program_id)?;
        let config_data = pool_config_info.try_borrow_data()?;
        if config_data.len() >= PoolConfig::LEN && config_data[0] == POOL_CONFIG_DISCRIMINATOR {
            let config = PoolConfig::from_bytes(&config_data)?;
            let pool_script = config.get_pool_script();
            if !pool_script.is_empty() {
                sweep_parsed
                    .find_output_by_script(pool_script)
                    .ok_or(UTXOpiaError::InvalidSpvProof)?
            } else {
                sweep_parsed
                    .find_deposit_output_with_vout()
                    .ok_or(UTXOpiaError::InvalidSpvProof)?
            }
        } else {
            return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
        }
    } else {
        sweep_parsed
            .find_deposit_output_with_vout()
            .ok_or(UTXOpiaError::InvalidSpvProof)?
    };
    let amount_sats = deposit_output.value;
    let original_deposit_sats = if direct_to_pool {
        // The SPV-verified transaction is the user deposit itself. The pool
        // output is the gross user deposit; other outputs may be wallet change.
        amount_sats
    } else {
        // Two-step sweep mode: report the original user deposit output before
        // the backend sweep miner fee reduced the pool-received amount.
        original_deposit_output
            .map(|o| o.value)
            .unwrap_or(amount_sats)
    };

    // Validate extracted amount is within bounds
    if amount_sats < min_deposit {
        return Err(UTXOpiaError::AmountTooSmall.into());
    }
    if amount_sats > max_deposit {
        return Err(UTXOpiaError::AmountTooLarge.into());
    }

    // Apply deposit fees: deposit_fee_bps (pool-level) + service_fee (per-token, BTC only)
    let protocol_fee = (amount_sats as u128 * deposit_fee_bps as u128 / 10_000) as u64;
    let total_fee = protocol_fee.checked_add(service_fee).ok_or(ProgramError::ArithmeticOverflow)?;
    let shielded_amount = amount_sats.checked_sub(total_fee).ok_or(ProgramError::ArithmeticOverflow)?;

    // Compute commitment ON-CHAIN: Poseidon(note_public_key, token_id, shielded_amount)
    // note_public_key is trustlessly extracted from the deposit TX's OP_RETURN
    let commitment = compute_commitment(&note_public_key, &token_id, shielded_amount)?;

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

    // Emit stealth announcement v2 with token_id
    let amount_bytes = shielded_amount.to_le_bytes();
    crate::utils::events::emit_stealth_announcement(
        ANNOUNCEMENT_TYPE_DEPOSIT,
        &ephemeral_pubkey,
        &amount_bytes,
        &commitment,
        leaf_index as u32,
        &token_id,
    );

    // Emit deposit verified event (BTC txids + amount + original deposit for indexer)
    crate::utils::events::emit_deposit_verified(
        &ix_data.sweep_txid,
        &ix_data.deposit_txid,
        amount_sats,
        leaf_index as u32,
        original_deposit_sats,
    );

    // Emit BTC origin attestation so third-party auditors can build their
    // own association sets without trusting our backend. Includes the
    // commitment + sweep output index so consumers don't have to re-derive
    // them from raw chain data.
    crate::utils::events::emit_btc_origin_attestation(
        ix_data.block_height,
        &ix_data.deposit_txid,
        sweep_vout,
        &commitment,
        amount_sats,
    );

    // Emit shield metadata (gross amount + Solana-side deposit fee) for indexer
    crate::utils::events::emit_shield_meta(amount_sats, total_fee, &token_id);

    // --- Create UTXO record PDA for the pool BTC output ---
    {
        let vout_le = sweep_vout.to_le_bytes();
        let utxo_seeds: &[&[u8]] = &[UtxoRecord::SEED, &ix_data.sweep_txid, &vout_le];
        let (expected_utxo_pda, utxo_bump) = find_program_address(utxo_seeds, program_id);
        if utxo_record_info.key() != &expected_utxo_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        let rent = Rent::get()?;
        let utxo_bump_bytes = [utxo_bump];
        let utxo_signer_seeds: &[&[u8]] = &[
            UtxoRecord::SEED,
            &ix_data.sweep_txid,
            &vout_le,
            &utxo_bump_bytes,
        ];

        create_pda_account(
            authority,
            utxo_record_info,
            program_id,
            rent.minimum_balance(UtxoRecord::LEN),
            UtxoRecord::LEN as u64,
            utxo_signer_seeds,
        )?;

        let mut utxo_data = utxo_record_info.try_borrow_mut_data()?;
        let utxo = UtxoRecord::init(&mut utxo_data)?;
        utxo.set_txid(&ix_data.sweep_txid);
        utxo.set_vout(sweep_vout);
        utxo.set_amount_sats(amount_sats);
        // status defaults to Unspent (0)

        crate::utils::events::emit_utxo_created(&ix_data.sweep_txid, sweep_vout, amount_sats);
    }

    // Mint zkBTC collateral to pool vault for the shielded liability only.
    // The BTC fee remainder stays in the Ika vault as protocol revenue, not as
    // a spendable private note.
    let pool_bump_bytes = [pool_bump];
    let pool_signer_seeds: &[&[u8]] = &[PoolState::SEED, &pool_bump_bytes];

    mint_zkbtc(
        token_program,
        zkbtc_mint,
        pool_vault,
        pool_state_info,
        shielded_amount,
        pool_signer_seeds,
    )?;

    // Update pool statistics
    {
        let mut pool_data = pool_state_info.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;

        pool.increment_deposit_count()?;
        pool.add_minted(shielded_amount)?;
        pool.add_shielded(shielded_amount)?;
        pool.add_utxo(amount_sats)?;
        pool.set_last_update(clock.unix_timestamp);
    }

    // Update token config: total_shielded and accumulated_fees
    {
        let mut tc_data = token_config_info.try_borrow_mut_data()?;
        let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;
        tc.add_shielded(shielded_amount)?;
        tc.add_fees(total_fee)?;
    }

    pinocchio::msg!("UTXOpia: deposit verified (SPV)");

    Ok(())
}

fn expected_pool_tag(program_id: &Pubkey, pool_state: &Pubkey, zkbtc_mint: &Pubkey) -> [u8; 8] {
    const DOMAIN: &[u8; 11] = b"UTXOPIA_SOL";
    let mut data = [0u8; 107];
    data[0..11].copy_from_slice(DOMAIN);
    data[11..43].copy_from_slice(program_id.as_ref());
    data[43..75].copy_from_slice(pool_state.as_ref());
    data[75..107].copy_from_slice(zkbtc_mint.as_ref());
    let hash = sha256(&data);
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hash[0..8]);
    tag
}
