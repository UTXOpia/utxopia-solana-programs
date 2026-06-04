//! Complete redemption instruction — verify BTC delivery via VerifiedTransaction PDA, burn zkBTC, close PDA
//!
//! ESCROW-BASED ARCHITECTURE:
//! - Authority provides btc_txid matching a VerifiedTransaction PDA (btc-light-client verified SPV)
//! - On-chain: parse raw tx from ChadBuffer, verify output pays correct address/amount
//! - On success: burn zkBTC from pool vault, close RedemptionRequest PDA
//! - NullifierRecord is NOT closed — it must persist forever to prevent double-spend
//!
//! UTXO TRACKING:
//! - Miner fee computed trustlessly: total_input_sats (from mark_processing UTXOs) - sum(tx_outputs)
//! - Change output creates a new UTXO PDA if pool_script matches
//! - Consumed UTXO PDAs (Reserved at mark_processing) are closed to reclaim rent

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{
    PoolConfig, PoolState, RedemptionRequest, RedemptionStatus, UtxoRecord, UtxoStatus,
    VerifiedTransactionView, light_client_tip_height,
    completion_receipt::{CompletionReceipt, COMPLETION_RECEIPT_DISCRIMINATOR},
    pool_config::POOL_CONFIG_DISCRIMINATOR,
    utxo::UTXO_RECORD_DISCRIMINATOR,
};
use crate::utils::bitcoin::{compute_tx_hash, ParsedTransaction};
use crate::utils::chadbuffer::read_transaction_from_buffer;
use crate::utils::{
    burn_zkbtc_signed, close_account_securely, create_pda_account,
    validate_account_writable, validate_program_owner,
    validate_token_owner, validate_any_token_program_key,
};
use crate::utils::policy::check_redemption_signing;

/// Required BTC confirmations before completing redemption
const REQUIRED_CONFIRMATIONS: u64 = 6;

/// Maximum fee tolerance in satoshis (allows miner fee deduction)
const MAX_FEE_SATS: u64 = 50_000;

/// Maximum consumed UTXOs per completion
const MAX_CONSUMED_UTXOS: usize = 20;

/// Complete redemption instruction data
///
/// Layout:
/// - btc_txid:             32 bytes - BTC transaction ID (internal byte order)
/// - tx_size:               4 bytes - Raw tx size in ChadBuffer
/// - pool_script_len:       1 byte  - Length of pool scriptPubKey (0 = no change tracking)
/// - pool_script:          0-34 bytes - P2TR scriptPubKey of pool address
/// - consumed_utxo_count:   1 byte  - Number of consumed UTXO PDAs in remaining accounts
pub struct CompleteRedemptionData {
    pub btc_txid: [u8; 32],
    pub tx_size: u32,
    pub pool_script_len: u8,
    pub pool_script: [u8; 34],
    pub consumed_utxo_count: u8,
}

impl CompleteRedemptionData {
    /// 32 (txid) + 4 (tx_size) + 1 (script_len) + 1 (consumed_count).
    /// `pool_script` (0..=34 bytes) sits between `script_len` and `consumed_count`.
    pub const MIN_SIZE: usize = 32 + 4 + 1 + 1;

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut btc_txid = [0u8; 32];
        btc_txid.copy_from_slice(&data[0..32]);

        let tx_size = u32::from_le_bytes(data[32..36].try_into().unwrap());

        let pool_script_len = data[36];
        let mut pool_script = [0u8; 34];

        let mut offset = 37;
        if pool_script_len > 0 {
            let end = offset + pool_script_len as usize;
            if end > data.len() || pool_script_len as usize > 34 {
                return Err(ProgramError::InvalidInstructionData);
            }
            pool_script[..pool_script_len as usize].copy_from_slice(&data[offset..end]);
            offset = end;
        }

        // consumed_utxo_count is the byte immediately following pool_script.
        if offset >= data.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        let consumed_utxo_count = data[offset];

        Ok(Self {
            btc_txid,
            tx_size,
            pool_script_len,
            pool_script,
            consumed_utxo_count,
        })
    }
}

#[cfg(test)]
mod data_tests {
    use super::*;

    fn build_ix_data(
        txid: &[u8; 32],
        tx_size: u32,
        pool_script: &[u8],
        consumed_count: u8,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(38 + pool_script.len());
        buf.extend_from_slice(txid);
        buf.extend_from_slice(&tx_size.to_le_bytes());
        buf.push(pool_script.len() as u8);
        buf.extend_from_slice(pool_script);
        buf.push(consumed_count);
        buf
    }

    #[test]
    fn parses_no_script_no_consumed() {
        let txid = [0x11u8; 32];
        let data = build_ix_data(&txid, 200, &[], 0);
        assert_eq!(data.len(), 38);
        let parsed = CompleteRedemptionData::from_bytes(&data).unwrap();
        assert_eq!(parsed.btc_txid, txid);
        assert_eq!(parsed.tx_size, 200);
        assert_eq!(parsed.pool_script_len, 0);
        assert_eq!(parsed.consumed_utxo_count, 0);
    }

    #[test]
    fn parses_with_pool_script_and_consumed_utxos() {
        let txid = [0x33u8; 32];
        let mut p2tr = vec![0x51u8, 0x20u8];
        p2tr.extend_from_slice(&[0xAAu8; 32]);
        let data = build_ix_data(&txid, 250, &p2tr, 3);
        assert_eq!(data.len(), 38 + 34);
        let parsed = CompleteRedemptionData::from_bytes(&data).unwrap();
        assert_eq!(parsed.pool_script_len, 34);
        assert_eq!(&parsed.pool_script[..34], p2tr.as_slice());
        assert_eq!(parsed.consumed_utxo_count, 3);
    }

    #[test]
    fn rejects_below_min_size() {
        let short = vec![0u8; CompleteRedemptionData::MIN_SIZE - 1];
        assert!(CompleteRedemptionData::from_bytes(&short).is_err());
    }

    #[test]
    fn rejects_missing_consumed_count() {
        let txid = [0u8; 32];
        let mut data = Vec::new();
        data.extend_from_slice(&txid);
        data.extend_from_slice(&100u32.to_le_bytes());
        data.push(0); // pool_script_len
        assert!(CompleteRedemptionData::from_bytes(&data).is_err());
    }
}

/// Process complete redemption with VerifiedTransaction PDA + output verification
///
/// # Accounts
/// 0.  `[writable]` Pool state
/// 1.  `[writable]` Redemption request
/// 2.  `[signer]`   Authority (pool authority)
/// 3.  `[]`         Rent recipient (receives lamports when PDA is closed)
/// 4.  `[]`         VerifiedTransaction PDA (owned by btc-light-client)
/// 5.  `[]`         Light client (owned by btc-light-client, for confirmation count)
/// 6.  `[]`         Transaction buffer (ChadBuffer)
/// 7.  `[writable]` zkBTC mint
/// 8.  `[writable]` Pool vault
/// 9.  `[]`         Token-2022 program
/// 10. `[writable]` Completion receipt PDA (prevents same BTC txid being used twice)
/// 11. `[]`         System program
/// 12. `[]`         Pool config PDA (stores on-chain pool_script; validates backend-provided script)
/// 13. `[writable]` Change UTXO record PDA (if change exists; else system program as placeholder)
/// 14..14+N `[writable]` Consumed UTXO PDAs (for closing, N = consumed_utxo_count)
///
pub fn process_complete_redemption(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 13 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let redemption_info = &accounts[1];
    let authority = &accounts[2];
    let rent_recipient = &accounts[3];
    let verified_tx_info = &accounts[4];
    let light_client_info = &accounts[5];
    let tx_buffer_info = &accounts[6];
    let zkbtc_mint = &accounts[7];
    let pool_vault = &accounts[8];
    let token_program = &accounts[9];
    let completion_receipt_info = &accounts[10];
    let _system_program = &accounts[11];
    let pool_config_info = &accounts[12];

    // Parse instruction data
    let ix_data = CompleteRedemptionData::from_bytes(data)?;

    // Validate signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate account owners
    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(redemption_info, program_id)?;
    validate_account_writable(completion_receipt_info)?;
    let btc_lc_id: &Pubkey = &crate::constants::BTC_LIGHT_CLIENT_PROGRAM_ID;
    validate_program_owner(verified_tx_info, btc_lc_id)?;
    validate_program_owner(light_client_info, btc_lc_id)?;
    validate_token_owner(zkbtc_mint)?;
    validate_token_owner(pool_vault)?;
    validate_any_token_program_key(token_program)?;

    // Validate writable accounts
    validate_account_writable(pool_state_info)?;
    validate_account_writable(redemption_info)?;
    validate_account_writable(zkbtc_mint)?;
    validate_account_writable(pool_vault)?;

    // Validate authority and get pool state
    let (pool_bump, pending_redemptions) = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        (pool.bump, pool.pending_redemptions())
    };

    // --- Validate pool_script against on-chain PoolConfig ---
    // Only validate if pool_script_len > 0 (change UTXO tracking requested).
    // When pool_script_len = 0, no change tracking is done and PoolConfig is not required.
    if ix_data.pool_script_len > 0 {
        validate_program_owner(pool_config_info, program_id)?;

        let config_data = pool_config_info.try_borrow_data()?;
        if config_data.len() >= PoolConfig::LEN && config_data[0] == POOL_CONFIG_DISCRIMINATOR {
            let config = PoolConfig::from_bytes(&config_data)?;
            let on_chain_script = config.get_pool_script();

            if !on_chain_script.is_empty() {
                // On-chain pool_script is set — validate ix data matches
                let ix_script = if ix_data.pool_script_len > 0 {
                    &ix_data.pool_script[..ix_data.pool_script_len as usize]
                } else {
                    &[]
                };

                if ix_script != on_chain_script {
                    pinocchio::msg!("UTXOpia: pool_script mismatch (ix data vs on-chain)");
                    return Err(UTXOpiaError::PoolScriptMismatch.into());
                }
            }
        }
    }

    // --- Completion receipt: prevent same BTC txid from completing two redemptions ---
    {
        let receipt_seeds: &[&[u8]] = &[CompletionReceipt::SEED, &ix_data.btc_txid];
        let (expected_receipt_pda, receipt_bump) = find_program_address(receipt_seeds, program_id);
        if completion_receipt_info.key() != &expected_receipt_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        // Check if this BTC txid was already used for a completion
        {
            let receipt_data = completion_receipt_info.try_borrow_data()?;
            if !receipt_data.is_empty() && receipt_data[0] == COMPLETION_RECEIPT_DISCRIMINATOR {
                pinocchio::msg!("UTXOpia: BTC txid already used for completion");
                return Err(UTXOpiaError::DuplicateDeposit.into());
            }
        }

        // Create completion receipt PDA
        let rent = Rent::get()?;
        let bump_bytes = [receipt_bump];
        let signer_seeds: &[&[u8]] = &[
            CompletionReceipt::SEED,
            &ix_data.btc_txid,
            &bump_bytes,
        ];

        create_pda_account(
            authority,
            completion_receipt_info,
            program_id,
            rent.minimum_balance(CompletionReceipt::LEN),
            CompletionReceipt::LEN as u64,
            signer_seeds,
        )?;

        let mut receipt_data = completion_receipt_info.try_borrow_mut_data()?;
        CompletionReceipt::init(&mut receipt_data)?;
    }

    // Validate redemption state (must be Pending or Processing) and get details
    let (amount_sats, service_fee, expected_script_len, expected_script, requester_key, request_id, total_input_sats) = {
        let redemption_data = redemption_info.try_borrow_data()?;
        let redemption = RedemptionRequest::from_bytes(&redemption_data)?;

        let status = redemption.get_status();
        if status != RedemptionStatus::Pending && status != RedemptionStatus::Processing {
            return Err(UTXOpiaError::InvalidRedemptionState.into());
        }

        let script = redemption.get_btc_script();
        let mut script_buf = [0u8; 62];
        let script_len = script.len();
        script_buf[..script_len].copy_from_slice(script);

        let mut req_key = [0u8; 32];
        req_key.copy_from_slice(&redemption.requester);

        (redemption.amount_sats(), redemption.service_fee(), script_len, script_buf, req_key, redemption.request_id(), redemption.total_input_sats())
    };

    // --- VerifiedTransaction PDA check ---
    let block_height = {
        let vt_data = verified_tx_info.try_borrow_data()?;
        let vt = VerifiedTransactionView::from_bytes(&vt_data)?;

        // Verify txid matches
        if *vt.txid() != ix_data.btc_txid {
            return Err(UTXOpiaError::RedemptionSpvFailed.into());
        }

        vt.block_height() as u64
    };

    // Verify sufficient confirmations
    {
        let lc_data = light_client_info.try_borrow_data()?;
        let tip = light_client_tip_height(&lc_data)?;
        let confirmations = if block_height > tip {
            0
        } else {
            tip - block_height + 1
        };
        if confirmations < REQUIRED_CONFIRMATIONS {
            return Err(UTXOpiaError::InsufficientConfirmations.into());
        }
    }

    // Read raw transaction from ChadBuffer
    crate::utils::chadbuffer::validate_chadbuffer_owner(tx_buffer_info)?;
    let buffer_data = tx_buffer_info
        .try_borrow_data()
        .map_err(|_| UTXOpiaError::RedemptionSpvFailed)?;
    let raw_tx = read_transaction_from_buffer(&buffer_data, ix_data.tx_size as usize)?;

    // Verify transaction hash matches provided txid
    let computed_hash = compute_tx_hash(raw_tx);
    if computed_hash != ix_data.btc_txid {
        return Err(UTXOpiaError::RedemptionSpvFailed.into());
    }

    // --- Output verification ---
    // Parse raw tx and verify an output pays the expected script with sufficient amount
    let parsed_tx = ParsedTransaction::parse(raw_tx)
        .map_err(|_| UTXOpiaError::RedemptionSpvFailed)?;

    let expected_script_slice = &expected_script[..expected_script_len];

    // Service fee was locked at request time in the PDA — no re-computation needed.
    // This ensures the user gets the fee they agreed to, even if pool config changes.

    // expected_send = amount_sats - service_fee (what we intended to send to user)
    let expected_send = amount_sats.saturating_sub(service_fee);
    let min_amount = expected_send.saturating_sub(MAX_FEE_SATS);

    // Find the matching output and capture the actual value sent
    let mut actual_received: u64 = 0;
    let mut found = false;
    for output in parsed_tx.outputs() {
        if output.script_pubkey == expected_script_slice && output.value >= min_amount {
            actual_received = output.value;
            found = true;
            break;
        }
    }
    if !found {
        return Err(UTXOpiaError::RedemptionOutputMismatch.into());
    }

    // --- Compute miner fee trustlessly from on-chain data ---
    // Require total_input_sats > 0: mark_processing MUST set this from UTXO PDAs.
    // Backward compat mode (total_input_sats=0) is removed — it produces incorrect
    // accounting when the signer overpays the user.
    if total_input_sats == 0 {
        return Err(UTXOpiaError::AmountTooSmall.into());
    }
    let total_outputs = parsed_tx.sum_outputs();
    let miner_fee = total_input_sats.saturating_sub(total_outputs);

    // Sanity: miner fee must not exceed MAX_FEE_SATS
    if miner_fee > MAX_FEE_SATS {
        return Err(UTXOpiaError::RedemptionOutputMismatch.into());
    }

    // --- Pure on-chain signing policy gate ---
    // Even though Ika is one entity (and pre-alpha is a single mock signer),
    // we still gate so a compromised backend cannot drain funds via forged
    // sighashes. Symmetric with the FROST signers' independent verification.
    {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        check_redemption_signing(pool, amount_sats, miner_fee)?;
    }

    let burn_amount = actual_received.saturating_add(miner_fee);
    let protocol_revenue = service_fee.saturating_sub(miner_fee);

    let bump_bytes = [pool_bump];
    let pool_signer_seeds: &[&[u8]] = &[PoolState::SEED, &bump_bytes];

    burn_zkbtc_signed(
        token_program,
        zkbtc_mint,
        pool_vault,
        pool_state_info,
        burn_amount,
        pool_signer_seeds,
    )?;

    // --- Handle change UTXO ---
    // If pool_script is provided, look for a change output in the BTC tx
    let has_change_utxo = if ix_data.pool_script_len > 0 && accounts.len() >= 14 {
        let pool_script_slice = &ix_data.pool_script[..ix_data.pool_script_len as usize];
        let change_utxo_info = &accounts[13];

        if let Some((change_output, change_vout)) = parsed_tx.find_output_by_script(pool_script_slice) {
            // Create change UTXO PDA
            let vout_le = change_vout.to_le_bytes();
            let utxo_seeds: &[&[u8]] = &[UtxoRecord::SEED, &ix_data.btc_txid, &vout_le];
            let (expected_utxo_pda, utxo_bump) = find_program_address(utxo_seeds, program_id);

            if change_utxo_info.key() != &expected_utxo_pda {
                return Err(ProgramError::InvalidSeeds);
            }

            validate_account_writable(change_utxo_info)?;

            let rent = Rent::get()?;
            let utxo_bump_bytes = [utxo_bump];
            let utxo_signer_seeds: &[&[u8]] = &[
                UtxoRecord::SEED,
                &ix_data.btc_txid,
                &vout_le,
                &utxo_bump_bytes,
            ];

            create_pda_account(
                authority,
                change_utxo_info,
                program_id,
                rent.minimum_balance(UtxoRecord::LEN),
                UtxoRecord::LEN as u64,
                utxo_signer_seeds,
            )?;

            {
                let mut utxo_data = change_utxo_info.try_borrow_mut_data()?;
                let utxo = UtxoRecord::init(&mut utxo_data)?;
                utxo.set_txid(&ix_data.btc_txid);
                utxo.set_vout(change_vout);
                utxo.set_amount_sats(change_output.value);
            }

            crate::utils::events::emit_utxo_created(&ix_data.btc_txid, change_vout, change_output.value);

            Some(change_output.value)
        } else {
            None
        }
    } else {
        None
    };

    // --- Close consumed UTXO PDAs ---
    let consumed_count = ix_data.consumed_utxo_count as usize;
    if consumed_count > MAX_CONSUMED_UTXOS {
        return Err(ProgramError::InvalidInstructionData);
    }

    let consumed_start = if ix_data.pool_script_len > 0 { 14 } else { 13 };

    if consumed_count > 0 && accounts.len() >= consumed_start + consumed_count {
        for i in 0..consumed_count {
            let consumed_utxo_info = &accounts[consumed_start + i];
            validate_program_owner(consumed_utxo_info, program_id)?;
            validate_account_writable(consumed_utxo_info)?;

            // Validate it's a UTXO record in Reserved status
            {
                let utxo_data = consumed_utxo_info.try_borrow_data()?;
                if utxo_data.is_empty() || utxo_data[0] != UTXO_RECORD_DISCRIMINATOR {
                    return Err(UTXOpiaError::InvalidUtxo.into());
                }
                let utxo = UtxoRecord::from_bytes(&utxo_data)?;
                // SECURITY: Verify UTXO is Reserved (set by mark_processing).
                // Prevents consuming Unspent UTXOs that weren't part of this withdrawal.
                if utxo.get_status() != UtxoStatus::Reserved {
                    return Err(UTXOpiaError::InvalidUtxo.into());
                }
                let amount = utxo.amount_sats();
                let vout = utxo.vout();
                let mut txid = [0u8; 32];
                txid.copy_from_slice(&utxo.txid);
                // Emit consumed event before closing
                crate::utils::events::emit_utxo_consumed(&txid, vout, amount);
            }

            // Close the UTXO account and reclaim rent
            close_account_securely(consumed_utxo_info, rent_recipient)?;
        }
    }

    // --- Update pool state with exact accounting ---
    let clock = Clock::get()?;
    {
        let mut pool_data = pool_state_info.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;

        // total_burned = actual_received + miner_fee (BTC that left the pool)
        pool.add_burned(burn_amount)?;

        // protocol_revenue = service_fee - miner_fee (net profit kept in vault)
        if protocol_revenue > 0 {
            pool.add_fee_pool(protocol_revenue)?;
        }

        // Add change UTXO to pool tracking
        if let Some(change_amount) = has_change_utxo {
            pool.add_utxo(change_amount)?;
        }

        pool.set_pending_redemptions(pending_redemptions.saturating_sub(1));
        pool.set_last_update(clock.unix_timestamp);
    }

    // --- Emit completion event (before PDA is closed) ---
    crate::utils::events::emit_redemption_completed(
        &requester_key,
        amount_sats,
        actual_received,
        service_fee,
        request_id,
        &ix_data.btc_txid,
        burn_amount,
        protocol_revenue,
        &expected_script[..expected_script_len],
    );

    // --- Close RedemptionRequest PDA ---
    close_account_securely(redemption_info, rent_recipient)?;

    pinocchio::msg!("UTXOpia: redemption completed");
    Ok(())
}
