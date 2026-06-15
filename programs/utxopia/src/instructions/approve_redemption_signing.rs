//! Approve redemption signing — pre-broadcast Ika approval.
//!
//! This is the missing first phase for Ika-backed BTC withdrawals:
//! - `mark_processing` reserves UTXO PDAs and records total input value.
//! - Backend builds the unsigned BTC transaction and computes its BIP-341 sighash.
//! - This instruction checks redemption state + policy, then CPIs to Ika
//!   `approve_message`.
//! - Backend polls the Ika MessageApproval PDA, attaches the signature, and
//!   broadcasts the BTC transaction.
//! - `complete_redemption` later SPV-verifies the broadcast tx and finalizes.

use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

use crate::constants::{
    BTC_DUST_THRESHOLD_SATS, BTC_INPUT_SEQUENCE, BTC_TX_LOCKTIME, BTC_TX_VERSION, MAX_BTC_SCRIPT_LEN,
};
use crate::cpi::ika::{
    approve_message, ApproveMessageAccounts, CPI_AUTHORITY_SEED, SIG_SCHEME_TAPROOT_SHA256,
};
use crate::error::UTXOpiaError;
use crate::state::utxo::UTXO_RECORD_DISCRIMINATOR;
use crate::state::{
    pool_config::POOL_CONFIG_DISCRIMINATOR, PoolConfig, PoolState, RedemptionRequest,
    RedemptionStatus, UtxoRecord, UtxoStatus,
};
use crate::utils::sighash::{
    canonical_sort, ika_message_digest as ika_message_digest_from_preimage,
    inputs_commitment as inputs_commitment_hash, taproot_keyspend_preimage,
    taproot_keyspend_sighash, ReservedInput, SighashInput, SighashOutput,
};
use crate::utils::{
    policy::check_redemption_signing, validate_program_owner, validate_system_program,
};

/// Number of fixed accounts before the variable-length reserved UTXO accounts.
const FIXED_ACCOUNTS: usize = 12;

/// Instruction data (after the 1-byte discriminator stripped by the dispatcher):
/// - btc_sighash:        [u8; 32] — final BIP-341 key-spend sighash (= sha256(preimage)).
///   CROSS-CHECKED against the on-chain reconstruction; not trusted as the source of truth.
/// - ika_message_digest: [u8; 32] — keccak256(TapSighash preimage), the MessageApproval key.
///   CROSS-CHECKED against the on-chain reconstruction.
/// - miner_fee_sats:     u64 LE   — backend-computed fee, bounded by policy.
/// - input_index:        u32 LE   — which input of the redemption tx this call approves.
///
/// SECURITY: the caller-supplied sighash/digest are no longer trusted. The program
/// reconstructs the BIP-341 sighash for `input_index` from the redemption's reserved
/// UTXOs + recipient script (trusted on-chain state) and requires the supplied values to
/// match. This closes the "unvalidated btc_sighash" signing-oracle hole. The previous
/// digest/scheme override fields are removed (they were the oracle).
pub struct ApproveRedemptionSigningData {
    pub btc_sighash: [u8; 32],
    pub ika_message_digest: [u8; 32],
    pub miner_fee_sats: u64,
    pub input_index: u32,
}

impl ApproveRedemptionSigningData {
    pub const LEN: usize = 32 + 32 + 8 + 4;

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut btc_sighash = [0u8; 32];
        btc_sighash.copy_from_slice(&data[..32]);
        let mut ika_message_digest = [0u8; 32];
        ika_message_digest.copy_from_slice(&data[32..64]);
        let miner_fee_sats = u64::from_le_bytes(data[64..72].try_into().unwrap());
        let input_index = u32::from_le_bytes(data[72..76].try_into().unwrap());
        Ok(Self {
            btc_sighash,
            ika_message_digest,
            miner_fee_sats,
            input_index,
        })
    }
}

/// Accounts:
/// 0.  `[]`                 Pool state
/// 1.  `[]`                 Redemption request, status must be Processing
/// 2.  `[signer]`           Pool authority
/// 3.  `[]`                 Pool config
/// 4.  `[]`                 Ika dWallet program
/// 5.  `[]`                 Ika DWalletCoordinator PDA
/// 6.  `[writable]`         Ika MessageApproval PDA
/// 7.  `[]`                 Ika dWallet account
/// 8.  `[]`                 This UTXOpia program account
/// 9.  `[]`                 CPI authority PDA, signer via invoke_signed
/// 10. `[writable, signer]` Ika payer
/// 11. `[]`                 System program
///     12..12+reserved_count `[]` Reserved UTXO record PDAs — the COMPLETE set reserved at
///     mark_processing (any order; the program canonical-sorts and checks the commitment).
///     Required so the program can reconstruct the redemption tx and re-derive the sighash.
pub fn process_approve_redemption_signing(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 12 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let ix_data = ApproveRedemptionSigningData::from_bytes(data)?;

    let pool_state_info = &accounts[0];
    let redemption_info = &accounts[1];
    let authority = &accounts[2];
    let pool_config_info = &accounts[3];
    let ika_program = &accounts[4];
    let ika_coordinator = &accounts[5];
    let ika_message_approval = &accounts[6];
    let ika_dwallet = &accounts[7];
    let caller_program = &accounts[8];
    let cpi_authority = &accounts[9];
    let ika_payer = &accounts[10];
    let system_program = &accounts[11];

    if !authority.is_signer() || !ika_payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    validate_program_owner(pool_state_info, program_id)?;
    validate_program_owner(redemption_info, program_id)?;
    validate_program_owner(pool_config_info, program_id)?;
    validate_system_program(system_program)?;

    // Capture the redemption's authoritative fields for trustless sighash reconstruction.
    let (
        amount_sats,
        service_fee,
        total_input_sats,
        reserved_count,
        inputs_commitment,
        recipient_script,
        recipient_script_len,
    ) = {
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        let redemption_data = redemption_info.try_borrow_data()?;
        let redemption = RedemptionRequest::from_bytes(&redemption_data)?;
        if redemption.get_status() != RedemptionStatus::Processing {
            return Err(UTXOpiaError::InvalidRedemptionState.into());
        }
        if redemption.total_input_sats() == 0 {
            return Err(UTXOpiaError::InvalidUtxo.into());
        }
        if redemption.reserved_count() == 0 {
            return Err(UTXOpiaError::InvalidUtxo.into());
        }

        check_redemption_signing(pool, redemption.amount_sats(), ix_data.miner_fee_sats)?;

        let script = redemption.get_btc_script();
        let mut recipient_script = [0u8; MAX_BTC_SCRIPT_LEN];
        recipient_script[..script.len()].copy_from_slice(script);
        (
            redemption.amount_sats(),
            redemption.service_fee(),
            redemption.total_input_sats(),
            redemption.reserved_count() as usize,
            *redemption.inputs_commitment(),
            recipient_script,
            script.len(),
        )
    };

    // input_index must address a real input of the reconstructed tx.
    if (ix_data.input_index as usize) >= reserved_count {
        return Err(ProgramError::InvalidInstructionData);
    }

    let (dwallet_xonly, cpi_authority_bump, pool_script, pool_script_len) = {
        let cfg_data = pool_config_info.try_borrow_data()?;
        if cfg_data.len() < PoolConfig::LEN || cfg_data[0] != POOL_CONFIG_DISCRIMINATOR {
            return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
        }
        let cfg = PoolConfig::from_bytes(&cfg_data)?;
        if !cfg.has_ika_dwallet() {
            return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
        }
        if ika_dwallet.key().as_ref() != cfg.get_ika_dwallet() {
            return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
        }
        // Pool taproot scriptPubKey (0x5120 || xonly): spent by every input AND the change output.
        let spk = cfg.get_pool_script();
        if spk.is_empty() {
            return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
        }
        let mut pool_script = [0u8; PoolConfig::MAX_SCRIPT_LEN];
        pool_script[..spk.len()].copy_from_slice(spk);
        (
            *cfg.get_ika_dwallet_xonly_pubkey(),
            cfg.get_cpi_authority_bump(),
            pool_script,
            spk.len(),
        )
    };

    if caller_program.key() != program_id || !caller_program.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !ika_program.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    if ika_dwallet.owner() != ika_program.key() || ika_coordinator.owner() != ika_program.key() {
        return Err(ProgramError::IllegalOwner);
    }
    if ika_message_approval.data_len() != 0 && ika_message_approval.owner() != ika_program.key() {
        return Err(ProgramError::IllegalOwner);
    }

    let (expected_cpi_authority, expected_cpi_authority_bump) =
        pinocchio::pubkey::find_program_address(&[CPI_AUTHORITY_SEED], program_id);
    if cpi_authority.key() != &expected_cpi_authority
        || cpi_authority_bump != expected_cpi_authority_bump
    {
        return Err(ProgramError::InvalidSeeds);
    }

    // --- Trustless BIP-341 sighash reconstruction (closes the unvalidated-sighash oracle) ---
    //
    // Rebuild the exact redemption BTC tx from trusted on-chain state and compute the
    // TapSighash preimage for `input_index`. The approved message is derived here, NOT taken
    // from the caller, so a malicious authority cannot approve a signature over an arbitrary tx.
    //
    // Inputs come from the reserved UTXO accounts (accounts[12..]); they must be exactly the
    // set committed at mark_processing (count + canonical-ordered commitment). Outputs are the
    // recipient (amount_sats - service_fee -> redemption.btc_script) and, when above dust, the
    // change back to the pool (total_input - send - miner_fee -> pool script). Tx version,
    // locktime and per-input sequence are pinned constants the backend must match.
    if accounts.len() < FIXED_ACCOUNTS + reserved_count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    // Reservation key for THIS redemption's unique PDA (audit f26).
    let reservation_key =
        crate::utils::validation::redemption_reservation_key(redemption_info.key());
    let mut reserved: std::vec::Vec<ReservedInput> = std::vec::Vec::with_capacity(reserved_count);
    let mut sum_inputs: u64 = 0;
    for j in 0..reserved_count {
        let utxo_info = &accounts[FIXED_ACCOUNTS + j];
        validate_program_owner(utxo_info, program_id)?;
        let utxo_data = utxo_info.try_borrow_data()?;
        if utxo_data.is_empty() || utxo_data[0] != UTXO_RECORD_DISCRIMINATOR {
            return Err(UTXOpiaError::InvalidUtxo.into());
        }
        let utxo = UtxoRecord::from_bytes(&utxo_data)?;
        if utxo.get_status() != UtxoStatus::Reserved {
            return Err(UTXOpiaError::UtxoNotUnspent.into());
        }
        if utxo.reserved_for_request_id() != reservation_key {
            return Err(UTXOpiaError::InvalidUtxo.into());
        }
        sum_inputs = sum_inputs
            .checked_add(utxo.amount_sats())
            .ok_or(ProgramError::ArithmeticOverflow)?;
        reserved.push(ReservedInput {
            txid: utxo.txid,
            vout: utxo.vout(),
            amount_sats: utxo.amount_sats(),
        });
    }
    if sum_inputs != total_input_sats {
        return Err(UTXOpiaError::InvalidUtxo.into());
    }

    // Pin set + order to the mark_processing commitment.
    canonical_sort(&mut reserved);
    if inputs_commitment_hash(&reserved) != inputs_commitment {
        return Err(UTXOpiaError::InvalidUtxo.into());
    }

    // Reconstruct outputs.
    let send_amount = amount_sats
        .checked_sub(service_fee)
        .ok_or(ProgramError::InvalidArgument)?;
    let change = total_input_sats
        .checked_sub(send_amount)
        .and_then(|v| v.checked_sub(ix_data.miner_fee_sats))
        .ok_or(ProgramError::InvalidArgument)?;

    let pool_spk = &pool_script[..pool_script_len];
    let mut sig_outputs: std::vec::Vec<SighashOutput> = std::vec::Vec::with_capacity(2);
    sig_outputs.push(SighashOutput {
        amount_sats: send_amount,
        script_pubkey: &recipient_script[..recipient_script_len],
    });
    if change > BTC_DUST_THRESHOLD_SATS {
        sig_outputs.push(SighashOutput {
            amount_sats: change,
            script_pubkey: pool_spk,
        });
    }

    // Reconstruct inputs in canonical order; every input spends the pool taproot spk.
    let sig_inputs: std::vec::Vec<SighashInput> = reserved
        .iter()
        .map(|r| SighashInput {
            txid: r.txid,
            vout: r.vout,
            sequence: BTC_INPUT_SEQUENCE,
            amount_sats: r.amount_sats,
            script_pubkey: pool_spk,
        })
        .collect();

    let preimage = taproot_keyspend_preimage(
        BTC_TX_VERSION,
        BTC_TX_LOCKTIME,
        &sig_inputs,
        &sig_outputs,
        ix_data.input_index,
    );
    let computed_digest = ika_message_digest_from_preimage(&preimage);
    let computed_sighash = taproot_keyspend_sighash(&preimage);

    // Cross-check the caller's claimed values against the trusted reconstruction.
    if computed_sighash != ix_data.btc_sighash || computed_digest != ix_data.ika_message_digest {
        return Err(UTXOpiaError::InvalidRedemptionState.into());
    }

    // Approve ONLY the program-derived digest (never the caller's), under Taproot-SHA256.
    let ika_message_digest = computed_digest;
    let btc_sighash = computed_sighash;
    let signature_scheme = SIG_SCHEME_TAPROOT_SHA256;

    let ma_bump = crate::cpi::ika::find_message_approval_pda_bump(
        ika_program.key(),
        &dwallet_xonly,
        &ika_message_digest,
        ika_message_approval.key(),
        signature_scheme,
    )?;

    let metadata_zero = [0u8; 32];
    let user_pubkey = btc_sighash;
    approve_message(
        ApproveMessageAccounts {
            coordinator: ika_coordinator,
            message_approval: ika_message_approval,
            dwallet: ika_dwallet,
            caller_program,
            cpi_authority,
            payer: ika_payer,
            system_program,
            dwallet_program: ika_program,
        },
        &ika_message_digest,
        &metadata_zero,
        &user_pubkey,
        signature_scheme,
        ma_bump,
        cpi_authority_bump,
    )?;

    // Mark the redemption as signing-approved so it can no longer be cancelled/re-minted:
    // a BTC payout may now be broadcastable, and cancelling would re-mint the note, enabling
    // a cross-chain double-spend.
    {
        let mut redemption_data = redemption_info.try_borrow_mut_data()?;
        let redemption = RedemptionRequest::from_bytes_mut(&mut redemption_data)?;
        redemption.set_signing_approved();
    }

    pinocchio::msg!("UTXOpia: redemption signing approved");
    Ok(())
}
