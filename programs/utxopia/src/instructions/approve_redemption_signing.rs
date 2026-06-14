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

use crate::cpi::ika::{
    approve_message, ApproveMessageAccounts, CPI_AUTHORITY_SEED, SIG_SCHEME_TAPROOT_SHA256,
};
use crate::error::UTXOpiaError;
use crate::state::{
    pool_config::POOL_CONFIG_DISCRIMINATOR, PoolConfig, PoolState, RedemptionRequest,
    RedemptionStatus,
};
use crate::utils::{
    policy::check_redemption_signing, validate_program_owner, validate_system_program,
};

/// Instruction data:
/// - btc_sighash: [u8; 32] — BIP-341 key-spend sighash for the unsigned BTC tx
/// - ika_message_digest_override: optional [u8; 32] — exact digest Ika's signer
///   uses for MessageApproval lookup
/// - miner_fee_sats: u64 LE — backend-computed fee, bounded by policy
pub struct ApproveRedemptionSigningData {
    pub btc_sighash: [u8; 32],
    pub ika_message_digest_override: Option<[u8; 32]>,
    pub signature_scheme_override: Option<u16>,
    pub miner_fee_sats: u64,
}

impl ApproveRedemptionSigningData {
    pub const LEN: usize = 32 + 8;
    pub const LEN_WITH_IKA_DIGEST: usize = 32 + 32 + 8;
    pub const LEN_WITH_IKA_DIGEST_AND_SCHEME: usize = 32 + 32 + 2 + 8;

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != Self::LEN
            && data.len() != Self::LEN_WITH_IKA_DIGEST
            && data.len() != Self::LEN_WITH_IKA_DIGEST_AND_SCHEME
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut btc_sighash = [0u8; 32];
        btc_sighash.copy_from_slice(&data[..32]);
        let (ika_message_digest_override, signature_scheme_override, miner_fee_offset) =
            if data.len() == Self::LEN_WITH_IKA_DIGEST
                || data.len() == Self::LEN_WITH_IKA_DIGEST_AND_SCHEME
            {
                let mut digest = [0u8; 32];
                digest.copy_from_slice(&data[32..64]);
                if data.len() == Self::LEN_WITH_IKA_DIGEST_AND_SCHEME {
                    let scheme = u16::from_le_bytes(data[64..66].try_into().unwrap());
                    (Some(digest), Some(scheme), 66)
                } else {
                    (Some(digest), None, 64)
                }
            } else {
                (None, None, 32)
            };
        let miner_fee_sats = u64::from_le_bytes(
            data[miner_fee_offset..miner_fee_offset + 8]
                .try_into()
                .unwrap(),
        );
        Ok(Self {
            btc_sighash,
            ika_message_digest_override,
            signature_scheme_override,
            miner_fee_sats,
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

    {
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

        check_redemption_signing(pool, redemption.amount_sats(), ix_data.miner_fee_sats)?;
    }

    let (dwallet_xonly, cpi_authority_bump) = {
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
        (
            *cfg.get_ika_dwallet_xonly_pubkey(),
            cfg.get_cpi_authority_bump(),
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

    // We still policy-check the original BIP-341 sighash above, but Ika's
    // MessageApproval PDA is keyed by keccak256(message), where message is the
    // exact byte payload sent to gRPC Sign.
    let ika_message_digest = ix_data
        .ika_message_digest_override
        .unwrap_or_else(|| crate::utils::bitcoin::keccak256(&ix_data.btc_sighash));
    let signature_scheme = ix_data
        .signature_scheme_override
        .unwrap_or(SIG_SCHEME_TAPROOT_SHA256);

    let ma_bump = crate::cpi::ika::find_message_approval_pda_bump(
        ika_program.key(),
        &dwallet_xonly,
        &ika_message_digest,
        ika_message_approval.key(),
        signature_scheme,
    )?;

    let metadata_zero = [0u8; 32];
    let user_pubkey = ix_data.btc_sighash;
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
