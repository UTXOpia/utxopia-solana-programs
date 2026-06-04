//! Request redemption instruction — locks zkBTC in escrow, queues BTC withdrawal
//!
//! ESCROW-BASED ARCHITECTURE:
//! - User proves ownership of commitment via ZK proof
//! - zkBTC is locked (sub_shielded) but NOT burned yet
//! - Burn happens in complete_redemption after SPV-verified BTC delivery
//! - User can cancel (cancel_redemption) while status is Pending

use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

use crate::constants::MAX_BTC_SCRIPT_LEN;

/// Minimum withdrawal amount in satoshis
const MIN_WITHDRAWAL_SATS: u64 = 10_000;
use crate::error::UTXOpiaError;
use crate::state::{
    CommitmentTree, NullifierOperationType, NullifierRecord, PoolState, TokenConfig,
    RedemptionRequest, RedemptionStatus, NULLIFIER_RECORD_DISCRIMINATOR,
    REDEMPTION_REQUEST_DISCRIMINATOR,
};
use crate::utils::{validate_program_owner, validate_system_program, validate_account_writable};

/// Request redemption instruction data (with ZK proof)
///
/// Layout:
/// - proof_hash: [u8; 32] - SHA256 hash of the ZK proof
/// - merkle_root: [u8; 32] - Current commitment tree root
/// - nullifier_hash: [u8; 32] - Nullifier to prevent double-spend
/// - amount_sats: u64 - Amount to redeem (revealed - unavoidable)
/// - vk_hash: [u8; 32] - Verification key hash (all zeros = demo mode)
/// - btc_script_len: u8
/// - btc_script: [u8; MAX_BTC_SCRIPT_LEN] - BTC withdrawal scriptPubKey (raw bytes)
/// - request_nonce: u64 - Unique nonce for this request
pub struct RequestRedemptionData {
    pub proof_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub nullifier_hash: [u8; 32],
    pub amount_sats: u64,
    pub vk_hash: [u8; 32],
    pub btc_script: [u8; MAX_BTC_SCRIPT_LEN],
    pub btc_script_len: u8,
    pub request_nonce: u64,
}

impl RequestRedemptionData {
    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        // proof_hash(32) + merkle_root(32) + nullifier_hash(32) + amount(8) + vk_hash(32)
        // + btc_script_len(1) + btc_script(variable) + request_nonce(8)
        if data.len() < 145 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(&data[0..32]);

        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&data[32..64]);

        let mut nullifier_hash = [0u8; 32];
        nullifier_hash.copy_from_slice(&data[64..96]);

        let amount_sats = u64::from_le_bytes(data[96..104].try_into().unwrap());

        let mut vk_hash = [0u8; 32];
        vk_hash.copy_from_slice(&data[104..136]);

        let btc_script_len = data[136];
        if btc_script_len as usize > MAX_BTC_SCRIPT_LEN {
            return Err(UTXOpiaError::InvalidBtcAddress.into());
        }

        let addr_end = 137 + btc_script_len as usize;
        if data.len() < addr_end + 8 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut btc_script = [0u8; MAX_BTC_SCRIPT_LEN];
        btc_script[..btc_script_len as usize].copy_from_slice(&data[137..addr_end]);

        let request_nonce = u64::from_le_bytes(data[addr_end..addr_end + 8].try_into().unwrap());

        Ok(Self {
            proof_hash,
            merkle_root,
            nullifier_hash,
            amount_sats,
            vk_hash,
            btc_script,
            btc_script_len,
            request_nonce,
        })
    }
}

/// Request redemption accounts (escrow-based — no token accounts needed)
pub struct RequestRedemptionAccounts<'a> {
    pub pool_state: &'a AccountInfo,
    pub commitment_tree: &'a AccountInfo,
    pub nullifier_record: &'a AccountInfo,
    pub redemption_request: &'a AccountInfo,
    pub user: &'a AccountInfo,
    pub system_program: &'a AccountInfo,
    pub token_config: &'a AccountInfo,
}

impl<'a> RequestRedemptionAccounts<'a> {
    pub fn from_accounts(accounts: &'a [AccountInfo]) -> Result<Self, ProgramError> {
        if accounts.len() < 7 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        let pool_state = &accounts[0];
        let commitment_tree = &accounts[1];
        let nullifier_record = &accounts[2];
        let redemption_request = &accounts[3];
        let user = &accounts[4];
        let system_program = &accounts[5];
        let token_config = &accounts[6];

        if !user.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        Ok(Self {
            pool_state,
            commitment_tree,
            nullifier_record,
            redemption_request,
            user,
            system_program,
            token_config,
        })
    }
}

/// Process redemption request (escrow-based architecture)
///
/// Locks zkBTC by decrementing total_shielded. Does NOT burn tokens.
/// Burn happens later in complete_redemption after SPV-verified BTC delivery.
pub fn process_request_redemption(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let accounts = RequestRedemptionAccounts::from_accounts(accounts)?;
    let ix_data = RequestRedemptionData::from_bytes(data)?;

    // SECURITY: Validate account owners BEFORE deserializing any data
    validate_program_owner(accounts.pool_state, program_id)?;
    validate_program_owner(accounts.commitment_tree, program_id)?;
    validate_program_owner(accounts.token_config, program_id)?;
    validate_system_program(accounts.system_program)?;

    // SECURITY: Validate writable accounts
    validate_account_writable(accounts.pool_state)?;
    validate_account_writable(accounts.nullifier_record)?;
    validate_account_writable(accounts.redemption_request)?;
    validate_account_writable(accounts.token_config)?;

    // Load and validate pool state
    let (pending_redemptions, total_shielded, withdrawal_fee_bps) = {
        let pool_data = accounts.pool_state.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }

        (
            pool.pending_redemptions(),
            pool.total_shielded(),
            pool.withdrawal_fee_bps(),
        )
    };

    // Load token config for service_fee
    let tc_service_fee = {
        let tc_data = accounts.token_config.try_borrow_data()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;
        tc.service_fee()
    };

    // Compute total fee: withdrawal_fee_bps (pool) + service_fee (token)
    let pct_fee = (ix_data.amount_sats as u128 * withdrawal_fee_bps as u128 / 10_000) as u64;
    let service_fee = pct_fee.checked_add(tc_service_fee).unwrap_or(u64::MAX);

    // Validate amount (MIN_WITHDRAWAL_SATS > 0, so zero check is implicit)
    if ix_data.amount_sats < MIN_WITHDRAWAL_SATS {
        return Err(UTXOpiaError::AmountTooSmall.into());
    }
    // min_deposit check removed — BTC withdrawals have MIN_WITHDRAWAL_SATS,
    // per-token min is validated in shield/unshield, not redemption
    // Validate amount covers service fee + dust (546 sats)
    if service_fee > 0 && ix_data.amount_sats <= service_fee + 546 {
        return Err(UTXOpiaError::AmountTooSmall.into());
    }
    if ix_data.amount_sats > total_shielded {
        return Err(UTXOpiaError::InsufficientFunds.into());
    }

    // Validate BTC address
    if ix_data.btc_script_len == 0 {
        return Err(UTXOpiaError::InvalidBtcAddress.into());
    }

    // SECURITY: Always verify root is valid in commitment tree
    {
        let tree_data = accounts.commitment_tree.try_borrow_data()?;
        let tree = CommitmentTree::from_bytes(&tree_data)?;

        if !tree.is_valid_root(&ix_data.merkle_root) {
            return Err(UTXOpiaError::InvalidRoot.into());
        }
    }

    // Verify nullifier PDA
    let nullifier_seeds: &[&[u8]] = &[NullifierRecord::SEED, &ix_data.nullifier_hash];
    let (expected_nullifier_pda, nullifier_bump) = find_program_address(nullifier_seeds, program_id);
    if accounts.nullifier_record.key() != &expected_nullifier_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Check if nullifier already spent (account already exists and initialized)
    {
        let nullifier_data = accounts.nullifier_record.try_borrow_data()?;
        if !nullifier_data.is_empty() && nullifier_data[0] == NULLIFIER_RECORD_DISCRIMINATOR {
            return Err(UTXOpiaError::NullifierAlreadyUsed.into());
        }
    }

    // Verify redemption request PDA
    let nonce_bytes = ix_data.request_nonce.to_le_bytes();
    let redemption_seeds: &[&[u8]] = &[
        RedemptionRequest::SEED,
        accounts.user.key().as_ref(),
        &nonce_bytes,
    ];
    let (expected_redemption_pda, _) = find_program_address(redemption_seeds, program_id);
    if accounts.redemption_request.key() != &expected_redemption_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Check if redemption already exists
    {
        let redemption_data = accounts.redemption_request.try_borrow_data()?;
        if !redemption_data.is_empty() && redemption_data[0] == REDEMPTION_REQUEST_DISCRIMINATOR {
            return Err(UTXOpiaError::AlreadyInitialized.into());
        }
    }

    // Get clock for timestamp
    let clock = Clock::get()?;

    // Create nullifier record account (PDA) - prevents double-spend
    let nullifier_bump_bytes = [nullifier_bump];
    let nullifier_signer_seeds: [Seed; 3] = [
        Seed::from(NullifierRecord::SEED),
        Seed::from(ix_data.nullifier_hash.as_slice()),
        Seed::from(&nullifier_bump_bytes),
    ];
    let nullifier_signer = [Signer::from(&nullifier_signer_seeds)];

    CreateAccount {
        from: accounts.user,
        to: accounts.nullifier_record,
        lamports: Rent::get()?.minimum_balance(NullifierRecord::LEN),
        space: NullifierRecord::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&nullifier_signer)?;

    // Record nullifier (prevent double-spend) — slim: discriminator only
    {
        let mut nullifier_data = accounts.nullifier_record.try_borrow_mut_data()?;
        NullifierRecord::init(&mut nullifier_data)?;
    }

    // Emit nullifier spent event (v2: trimmed — spent_at/spent_by derived from tx metadata)
    crate::utils::events::emit_nullifier_spent(
        &ix_data.nullifier_hash,
        NullifierOperationType::FullWithdrawal as u8,
        5, // instruction::REQUEST_REDEMPTION
    );

    // Create redemption request PDA
    let (_, redemption_bump) = find_program_address(
        &[RedemptionRequest::SEED, accounts.user.key().as_ref(), &nonce_bytes],
        program_id,
    );
    let redemption_bump_bytes = [redemption_bump];
    let redemption_signer_seeds: [Seed; 4] = [
        Seed::from(RedemptionRequest::SEED),
        Seed::from(accounts.user.key().as_ref()),
        Seed::from(nonce_bytes.as_slice()),
        Seed::from(&redemption_bump_bytes),
    ];
    let redemption_signer = [Signer::from(&redemption_signer_seeds)];

    CreateAccount {
        from: accounts.user,
        to: accounts.redemption_request,
        lamports: Rent::get()?.minimum_balance(RedemptionRequest::LEN),
        space: RedemptionRequest::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&redemption_signer)?;

    // Initialize redemption request
    {
        let mut redemption_data = accounts.redemption_request.try_borrow_mut_data()?;
        let redemption = RedemptionRequest::init(&mut redemption_data)?;

        redemption.set_request_id(ix_data.request_nonce);
        redemption.requester.copy_from_slice(accounts.user.key().as_ref());
        redemption.set_amount_sats(ix_data.amount_sats);
        redemption.set_service_fee(service_fee);
        redemption.set_btc_script(&ix_data.btc_script[..ix_data.btc_script_len as usize])?;
        redemption.set_status(RedemptionStatus::Pending);
    }

    // Update pool state — lock funds (sub_shielded) but do NOT burn
    {
        let mut pool_data = accounts.pool_state.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;

        pool.sub_shielded(ix_data.amount_sats)?;
        pool.set_pending_redemptions(pending_redemptions.saturating_add(1));
        pool.set_last_update(clock.unix_timestamp);
    }

    // Update token config — track shielded decrease and fee accumulation
    {
        let mut tc_data = accounts.token_config.try_borrow_mut_data()?;
        let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;
        tc.sub_shielded(ix_data.amount_sats)?;
        tc.add_fees(service_fee)?;
    }

    // Emit structured event for indexer (0x08 RedemptionRequested)
    crate::utils::events::emit_redemption_requested(
        accounts.user.key().as_ref().try_into().unwrap(),
        ix_data.amount_sats,
        ix_data.request_nonce,
        service_fee,
        0, // fee_bps passed as 0; actual computed fee is in service_fee
        &ix_data.btc_script[..ix_data.btc_script_len as usize],
    );

    pinocchio::msg!("UTXOpia: redemption requested");
    Ok(())
}
