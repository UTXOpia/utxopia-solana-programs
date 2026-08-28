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

use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError, Pubkey};
use pinocchio::{
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{
    deposit_receipt::DEPOSIT_RECEIPT_DISCRIMINATOR, light_client_tip_height,
    pool_config::POOL_CONFIG_DISCRIMINATOR, utxo::UTXO_RECORD_DISCRIMINATOR, CommitmentTree,
    DepositReceipt, PoolConfig, PoolState, TokenConfig, UtxoRecord, VerifiedTransactionView,
};
use crate::utils::bitcoin::{compute_tx_hash, sha256, DepositOpReturn, ParsedTransaction};
use crate::utils::chadbuffer::read_transaction_from_buffer;
use crate::utils::crypto::compute_commitment;
use crate::utils::events::ANNOUNCEMENT_TYPE_DEPOSIT;
use crate::utils::secp256k1::verify_taproot_output_key;
use crate::utils::{
    create_pda_account, mint_zkbtc, validate_account_writable, validate_active_tree_pda,
    validate_any_token_program_key, validate_pool_config_pda, validate_program_owner,
    validate_system_program, validate_token_owner,
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

/// Verify a note-public-key stealth deposit using VerifiedTransaction PDA (public pools only).
///
/// Trustlessly extracts note_public_key + ephemeral_pubkey from the deposit TX's OP_RETURN.
/// Verifies the sweep TX spends from the deposit TX (input linkage).
/// Computes commitment on-chain, inserts into Merkle tree, emits stealth announcement event.
///
/// Rejects permissioned pools — use disc 22 (`complete_deposit_permissioned`) for those.
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
/// 14. `[]` PoolConfig PDA (enforces sweep output is pool-controlled)
///
/// # Instruction data
/// - CompleteDepositData (80 bytes, fixed)
pub fn process_complete_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 15 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let authority = &accounts[5];

    // Authority must be signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse instruction data
    let ix_data = CompleteDepositData::from_bytes(data)?;

    // Validate authority matches pool; reject permissioned pools on this path
    validate_program_owner(pool_state_info, program_id)?;
    {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        // Public entry point must not be used for permissioned pools
        if pool.permissioned() {
            return Err(UTXOpiaError::NotPermissioned.into());
        }

        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }

        if authority.address().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    complete_deposit_inner(program_id, accounts, &ix_data, &[], &DepositBinding::OpReturn)
}

/// How a deposit's note keys are bound to the Bitcoin transaction.
///
/// Both variants end up proving the same thing — that the depositor, not the
/// caller, chose the note key — they just read it from different places.
pub enum DepositBinding {
    /// disc 11/22: the deposit tx carries an OP_RETURN with the keys, and the
    /// receipt is keyed on the txid alone.
    OpReturn,
    /// disc 25: the keys ride in instruction data, proven by the deposit
    /// address's Taproot tweak. Nothing identifies the transaction as a UTXOpia
    /// deposit on chain, so it can be funded by any wallet or exchange that can
    /// send to a P2TR address. The receipt is keyed on (txid, vout) so each
    /// output of one funding transaction is independently creditable.
    Tweak {
        ephemeral_pubkey: [u8; 32],
        note_public_key: [u8; 32],
        deposit_vout: u32,
    },
}

impl DepositBinding {
    fn deposit_vout(&self) -> Option<u32> {
        match self {
            Self::OpReturn => None,
            Self::Tweak { deposit_vout, .. } => Some(*deposit_vout),
        }
    }
}

/// The per-deposit commitment a `Tweak`-bound deposit address is bound to.
///
/// Both keys are hashed in, not just the note key. Binding the note key alone
/// would leave the ephemeral pubkey caller-chosen: the commitment (and so the
/// funds) would still be correct, but a wrong ephemeral key makes the stealth
/// announcement undecryptable and the recipient can never find their note.
pub fn tweak_commitment(note_public_key: &[u8; 32], ephemeral_pubkey: &[u8; 32]) -> [u8; 32] {
    crate::utils::bitcoin::sha256_parts([note_public_key.as_slice(), ephemeral_pubkey.as_slice()])
}

/// BIP-341's suggested NUMS point, used as the deposit address's internal key.
///
/// Nobody knows its discrete log, so the key path is unspendable and custody
/// rests entirely on the script path below. That is deliberate: Ika's MPC cannot
/// sign for a tweaked key (its own Bitcoin example says so and works around it
/// the same way), so an address whose internal key were the dWallet key plus a
/// per-deposit tweak would be unspendable by the very custodian meant to sweep
/// it. Script-path binding keeps the deposit under Ika custody from the moment
/// it confirms — no second key holds it in the meantime.
pub const DEPOSIT_NUMS_INTERNAL_KEY: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// Precomputed SHA256("TapLeaf") for BIP-341 tagged hashing.
const TAPLEAF_TAG_HASH: [u8; 32] = [
    0xae, 0xea, 0x8f, 0xdc, 0x42, 0x08, 0x98, 0x31, 0x05, 0x73, 0x4b, 0x58, 0x08, 0x1d, 0x1e, 0x26,
    0x38, 0xd3, 0x5f, 0x1c, 0xb5, 0x40, 0x08, 0xd4, 0xd3, 0x57, 0xca, 0x03, 0xbe, 0x78, 0xe9, 0xee,
];

/// Tapscript leaf version (BIP-342).
const TAPSCRIPT_LEAF_VERSION: u8 = 0xc0;

/// The single tapleaf a `Tweak`-bound deposit address commits to:
///
/// ```text
/// <commitment> OP_DROP <ika_xonly> OP_CHECKSIG
/// ```
///
/// The commitment rides in the script purely to make the leaf — and therefore
/// the address — unique per deposit; `OP_DROP` discards it at spend time. Only
/// the dWallet key can satisfy the `OP_CHECKSIG`, and it signs untweaked.
pub fn deposit_leaf_script(commitment: &[u8; 32], ika_xonly: &[u8; 32]) -> [u8; 68] {
    let mut script = [0u8; 68];
    script[0] = 0x20; // push 32 bytes
    script[1..33].copy_from_slice(commitment);
    script[33] = 0x75; // OP_DROP
    script[34] = 0x20; // push 32 bytes
    script[35..67].copy_from_slice(ika_xonly);
    script[67] = 0xac; // OP_CHECKSIG
    script
}

/// BIP-341 tapleaf hash for the script above.
///
/// `tagged_hash("TapLeaf", leaf_version || compact_size(len) || script)`. The
/// script is a fixed 68 bytes, so the compact size is always a single byte.
pub fn deposit_leaf_hash(commitment: &[u8; 32], ika_xonly: &[u8; 32]) -> [u8; 32] {
    let script = deposit_leaf_script(commitment, ika_xonly);
    crate::utils::bitcoin::sha256_parts([
        &TAPLEAF_TAG_HASH,
        &TAPLEAF_TAG_HASH,
        &[TAPSCRIPT_LEAF_VERSION, script.len() as u8],
        &script,
    ])
}

/// Instruction data for `verify_deposit` (disc 25), 148 bytes fixed.
///
/// `CompleteDepositData` (80) || ephemeral_pubkey (32) || note_public_key (32)
/// || deposit_vout (4, LE).
pub struct VerifyDepositData {
    pub base: CompleteDepositData,
    pub ephemeral_pubkey: [u8; 32],
    pub note_public_key: [u8; 32],
    pub deposit_vout: u32,
}

impl VerifyDepositData {
    pub const SIZE: usize = CompleteDepositData::HEADER_SIZE + 32 + 32 + 4;

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidInstructionData);
        }
        let base = CompleteDepositData::from_bytes(data)?;
        let mut ephemeral_pubkey = [0u8; 32];
        ephemeral_pubkey.copy_from_slice(&data[80..112]);
        let mut note_public_key = [0u8; 32];
        note_public_key.copy_from_slice(&data[112..144]);
        let deposit_vout = u32::from_le_bytes(data[144..148].try_into().unwrap());

        Ok(Self {
            base,
            ephemeral_pubkey,
            note_public_key,
            deposit_vout,
        })
    }
}

/// OP_RETURN-free deposit for public pools (disc 25).
///
/// Same accounts and same trust model as `process_complete_deposit`; the note
/// keys arrive in instruction data instead of in the deposit transaction, and
/// are proven against the deposit output's Taproot tweak rather than read from
/// an OP_RETURN. A caller cannot substitute its own keys: a different key pair
/// derives a different address, which the funding transaction did not pay.
///
/// No sweep. The deposit output's tapleaf names the pool's own dWallet key, so
/// the coins are under pool custody the moment the deposit confirms — moving them
/// to `pool_script` would transfer them from that key to that same key. The
/// SPV-verified transaction is therefore the deposit itself, and its credited
/// output is recorded directly as a pool UTXO.
///
/// That drops a miner fee and an MPC signing round from every deposit, and makes
/// the custody check cryptographic rather than a comparison against a configured
/// script.
///
/// # Instruction data
/// - `VerifyDepositData` (148 bytes, fixed)
pub fn process_verify_deposit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 15 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let authority = &accounts[5];

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let ix_data = VerifyDepositData::from_bytes(data)?;

    // No sweep: the SPV-verified transaction IS the deposit, so there is no second
    // transaction to read and `deposit_txid` must name the proven one. A caller
    // supplying a separate deposit tx is describing the old two-step flow, which
    // this instruction does not implement.
    if ix_data.base.deposit_tx_size != 0
        || ix_data.base.deposit_txid != ix_data.base.sweep_txid
    {
        return Err(ProgramError::InvalidInstructionData);
    }

    validate_program_owner(pool_state_info, program_id)?;
    {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if pool.permissioned() {
            return Err(UTXOpiaError::NotPermissioned.into());
        }

        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }

        if authority.address().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    complete_deposit_inner(
        program_id,
        accounts,
        &ix_data.base,
        &[],
        &DepositBinding::Tweak {
            ephemeral_pubkey: ix_data.ephemeral_pubkey,
            note_public_key: ix_data.note_public_key,
            deposit_vout: ix_data.deposit_vout,
        },
    )
}

/// Policy-approved OP_RETURN-free deposit for permissioned pools (disc 26).
///
/// disc 25's binding with disc 22's gate. The tapleaf already tells the two pools
/// apart — each carries its own Ika custody key, so an open-pool address simply
/// does not verify against a permissioned pool's config — but distinguishing the
/// pools is not the same as clearing the pool's policy. A permissioned pool
/// exists *for* that gate, so it is enforced here exactly as disc 22 enforces it.
///
/// Accounts: the 15 of `process_verify_deposit`, plus
/// 15. `[writable]` One-time PolicyApproval bound to this exact instruction.
/// 16. `[]` PolicyApproval program.
///
/// Instruction data:
///   `VerifyDepositData` (148 bytes) || auditor_ciphertext (variable, may be empty)
pub fn process_verify_deposit_permissioned(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 17 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let authority = &accounts[5];

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    let ix_data = VerifyDepositData::from_bytes(data)?;
    let auditor_ciphertext = &data[VerifyDepositData::SIZE..];

    // Same no-sweep shape disc 25 requires: the SPV-verified transaction IS the
    // deposit, so there is no second transaction and no separate txid.
    if ix_data.base.deposit_tx_size != 0 || ix_data.base.deposit_txid != ix_data.base.sweep_txid {
        return Err(ProgramError::InvalidInstructionData);
    }

    validate_program_owner(pool_state_info, program_id)?;
    let policy_authority = {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }

        if authority.address().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        if pool.auditor_is_frozen() {
            return Err(UTXOpiaError::AuditorFrozen.into());
        }

        // A public pool must use disc 25; routing it here would consume a policy
        // approval it never needed.
        if !pool.permissioned() {
            return Err(UTXOpiaError::NotPermissioned.into());
        }
        *pool.auditor()
    };

    crate::instructions::consume_policy_approval(
        program_id,
        &accounts[15],
        &accounts[16],
        pool_state_info,
        authority.address(),
        &policy_authority,
        crate::instruction::VERIFY_DEPOSIT_PERMISSIONED,
        // Whole payload, as disc 22 does: nothing in a deposit ages, so the
        // depositor can hold these exact bytes until the answer arrives.
        &[data],
    )?;

    complete_deposit_inner(
        program_id,
        accounts,
        &ix_data.base,
        auditor_ciphertext,
        &DepositBinding::Tweak {
            ephemeral_pubkey: ix_data.ephemeral_pubkey,
            note_public_key: ix_data.note_public_key,
            deposit_vout: ix_data.deposit_vout,
        },
    )
}

/// Policy-approved deposit for permissioned pools (disc 22).
///
/// Same accounts as `process_complete_deposit` (indices 0-14), plus one
/// appended account:
///
/// 15. `[writable]` One-time PolicyApproval bound to this exact instruction.
///
/// Instruction data layout:
///   CompleteDepositData fixed part (80 bytes) || auditor_ciphertext (variable, may be empty)
///
/// Gate logic:
/// - Pool MUST be permissioned (else InvalidInstructionData / wrong handler)
/// - Pool auditor must not be frozen (AuditorFrozen)
pub fn process_complete_deposit_permissioned(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    // Need the 15 base accounts + PolicyApproval + PolicyApproval program
    if accounts.len() < 17 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state_info = &accounts[0];
    let authority = &accounts[5];

    // Authority must be signer (same as public path — authority still pays for storage)
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse the fixed header (80 bytes); trailing bytes are auditor_ciphertext
    let ix_data = CompleteDepositData::from_bytes(data)?;
    let auditor_ciphertext = &data[CompleteDepositData::HEADER_SIZE..];

    // Validate authority + pool state; enforce permissioned gate
    validate_program_owner(pool_state_info, program_id)?;
    let policy_authority = {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if pool.is_paused() {
            return Err(UTXOpiaError::PoolPaused.into());
        }

        if authority.address().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        if pool.auditor_is_frozen() {
            return Err(UTXOpiaError::AuditorFrozen.into());
        }

        // Pool must actually be permissioned for this entry point to make sense.
        // (A non-permissioned pool should use disc 11.)
        if !pool.permissioned() {
            return Err(UTXOpiaError::NotPermissioned.into());
        }
        *pool.auditor()
    };

    crate::instructions::consume_policy_approval(
        program_id,
        &accounts[15],
        &accounts[16],
        pool_state_info,
        authority.address(),
        &policy_authority,
        crate::instruction::COMPLETE_DEPOSIT_PERMISSIONED,
        // Whole payload: nothing in a deposit ages, so the depositor can hold
        // these exact bytes until the answer arrives and never re-derive them.
        &[data],
    )?;

    complete_deposit_inner(
        program_id,
        accounts,
        &ix_data,
        auditor_ciphertext,
        &DepositBinding::OpReturn,
    )
}

/// Core deposit logic shared by both public and permissioned entry points.
///
/// Receives the pre-parsed `ix_data` and an `auditor_ciphertext` slice
/// (empty on the public path, caller-supplied on the permissioned path).
/// The auditor ciphertext is emitted as an event when non-empty.
///
/// Callers are responsible for the authority/signer gate and pool-type
/// check before calling this function.
fn complete_deposit_inner(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    ix_data: &CompleteDepositData,
    auditor_ciphertext: &[u8],
    binding: &DepositBinding,
) -> ProgramResult {
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

    // Validate account owners
    // (pool_state_info owner already validated by caller before reaching here)
    let btc_lc_id = Pubkey::new_from_array(crate::constants::BTC_LIGHT_CLIENT_PROGRAM_ID);
    validate_program_owner(verified_tx_info, &btc_lc_id)?;
    validate_program_owner(light_client_info, &btc_lc_id)?;
    validate_program_owner(commitment_tree_info, program_id)?;
    validate_token_owner(zkbtc_mint)?;
    validate_token_owner(pool_vault)?;
    validate_any_token_program_key(token_program)?;
    if !zkbtc_mint.owned_by(token_program.address())
        || !pool_vault.owned_by(token_program.address())
    {
        return Err(ProgramError::InvalidAccountOwner);
    }
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

    // Bind token_config to the mint actually being credited (prevents cross-token mint:
    // supplying another token's canonical config to mint a note under its token_id).
    {
        let tc_seeds: &[&[u8]] = &[
            TokenConfig::SEED,
            pool_state_info.address().as_ref(),
            zkbtc_mint.address().as_ref(),
        ];
        let (expected_tc_pda, _) = find_program_address(tc_seeds, program_id);
        if token_config_info.address() != &expected_tc_pda {
            return Err(UTXOpiaError::InvalidPDA.into());
        }
    }

    // Load bump + bounds + fee bps (pool already validated by caller)
    let (pool_bump, min_deposit, max_deposit, deposit_fee_bps) = {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;

        if zkbtc_mint.address().as_ref() != pool.zkbtc_mint
            || pool_vault.address().as_ref() != pool.pool_vault
        {
            return Err(UTXOpiaError::InvalidVault.into());
        }
        validate_active_tree_pda(
            commitment_tree_info,
            pool_state_info,
            program_id,
            pool.active_tree_index(),
        )?;
        (
            pool.bump,
            pool.min_deposit(),
            pool.max_deposit(),
            pool.deposit_fee_bps(),
        )
    };

    // Read token config for token_id, limits, and service fee.
    let (token_id, service_fee, token_min_deposit, token_max_deposit) = {
        let tc_data = token_config_info.try_borrow()?;
        let tc = TokenConfig::from_bytes(&tc_data)?;
        if !tc.is_enabled() {
            return Err(UTXOpiaError::TokenDisabled.into());
        }
        if tc.mint.as_ref() != zkbtc_mint.address().as_ref()
            || tc.vault.as_ref() != pool_vault.address().as_ref()
        {
            return Err(UTXOpiaError::InvalidTokenConfig.into());
        }
        (
            tc.token_id,
            tc.service_fee(),
            tc.min_deposit(),
            tc.max_deposit(),
        )
    };

    // --- Deposit receipt dedup check ---
    // Derive deposit receipt PDA from deposit_txid and verify it doesn't already exist
    {
        // Keying on the txid alone lets the first output of a funding transaction
        // block every sibling. A tweak-bound deposit names its own output, so it
        // gets a receipt per outpoint and one transaction can fund many depositors
        // (an exchange batch withdrawal is exactly that shape).
        let vout_le = binding.deposit_vout().map(|v| v.to_le_bytes());
        let seeds_with_vout;
        let seeds_txid_only;
        let receipt_seeds: &[&[u8]] = match &vout_le {
            Some(v) => {
                seeds_with_vout = [DepositReceipt::SEED, &ix_data.deposit_txid[..], &v[..]];
                &seeds_with_vout
            }
            None => {
                seeds_txid_only = [DepositReceipt::SEED, &ix_data.deposit_txid[..]];
                &seeds_txid_only
            }
        };
        let (expected_receipt_pda, receipt_bump) = find_program_address(receipt_seeds, program_id);
        if deposit_receipt_info.address() != &expected_receipt_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        // Check if deposit was already verified (account exists and initialized)
        {
            let receipt_data = deposit_receipt_info.try_borrow()?;
            if !receipt_data.is_empty() && receipt_data[0] == DEPOSIT_RECEIPT_DISCRIMINATOR {
                return Err(UTXOpiaError::DuplicateDeposit.into());
            }
        }

        // Create deposit receipt PDA to prevent future duplicates
        let rent = Rent::get()?;
        let bump_bytes = [receipt_bump];
        let signer_with_vout;
        let signer_txid_only;
        let signer_seeds: &[&[u8]] = match &vout_le {
            Some(v) => {
                signer_with_vout = [
                    DepositReceipt::SEED,
                    &ix_data.deposit_txid[..],
                    &v[..],
                    &bump_bytes[..],
                ];
                &signer_with_vout
            }
            None => {
                signer_txid_only = [
                    DepositReceipt::SEED,
                    &ix_data.deposit_txid[..],
                    &bump_bytes[..],
                ];
                &signer_txid_only
            }
        };

        create_pda_account(
            authority,
            deposit_receipt_info,
            program_id,
            rent.try_minimum_balance(DepositReceipt::LEN)?,
            DepositReceipt::LEN as u64,
            signer_seeds,
        )?;

        let mut receipt_data = deposit_receipt_info.try_borrow_mut()?;
        DepositReceipt::init(&mut receipt_data)?;
    }

    // --- VerifiedTransaction PDA check ---
    // Parse the VerifiedTransaction PDA and verify the SPV-verified txid matches.
    let vt_epoch = {
        let vt_data = verified_tx_info.try_borrow()?;
        let vt = VerifiedTransactionView::from_bytes(&vt_data)?;

        // Verify txid matches (both in internal byte order)
        if *vt.txid() != ix_data.sweep_txid {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }

        // Cross-check block height
        if vt.block_height() as u64 != ix_data.block_height {
            return Err(UTXOpiaError::InvalidBlockHeader.into());
        }

        // Pin both light-client accounts to their canonical PDAs (owner+disc alone would
        // accept any btc-light-client-owned account with a forged confirmation).
        crate::state::assert_canonical_verified_tx(
            verified_tx_info.address(),
            vt.block_hash(),
            vt.txid(),
            &btc_lc_id,
        )?;

        vt.reinit_epoch()
    };
    crate::state::assert_canonical_light_client(light_client_info.address(), &btc_lc_id)?;

    // The VerifiedTransaction proves a merkle proof was valid once; it is never invalidated.
    // Require live proof that its block is STILL canonical at that height, or a reorg that
    // orphaned the block leaves a proof that mints against a transaction no longer in the
    // chain (audit_1 F-BTC-04). Located by address, so it can be appended in any position.
    {
        let vt_data = verified_tx_info.try_borrow()?;
        let vt = VerifiedTransactionView::from_bytes(&vt_data)?;
        crate::state::assert_block_still_canonical(
            accounts,
            ix_data.block_height,
            vt.block_hash(),
            &btc_lc_id,
        )
        .map_err(|_| UTXOpiaError::InvalidSpvProof)?;
    }

    // Verify sufficient confirmations via light client tip height
    {
        let lc_data = light_client_info.try_borrow()?;
        // A regtest light client checks no proof-of-work at all, so its SPV proofs are free.
        crate::state::assert_light_client_network(&lc_data)
            .map_err(|_| UTXOpiaError::InvalidSpvProof)?;
        // Reject proofs minted under a prior light-client chain instance (see reinitialize).
        if vt_epoch != crate::state::light_client_reinit_epoch(&lc_data)? {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }
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
        .try_borrow()
        .map_err(|_| UTXOpiaError::InvalidBlockHeader)?;

    let sweep_raw_tx =
        read_transaction_from_buffer(&sweep_buffer_data, ix_data.sweep_tx_size as usize)?;

    // Verify sweep transaction hash matches sweep_txid
    let computed_sweep_hash = compute_tx_hash(sweep_raw_tx);
    if computed_sweep_hash != ix_data.sweep_txid {
        return Err(UTXOpiaError::InvalidSpvProof.into());
    }

    // Parse SPV-verified TX and extract deposit amount
    let sweep_parsed =
        ParsedTransaction::parse(sweep_raw_tx).map_err(|_| UTXOpiaError::InvalidSpvProof)?;

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
                .try_borrow()
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
    let deposit_parsed =
        ParsedTransaction::parse(deposit_raw_tx).map_err(|_| UTXOpiaError::InvalidSpvProof)?;

    // --- Note keys: from the deposit TX's OP_RETURN, or from instruction data ---
    // The tweak path needs no pool tag: the deposit address is derived from this
    // pool's own Ika key, so an address for another pool simply will not verify.
    let (ephemeral_pubkey, note_public_key) = match binding {
        DepositBinding::OpReturn => {
            let DepositOpReturn {
                pool_tag,
                ephemeral_pubkey,
                note_public_key,
            } = deposit_parsed
                .find_deposit_op_return()
                .ok_or(UTXOpiaError::InvalidStealthOpReturn)?;
            if pool_tag
                != expected_pool_tag(program_id, pool_state_info.address(), zkbtc_mint.address())
            {
                return Err(UTXOpiaError::InvalidStealthOpReturn.into());
            }
            (ephemeral_pubkey, note_public_key)
        }
        DepositBinding::Tweak {
            ephemeral_pubkey,
            note_public_key,
            ..
        } => (*ephemeral_pubkey, *note_public_key),
    };

    let pool_config_info = &accounts[14];
    validate_pool_config_pda(pool_config_info, pool_state_info, program_id)?;
    let config_data = pool_config_info.try_borrow()?;
    if config_data.len() < PoolConfig::LEN || config_data[0] != POOL_CONFIG_DISCRIMINATOR {
        return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
    }
    let config = PoolConfig::from_bytes(&config_data)?;
    let pool_script = config.get_pool_script();
    if pool_script.is_empty() {
        return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
    }

    // --- Verify sweep TX spends the exact credited deposit outpoint ---
    // A txid-only linkage is insufficient when the deposit transaction has
    // multiple outputs. Bind the sweep to the specific output that supplied the
    // user's original deposit value.
    //
    // A tweak-bound deposit takes neither branch: it has no sweep. Its tapleaf
    // names the pool's own dWallet key and nothing else can satisfy the leaf, so
    // the coins are under pool custody the moment the deposit confirms. Moving
    // them to `pool_script` would hand them from that key to that same key — a
    // hop that buys no custody, costs a miner fee, and puts an MPC signing round
    // on the busiest path in the system. It also makes the custody check
    // cryptographic (provably spendable only by the configured key) instead of a
    // string comparison against a configured script.
    let tweak_credited: Option<(u64, u32)> = match binding {
        DepositBinding::Tweak { deposit_vout, .. } => {
            let internal_key = config.get_ika_dwallet_xonly_pubkey();
            if *internal_key == [0u8; 32] {
                return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
            }

            // The caller names the output, so verify that exact one rather than
            // searching. Two outputs of one transaction may legitimately pay two
            // different depositors, each credited under its own receipt.
            let output = sweep_parsed
                .outputs()
                .nth(*deposit_vout as usize)
                .ok_or(UTXOpiaError::InvalidSpvProof)?;
            let script = output.script_pubkey;
            if output.value == 0 || script.len() != 34 || script[0] != 0x51 || script[1] != 0x20 {
                return Err(UTXOpiaError::TaprootVerificationFailed.into());
            }
            let output_key: &[u8; 32] = script[2..34]
                .try_into()
                .map_err(|_| UTXOpiaError::TaprootVerificationFailed)?;

            // Script-path binding, not a tweak of the dWallet key: the address is
            // TapTweak(NUMS, tapleaf_hash), and the leaf names both this deposit's
            // commitment and the pool's custody key. Substituting either changes
            // the leaf, and so the address the funder would have had to pay.
            //
            // `verify_taproot_output_key` already computes TapTweak(a || b), so
            // the merkle root goes in the slot a raw commitment would occupy.
            let leaf_hash = deposit_leaf_hash(
                &tweak_commitment(&note_public_key, &ephemeral_pubkey),
                internal_key,
            );
            verify_taproot_output_key(&DEPOSIT_NUMS_INTERNAL_KEY, &leaf_hash, output_key)?;
            Some((output.value, *deposit_vout))
        }
        DepositBinding::OpReturn => None,
    };

    let original_deposit_output = if direct_to_pool || tweak_credited.is_some() {
        None
    } else {
        // Batched consolidation cannot allocate one sweep miner fee across independently
        // completed deposits without additional shared accounting state. Require a one-to-one
        // sweep so minted liabilities can never exceed the actual pool output.
        if sweep_parsed.input_count() != 1 {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }
        // Bind the selected output to the note key. Selecting the first positive
        // output is unsafe because ordinary wallet change can precede the actual deposit.
        let internal_key = config.get_ika_dwallet_xonly_pubkey();
        if *internal_key == [0u8; 32] {
            return Err(UTXOpiaError::IkaCpiAccountsMissing.into());
        }

        let (output, deposit_vout) = match binding {
            DepositBinding::OpReturn => {
                let mut matched_output = None;
                for (vout, output) in deposit_parsed.outputs().enumerate() {
                    let script = output.script_pubkey;
                    if output.value == 0
                        || script.len() != 34
                        || script[0] != 0x51
                        || script[1] != 0x20
                    {
                        continue;
                    }
                    let output_key: &[u8; 32] = script[2..34]
                        .try_into()
                        .map_err(|_| UTXOpiaError::TaprootVerificationFailed)?;
                    if verify_taproot_output_key(internal_key, &note_public_key, output_key).is_ok()
                    {
                        // Multiple outputs to the same derived address are ambiguous. Refuse
                        // instead of silently choosing one and crediting a value the depositor
                        // did not intend.
                        if matched_output.is_some() {
                            return Err(UTXOpiaError::InvalidSpvProof.into());
                        }
                        matched_output = Some((output, vout as u32));
                    }
                }
                matched_output.ok_or(UTXOpiaError::TaprootVerificationFailed)?
            }
            // Handled above — a tweak-bound deposit never reaches the sweep path.
            DepositBinding::Tweak { .. } => {
                return Err(ProgramError::InvalidInstructionData)
            }
        };

        if !sweep_parsed.find_input_with_prev_outpoint(&ix_data.deposit_txid, deposit_vout) {
            return Err(UTXOpiaError::InvalidSpvProof.into());
        }
        Some(output)
    };

    // Extract the credited output's amount and vout. For the OP_RETURN paths that
    // means matching the configured pool script, so the recorded UTXO is known to
    // be under Ika custody; the tweak path proved custody from the leaf above and
    // credits the deposit output itself.
    let (pool_output_value, sweep_vout) = match tweak_credited {
        Some(credited) => credited,
        None => {
            if sweep_parsed.positive_output_count_by_script(pool_script) != 1 {
                return Err(UTXOpiaError::InvalidSpvProof.into());
            }
            let (pool_output, vout) = sweep_parsed
                .find_output_by_script(pool_script)
                .ok_or(UTXOpiaError::InvalidSpvProof)?;
            (pool_output.value, vout)
        }
    };
    let original_deposit_sats = if direct_to_pool || tweak_credited.is_some() {
        // The SPV-verified transaction is the user deposit itself. The pool
        // output is the gross user deposit; other outputs may be wallet change.
        pool_output_value
    } else {
        // Two-step sweep mode: report the original user deposit output before
        // the backend sweep miner fee reduced the pool-received amount.
        original_deposit_output
            .map(|o| o.value)
            .unwrap_or(pool_output_value)
    };

    // Credit exactly the BTC that reached pool custody. Sweep mode is restricted to one input
    // above, so this also accounts for its miner fee without cross-deposit allocation ambiguity.
    let amount_sats = pool_output_value;

    let (total_fee, shielded_amount) = validate_btc_deposit_amount_and_fee(
        amount_sats,
        min_deposit,
        max_deposit,
        token_min_deposit,
        token_max_deposit,
        deposit_fee_bps,
        service_fee,
    )?;

    // Compute commitment ON-CHAIN: Poseidon(note_public_key, token_id, shielded_amount)
    // note_public_key is trustlessly extracted from the deposit TX's OP_RETURN
    let commitment = compute_commitment(&note_public_key, &token_id, shielded_amount)?;

    // Insert commitment into Merkle tree
    let leaf_index = {
        let mut tree_data = commitment_tree_info.try_borrow_mut()?;
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

    // Emit auditor ciphertext event on the permissioned path (non-empty only)
    if !auditor_ciphertext.is_empty() {
        crate::utils::events::emit_auditor_ciphertext(&commitment, auditor_ciphertext);
    }

    // --- Record the pool BTC output as a spendable UtxoRecord ---
    // The PDA is keyed by (sweep_txid, sweep_vout), so a batched/consolidating sweep that
    // aggregates several deposits into ONE pool output maps every one of those completions to the
    // same UtxoRecord. Create it idempotently — exactly once per pool output — and record the
    // FULL `pool_output_value` (the real spendable BTC), not the per-claimant `amount_sats`.
    // Crediting per-claimant value or creating unconditionally caused the second completion of a
    // shared output to revert and understated the tracked BTC (audit batched-sweep finding).
    {
        let vout_le = sweep_vout.to_le_bytes();
        // Pool-scoped: the address itself says which pool owns this coin, so a
        // record cannot be presented to a pool that never received it.
        let utxo_seeds: &[&[u8]] = &[
            UtxoRecord::SEED,
            pool_state_info.address().as_ref(),
            &ix_data.sweep_txid,
            &vout_le,
        ];
        let (expected_utxo_pda, utxo_bump) = find_program_address(utxo_seeds, program_id);
        if utxo_record_info.address() != &expected_utxo_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        let already_recorded = {
            let d = utxo_record_info.try_borrow()?;
            !d.is_empty() && d[0] == UTXO_RECORD_DISCRIMINATOR
        };

        // A pool output may be credited exactly once, whichever mode names it. The receipt
        // dedup above cannot see across modes — sweep mode keys on `deposit_txid`, direct and
        // tweak modes on the output — so the output's own identity is what closes the gap:
        // complete once as direct(S), again as sweep(D -> S), and the two receipts are
        // different PDAs while `mint_zkbtc` below runs both times, issuing twice the custody
        // value against one real deposit (audit_2 F-DEP-01).
        //
        // This used to be conditional on the *current* call being direct or tweak mode, to let
        // sweep mode re-use a record for several deposits consolidating into one pool output.
        // That allowance was already dead: the sweep branch rejects `input_count() != 1` (see
        // above), so one sweep credits exactly one deposit and no two legitimate completions
        // can ever name the same `(sweep_txid, sweep_vout)`. Being unconditional costs nothing
        // and closes both orderings rather than only sweep-then-direct.
        if already_recorded {
            return Err(UTXOpiaError::DuplicateDeposit.into());
        }

        let rent = Rent::get()?;
        let utxo_bump_bytes = [utxo_bump];
        let utxo_signer_seeds: &[&[u8]] = &[
            UtxoRecord::SEED,
            pool_state_info.address().as_ref(),
            &ix_data.sweep_txid,
            &vout_le,
            &utxo_bump_bytes,
        ];

        // A tweak-bound deposit's UTXO sits at its own address, spendable only
        // through the tapleaf. Redemption has to rebuild that leaf, and the
        // commitment is the only half of it not already on chain — so it is
        // stored here, at credit time, or it is lost. There is no fallback:
        // the key path is a NUMS point.
        let leaf_commitment = match binding {
            DepositBinding::Tweak { .. } => {
                Some(tweak_commitment(&note_public_key, &ephemeral_pubkey))
            }
            DepositBinding::OpReturn => None,
        };
        let account_len = if leaf_commitment.is_some() {
            UtxoRecord::LEN_WITH_LEAF
        } else {
            UtxoRecord::LEN
        };

        create_pda_account(
            authority,
            utxo_record_info,
            program_id,
            rent.try_minimum_balance(account_len)?,
            account_len as u64,
            utxo_signer_seeds,
        )?;

        {
            let mut utxo_data = utxo_record_info.try_borrow_mut()?;
            let utxo = UtxoRecord::init(&mut utxo_data)?;
            utxo.set_txid(&ix_data.sweep_txid);
            utxo.set_vout(sweep_vout);
            utxo.set_amount_sats(pool_output_value);
            // status defaults to Unspent (0)

            if let Some(commitment) = leaf_commitment {
                UtxoRecord::set_leaf_commitment(&mut utxo_data, &commitment)?;
            }
        }

        // Track the spendable BTC exactly once for this pool output.
        {
            let mut pool_data = pool_state_info.try_borrow_mut()?;
            let pool = PoolState::from_bytes_mut(&mut pool_data)?;
            pool.add_utxo(pool_output_value)?;
        }

        crate::utils::events::emit_utxo_created(
            &ix_data.sweep_txid,
            sweep_vout,
            pool_output_value,
        );
    }

    // Mint zkBTC into the pool vault for the FULL deposit (shielded liability + fee).
    // The whole `amount_sats` of BTC sits in custody, so minting the gross amount keeps the
    // vault fully backed: `shielded_amount` backs the user's note and `total_fee` backs the
    // accumulated_fees credited below (claimable via claim_fees, identical to the SPL shield
    // path). Minting only `shielded_amount` while crediting `total_fee` to accumulated_fees let
    // claim_fees withdraw user-backing tokens and undercollateralize the vault (audit f15).
    let pool_bump_bytes = [pool_bump];
    let pool_signer_seeds: &[&[u8]] = &[
        PoolState::SEED,
        zkbtc_mint.address().as_ref(),
        &pool_bump_bytes,
    ];

    mint_zkbtc(
        token_program,
        zkbtc_mint,
        pool_vault,
        pool_state_info,
        amount_sats,
        pool_signer_seeds,
    )?;

    // Update token config: total_shielded and accumulated_fees
    let token_total_shielded = {
        let mut tc_data = token_config_info.try_borrow_mut()?;
        let tc = TokenConfig::from_bytes_mut(&mut tc_data)?;
        // Enforce the per-token deposit cap on every minting path, not just SPL shield (audit
        // f36): the cap is a hard exposure invariant and the bridge must honour it too.
        if tc
            .total_shielded()
            .checked_add(shielded_amount)
            .ok_or(ProgramError::ArithmeticOverflow)?
            > tc.deposit_cap()
        {
            return Err(UTXOpiaError::DepositCapExceeded.into());
        }
        tc.add_shielded(shielded_amount)?;
        tc.add_fees(total_fee)?;
        tc.total_shielded()
    };

    // Update pool statistics and reconcile legacy SPL shields from the token ledger.
    {
        let mut pool_data = pool_state_info.try_borrow_mut()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;

        pool.increment_deposit_count()?;
        // Gross amount actually minted into the vault (shielded note + claimable fee).
        pool.add_minted(amount_sats)?;
        pool.set_total_shielded(token_total_shielded);
        // NOTE: pool.add_utxo() for the spendable BTC is done once per pool output in the
        // idempotent UtxoRecord block above, using the full pool_output_value.
        pool.set_last_update(clock.unix_timestamp);
    }

    solana_program_log::log!("UTXOpia: deposit verified (SPV)");

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

fn validate_btc_deposit_amount_and_fee(
    amount_sats: u64,
    pool_min_deposit: u64,
    pool_max_deposit: u64,
    token_min_deposit: u64,
    token_max_deposit: u64,
    deposit_fee_bps: u16,
    service_fee: u64,
) -> Result<(u64, u64), ProgramError> {
    if amount_sats < pool_min_deposit {
        return Err(UTXOpiaError::AmountTooSmall.into());
    }
    if amount_sats > pool_max_deposit {
        return Err(UTXOpiaError::AmountTooLarge.into());
    }
    if amount_sats < token_min_deposit || amount_sats > token_max_deposit {
        return Err(UTXOpiaError::AmountOutOfRange.into());
    }

    let protocol_fee = crate::utils::policy::compute_bps_fee(amount_sats, deposit_fee_bps);
    let total_fee = protocol_fee
        .checked_add(service_fee)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let shielded_amount = amount_sats
        .checked_sub(total_fee)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if shielded_amount == 0 {
        return Err(UTXOpiaError::ZeroAmount.into());
    }
    Ok((total_fee, shielded_amount))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that CompleteDepositData parses exactly the 80-byte fixed header and
    /// that trailing bytes (auditor_ciphertext) are left in the slice without error.
    #[test]
    fn test_complete_deposit_data_parses_fixed_header() {
        let mut data = [0u8; 80 + 16]; // 80-byte header + 16 bytes of fake ciphertext

        // Fill sweep_txid with 0x01
        data[0..32].fill(0x01);
        // block_height = 123456 LE
        data[32..40].copy_from_slice(&123456u64.to_le_bytes());
        // sweep_tx_size = 500 LE
        data[40..44].copy_from_slice(&500u32.to_le_bytes());
        // deposit_tx_size = 250 LE
        data[44..48].copy_from_slice(&250u32.to_le_bytes());
        // deposit_txid with 0x02
        data[48..80].fill(0x02);
        // Trailing ciphertext bytes
        data[80..96].fill(0xFF);

        let ix = CompleteDepositData::from_bytes(&data).expect("should parse");
        assert_eq!(ix.sweep_txid, [0x01u8; 32]);
        assert_eq!(ix.block_height, 123456);
        assert_eq!(ix.sweep_tx_size, 500);
        assert_eq!(ix.deposit_tx_size, 250);
        assert_eq!(ix.deposit_txid, [0x02u8; 32]);

        // Auditor ciphertext is everything past the fixed header
        let ciphertext = &data[CompleteDepositData::HEADER_SIZE..];
        assert_eq!(ciphertext, &[0xFFu8; 16]);
    }

    /// Verify that data shorter than the fixed header is rejected.
    #[test]
    fn test_complete_deposit_data_rejects_short_input() {
        let short = [0u8; 79]; // one byte under the required 80
        assert!(CompleteDepositData::from_bytes(&short).is_err());
    }

    /// Verify that an empty auditor ciphertext slice (public path) is accepted
    /// and no ciphertext bytes are emitted (slice is empty).
    #[test]
    fn test_auditor_ciphertext_empty_on_public_path() {
        let data = [0u8; 80]; // exactly 80 bytes, no trailing ciphertext
        let ciphertext = &data[CompleteDepositData::HEADER_SIZE..];
        assert!(
            ciphertext.is_empty(),
            "public path must produce no ciphertext"
        );
    }

    #[test]
    fn btc_deposit_amount_must_satisfy_token_limits() {
        assert!(validate_btc_deposit_amount_and_fee(99, 1, 1_000, 100, 900, 0, 0).is_err());
        assert!(validate_btc_deposit_amount_and_fee(901, 1, 1_000, 100, 900, 0, 0).is_err());
        assert_eq!(
            validate_btc_deposit_amount_and_fee(500, 1, 1_000, 100, 900, 100, 2).unwrap(),
            (7, 493)
        );
    }

    #[test]
    fn btc_deposit_rejects_zero_value_notes_after_fees() {
        assert!(validate_btc_deposit_amount_and_fee(10, 1, 1_000, 1, 1_000, 0, 10).is_err());
    }
}

#[cfg(test)]
#[path = "verify_deposit_tests.rs"]
mod verify_deposit_tests;
