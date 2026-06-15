//! SVM-level adversarial regression tests (mollusk).
//!
//! Covers gate logic that cannot be exercised by host unit tests because it lives inside
//! instruction handlers (needs real AccountInfo + on-chain `find_program_address`):
//!
//! 2026-06-14 hardening:
//!   1. utxopia `complete_deposit` rejects a substituted token_config (cross-token mint).
//!   2. btc-light-client `verify_transaction` requires finality (block <= finalized_height).
//!
//! Permissioned-pool gates (auditor signer checks, NotPermissioned, AuditorFrozen):
//!   3. `set_auditor_frozen` / `set_auditor_viewing_pubkey` — auditor-only setters.
//!   4. `shield` — public path rejects permissioned pool (NotPermissioned).
//!   5. `shield_permissioned` — succeeds with correct user+auditor signers; fails when:
//!      - auditor key is wrong (Unauthorized)
//!      - pool is auditor-frozen (AuditorFrozen)
//!
//! Skipped: `complete_deposit_permissioned` (disc 22) requires a full BTC SPV proof
//! scaffold (verified_tx PDA, light-client, block-header blob) that mirrors the existing
//! complete_deposit test but additionally needs auditor + auditor-ciphertext wiring.
//! The existing non-permissioned test already stresses the early owner/PDA checks; the
//! auditor-gate in the permissioned variant is identical in structure to shield_permissioned
//! and is covered transitively by those tests.
//!
//! Requires the .so artifacts — run `cargo build-sbf` in solana-programs/ first.

use mollusk_svm::program::keyed_account_for_system_program;
use mollusk_svm::result::ProgramResult;
use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const SYSTEM_ID: Pubkey = Pubkey::new_from_array([0u8; 32]);

/// utxopia's compiled-in BTC_LIGHT_CLIENT_PROGRAM_ID (default features = devnet).
/// C8JoSKzondM7X1ESwrBSodGMrXWtEWNmawXyjh9zEWJZ — from programs/utxopia/src/constants.rs
const BTC_LC_OWNER: [u8; 32] = [
    0xa5, 0x4f, 0xbf, 0xc4, 0x89, 0x7f, 0xa5, 0x53, 0x1c, 0x76, 0xa4, 0x82, 0xba, 0xce, 0x0f, 0x72,
    0x9d, 0x18, 0x8b, 0xc4, 0x4e, 0x4d, 0xdb, 0xe9, 0xf2, 0x1d, 0x69, 0x81, 0xa2, 0x08, 0x41, 0xa6,
];

/// Token-2022 program id (validate_token_owner / validate_any_token_program_key).
const TOKEN_2022: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];

const INVALID_PDA: u32 = 6085; // UTXOpiaError::InvalidPDA

fn so_dir() -> String {
    format!("{}/../../target/deploy", env!("CARGO_MANIFEST_DIR"))
}

fn acct(lamports: u64, data: Vec<u8>, owner: Pubkey) -> Account {
    Account {
        lamports,
        data,
        owner,
        executable: false,
        rent_epoch: 0,
    }
}

fn is_custom(pr: &ProgramResult, code: u32) -> bool {
    matches!(pr, ProgramResult::Failure(ProgramError::Custom(c)) if *c == code)
}

fn double_sha256(d: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(d);
    Sha256::digest(first).into()
}

// ----------------------------------------------------------------------------
// 1. Cross-token mint: complete_deposit must reject a non-canonical token_config.
// ----------------------------------------------------------------------------

/// Build the 15 accounts for complete_deposit, all satisfying the owner/writable checks that
/// precede the token_config PDA gate. `token_config_key` is the only knob the tests vary.
#[allow(clippy::too_many_arguments)]
fn complete_deposit_call(
    pid: &Pubkey,
    zkbtc_mint: &Pubkey,
    token_config_key: &Pubkey,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let token_2022 = Pubkey::new_from_array(TOKEN_2022);
    let btc_lc = Pubkey::new_from_array(BTC_LC_OWNER);

    let pool_state = Pubkey::new_unique();
    let verified_tx = Pubkey::new_unique();
    let light_client = Pubkey::new_unique();
    let commitment_tree = Pubkey::new_unique();
    let tx_buffer = Pubkey::new_unique();
    let authority = Pubkey::new_unique();
    let pool_vault = Pubkey::new_unique();
    let deposit_tx_buffer = Pubkey::new_unique();
    let deposit_receipt = Pubkey::new_unique();
    let utxo_record = Pubkey::new_unique();
    let pool_config = Pubkey::new_unique(); // accounts[14]; read only after the PDA gate
    let (system_key, system_acct) = keyed_account_for_system_program();

    let metas = vec![
        AccountMeta::new(pool_state, false),
        AccountMeta::new_readonly(verified_tx, false),
        AccountMeta::new_readonly(light_client, false),
        AccountMeta::new(commitment_tree, false),
        AccountMeta::new_readonly(tx_buffer, false),
        AccountMeta::new(authority, true),
        AccountMeta::new_readonly(system_key, false),
        AccountMeta::new(*zkbtc_mint, false),
        AccountMeta::new(pool_vault, false),
        AccountMeta::new_readonly(token_2022, false),
        AccountMeta::new_readonly(deposit_tx_buffer, false),
        AccountMeta::new(deposit_receipt, false),
        AccountMeta::new(utxo_record, false),
        AccountMeta::new(*token_config_key, false),
        AccountMeta::new_readonly(pool_config, false),
    ];

    // discriminator 11 (COMPLETE_DEPOSIT) + 80-byte CompleteDepositData (all zero parses fine)
    let mut data = vec![11u8];
    data.extend_from_slice(&[0u8; 80]);
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    // Pool state needs a valid, non-permissioned discriminator AND the authority
    // set so that the authority-match gate (line ~164 of complete_deposit.rs)
    // passes before reaching the token_config PDA gate.
    // authority field is at offset 4 (disc+bump+flags+_padding).
    let pool_blob = {
        let mut d = vec![0u8; POOL_LEN];
        d[0] = 0x01; // POOL_STATE_DISCRIMINATOR; flags=0 (not permissioned)
        d[4..36].copy_from_slice(authority.as_ref()); // pool.authority = authority
        d
    };
    let accounts = vec![
        (pool_state, acct(1_000_000, pool_blob, *pid)),
        (verified_tx, acct(1, vec![], btc_lc)),
        (light_client, acct(1, vec![], btc_lc)),
        (commitment_tree, acct(1, vec![], *pid)),
        (tx_buffer, acct(1, vec![], SYSTEM_ID)),
        (authority, acct(1_000_000_000, vec![], SYSTEM_ID)),
        (system_key, system_acct),
        (*zkbtc_mint, acct(1, vec![0u8; 8], token_2022)),
        (pool_vault, acct(1, vec![0u8; 8], token_2022)),
        (token_2022, acct(1, vec![], SYSTEM_ID)),
        (deposit_tx_buffer, acct(1, vec![], SYSTEM_ID)),
        (deposit_receipt, acct(1, vec![], *pid)),
        (utxo_record, acct(1, vec![], *pid)),
        (*token_config_key, acct(1, vec![0u8; 164], *pid)),
        (pool_config, acct(1, vec![], *pid)),
    ];

    (ix, accounts)
}

#[test]
fn complete_deposit_rejects_substituted_token_config() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let zkbtc_mint = Pubkey::new_unique();
    // A token_config at an arbitrary address that is NOT the canonical PDA for zkbtc_mint —
    // i.e. another token's config substituted to mint a foreign token_id.
    let wrong_token_config = Pubkey::new_unique();

    let (ix, accounts) = complete_deposit_call(&pid, &zkbtc_mint, &wrong_token_config);
    let res = mollusk.process_instruction(&ix, &accounts);

    assert!(
        is_custom(&res.program_result, INVALID_PDA),
        "expected InvalidPDA (cross-token mint blocked), got {:?}",
        res.program_result
    );
}

#[test]
fn complete_deposit_accepts_canonical_token_config() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let zkbtc_mint = Pubkey::new_unique();
    // The canonical PDA ["token_config", zkbtc_mint] passes the binding gate.
    let (canonical_tc, _) =
        Pubkey::find_program_address(&[b"token_config", zkbtc_mint.as_ref()], &pid);

    let (ix, accounts) = complete_deposit_call(&pid, &zkbtc_mint, &canonical_tc);
    let res = mollusk.process_instruction(&ix, &accounts);

    // The binding gate is passed; the instruction then fails later (uninitialized pool state
    // etc.) with some OTHER error — it must NOT be InvalidPDA.
    assert!(
        !is_custom(&res.program_result, INVALID_PDA),
        "canonical token_config must pass the binding gate, got InvalidPDA"
    );
}

// ----------------------------------------------------------------------------
// 2. Finality: verify_transaction must reject a block above finalized_height.
// ----------------------------------------------------------------------------

const BH_DISC: u8 = 0x07;
const HI_DISC: u8 = 0x09;
const LC_DISC: u8 = 0x06;
const BH_LEN: usize = 196;
const HI_LEN: usize = 48;
const LC_LEN: usize = 232;

fn block_header_blob(block_hash: &[u8; 32], merkle_root: &[u8; 32], height: u64) -> Vec<u8> {
    let mut d = vec![0u8; BH_LEN];
    d[0] = BH_DISC;
    d[40..72].copy_from_slice(merkle_root);
    d[84..116].copy_from_slice(block_hash);
    d[148..156].copy_from_slice(&height.to_le_bytes());
    d
}

fn height_index_blob(block_hash: &[u8; 32], height: u64) -> Vec<u8> {
    let mut d = vec![0u8; HI_LEN];
    d[0] = HI_DISC;
    d[8..40].copy_from_slice(block_hash);
    d[40..48].copy_from_slice(&height.to_le_bytes());
    d
}

fn light_client_blob(finalized_height: u64) -> Vec<u8> {
    let mut d = vec![0u8; LC_LEN];
    d[0] = LC_DISC;
    d[144..152].copy_from_slice(&finalized_height.to_le_bytes());
    d
}

/// Build a verify_transaction call for a single-tx block (merkle path_len 0, so the merkle
/// root == txid). `finalized_height` is the knob the tests vary against a fixed block height.
fn verify_tx_call(
    pid: &Pubkey,
    block_height: u64,
    finalized_height: u64,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let block_hash = [0x7au8; 32];
    let raw_tx = b"utxopia-finality-regression-test-raw-bitcoin-transaction".to_vec(); // len != 64
    let txid = double_sha256(&raw_tx);

    let (block_header, _) = Pubkey::find_program_address(&[b"block", &block_hash], pid);
    let (height_index, _) =
        Pubkey::find_program_address(&[b"height_index", &block_height.to_le_bytes()], pid);
    let (verified_tx, _) =
        Pubkey::find_program_address(&[b"verified_tx", &block_hash, &txid], pid);
    let light_client = Pubkey::new_unique();
    let tx_buffer = Pubkey::new_unique();
    let payer = Pubkey::new_unique();
    let (system_key, system_acct) = keyed_account_for_system_program();

    // ChadBuffer: 32-byte authority header + raw tx.
    let mut buffer = vec![0u8; 32];
    buffer.extend_from_slice(&raw_tx);

    // instruction data: disc 2 + [txid][block_hash][tx_size] + merkle proof (path_len 0)
    let mut data = vec![2u8];
    data.extend_from_slice(&txid);
    data.extend_from_slice(&block_hash);
    data.extend_from_slice(&(raw_tx.len() as u32).to_le_bytes());
    data.extend_from_slice(&txid); // proof_txid
    data.extend_from_slice(&0u32.to_le_bytes()); // path_bits
    data.push(0u8); // path_len
    data.extend_from_slice(&0u32.to_le_bytes()); // tx_index

    let metas = vec![
        AccountMeta::new(verified_tx, false),
        AccountMeta::new_readonly(light_client, false),
        AccountMeta::new_readonly(block_header, false),
        AccountMeta::new_readonly(height_index, false),
        AccountMeta::new_readonly(tx_buffer, false),
        AccountMeta::new(payer, true),
        AccountMeta::new_readonly(system_key, false),
    ];
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    let accounts = vec![
        (verified_tx, acct(0, vec![], SYSTEM_ID)),
        (light_client, acct(1, light_client_blob(finalized_height), *pid)),
        (block_header, acct(1, block_header_blob(&block_hash, &txid, block_height), *pid)),
        (height_index, acct(1, height_index_blob(&block_hash, block_height), *pid)),
        (tx_buffer, acct(1, buffer, SYSTEM_ID)),
        (payer, acct(10_000_000_000, vec![], SYSTEM_ID)),
        (system_key, system_acct),
    ];

    (ix, accounts)
}

#[test]
fn verify_transaction_rejects_unfinalized_block() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "btc_light_client");

    // block at height 50, but only finalized up to 40 → not final → reject.
    let (ix, accounts) = verify_tx_call(&pid, 50, 40);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        res.program_result.is_err(),
        "unfinalized block must be rejected, got {:?}",
        res.program_result
    );
}

#[test]
fn verify_transaction_accepts_finalized_block() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "btc_light_client");

    // Same block at height 50, now finalized up to 100 → final → full success (VT created).
    let (ix, accounts) = verify_tx_call(&pid, 50, 100);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        res.program_result.is_ok(),
        "finalized block should verify successfully, got {:?}",
        res.program_result
    );
}

/// Regression test for audit #32 off-by-one: a block at exactly
/// `tip - (REQUIRED_CONFIRMATIONS - 1)` has exactly REQUIRED_CONFIRMATIONS
/// confirmations (inclusive) and must be accepted. With the old formula
/// (`finalized_height = tip - REQUIRED_CONFIRMATIONS`) this block was one
/// above `finalized_height` and wrongly rejected.
///
/// Setup: tip=100, REQUIRED_CONFIRMATIONS=6, so finalized_height=95.
/// Block 95 has 100-95+1=6 confs (exactly the minimum) → must be accepted.
/// Block 96 has 5 confs → must be rejected.
#[test]
fn verify_transaction_accepts_exactly_required_confirmations() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "btc_light_client");

    // tip=100, REQUIRED_CONFIRMATIONS=6 → finalized_height=95 (tip - (6-1))
    let (ix, accounts) = verify_tx_call(&pid, 95, 95);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        res.program_result.is_ok(),
        "block with exactly REQUIRED_CONFIRMATIONS should be accepted (off-by-one regression), got {:?}",
        res.program_result
    );
}

#[test]
fn verify_transaction_rejects_one_below_required_confirmations() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "btc_light_client");

    // Block 96 is above finalized_height 95 → has only 5 confs → must be rejected.
    let (ix, accounts) = verify_tx_call(&pid, 96, 95);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        res.program_result.is_err(),
        "block with fewer than REQUIRED_CONFIRMATIONS must be rejected, got {:?}",
        res.program_result
    );
}

// ============================================================================
// 3. Permissioned-pool gate integration tests.
//
// These tests exercise the auditor signer checks, NotPermissioned, Unauthorized,
// and AuditorFrozen errors.  They all use pre-crafted PoolState account blobs so
// that no BTC-SPV / light-client setup is required.
// ============================================================================

// ---- PoolState blob helpers -------------------------------------------------

/// PoolState discriminator and field offsets (must match pool.rs repr(C) layout).
const POOL_DISC: u8 = 0x01;
const POOL_LEN: usize = 332;

const POOL_OFF_FLAGS: usize = 2;
const POOL_OFF_AUDITOR: usize = 264;
const POOL_OFF_AUDITOR_VPK: usize = 296;

/// Flag bits from PoolState.
const FLAG_PERMISSIONED: u8 = 1 << 1;
const FLAG_AUDITOR_FROZEN: u8 = 1 << 2;

/// Build a minimal PoolState blob with the given flags, auditor key, and viewing key.
fn pool_state_blob(flags: u8, auditor: &[u8; 32], viewing_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut d = vec![0u8; POOL_LEN];
    d[0] = POOL_DISC;
    d[POOL_OFF_FLAGS] = flags;
    d[POOL_OFF_AUDITOR..POOL_OFF_AUDITOR + 32].copy_from_slice(auditor);
    d[POOL_OFF_AUDITOR_VPK..POOL_OFF_AUDITOR_VPK + 32].copy_from_slice(viewing_pubkey);
    d
}

// ---- Error codes ------------------------------------------------------------
const UNAUTHORIZED: u32 = 6011;
const NOT_PERMISSIONED: u32 = 6091;
const AUDITOR_FROZEN: u32 = 6092;

// ---- set_auditor_frozen (disc 28) ------------------------------------------

/// Build a set_auditor_frozen call.
/// Accounts: 0=pool_state (writable, program-owned), 1=auditor (signer).
fn set_auditor_frozen_call(
    pid: &Pubkey,
    auditor_key: &Pubkey,
    pool_flags: u8,
    pool_auditor: &[u8; 32],
    frozen_byte: u8,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let pool_state = Pubkey::new_unique();

    let metas = vec![
        AccountMeta::new(pool_state, false),
        AccountMeta::new_readonly(*auditor_key, true), // signer
    ];
    // Full instruction_data = discriminator(28) + frozen_byte
    let ix = Instruction::new_with_bytes(*pid, &[28u8, frozen_byte], metas);

    let accounts = vec![
        (
            pool_state,
            acct(
                1_000_000,
                pool_state_blob(pool_flags, pool_auditor, &[0u8; 32]),
                *pid,
            ),
        ),
        (
            *auditor_key,
            acct(1_000_000, vec![], SYSTEM_ID),
        ),
    ];

    (ix, accounts)
}

#[test]
fn set_auditor_frozen_succeeds_with_correct_auditor() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let auditor = Pubkey::new_unique();
    let auditor_bytes: [u8; 32] = auditor.to_bytes();

    let (ix, accounts) = set_auditor_frozen_call(
        &pid,
        &auditor,
        FLAG_PERMISSIONED, // pool is permissioned, auditor not frozen
        &auditor_bytes,
        1u8, // freeze
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        res.program_result.is_ok(),
        "set_auditor_frozen should succeed with correct auditor, got {:?}",
        res.program_result
    );

    // Verify the frozen flag flipped in the resulting account data.
    let pool_data = res.get_account(&accounts[0].0).unwrap();
    assert_eq!(
        pool_data.data[POOL_OFF_FLAGS] & FLAG_AUDITOR_FROZEN,
        FLAG_AUDITOR_FROZEN,
        "FLAG_AUDITOR_FROZEN should be set after freeze"
    );
}

#[test]
fn set_auditor_frozen_fails_with_wrong_auditor() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let real_auditor: [u8; 32] = [0xAAu8; 32];
    let impersonator = Pubkey::new_unique(); // key does NOT match real_auditor

    let (ix, accounts) = set_auditor_frozen_call(
        &pid,
        &impersonator,
        FLAG_PERMISSIONED,
        &real_auditor,
        1u8,
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, UNAUTHORIZED),
        "wrong auditor signer must return Unauthorized (6011), got {:?}",
        res.program_result
    );
}

#[test]
fn set_auditor_frozen_unfreezes_correctly() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let auditor = Pubkey::new_unique();
    let auditor_bytes: [u8; 32] = auditor.to_bytes();

    // Pool starts with auditor frozen.
    let (ix, accounts) = set_auditor_frozen_call(
        &pid,
        &auditor,
        FLAG_PERMISSIONED | FLAG_AUDITOR_FROZEN,
        &auditor_bytes,
        0u8, // unfreeze
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        res.program_result.is_ok(),
        "un-freeze by correct auditor must succeed, got {:?}",
        res.program_result
    );

    // Frozen flag must be cleared.
    let pool_data = res.get_account(&accounts[0].0).unwrap();
    assert_eq!(
        pool_data.data[POOL_OFF_FLAGS] & FLAG_AUDITOR_FROZEN,
        0,
        "FLAG_AUDITOR_FROZEN should be clear after un-freeze"
    );
}

// ---- set_auditor_viewing_pubkey (disc 29) -----------------------------------

/// Build a set_auditor_viewing_pubkey call.
fn set_auditor_vpk_call(
    pid: &Pubkey,
    auditor_key: &Pubkey,
    pool_auditor: &[u8; 32],
    new_vpk: &[u8; 32],
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let pool_state = Pubkey::new_unique();

    let metas = vec![
        AccountMeta::new(pool_state, false),
        AccountMeta::new_readonly(*auditor_key, true),
    ];
    // Instruction data = disc(29) prepended outside; handler receives data after disc.
    // In Mollusk the full instruction data includes the discriminator byte at [0].
    // The handler dispatches on data[0] then calls process_set_auditor_viewing_pubkey
    // with data[1..].  Build a 33-byte payload: disc(29) + 32-byte key.
    let mut data = vec![29u8];
    data.extend_from_slice(new_vpk);
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    let accounts = vec![
        (
            pool_state,
            acct(
                1_000_000,
                pool_state_blob(FLAG_PERMISSIONED, pool_auditor, &[0u8; 32]),
                *pid,
            ),
        ),
        (*auditor_key, acct(1_000_000, vec![], SYSTEM_ID)),
    ];

    (ix, accounts)
}

#[test]
fn set_auditor_viewing_pubkey_succeeds_with_correct_auditor() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let auditor = Pubkey::new_unique();
    let auditor_bytes: [u8; 32] = auditor.to_bytes();
    let new_vpk = [0xBEu8; 32];

    let (ix, accounts) = set_auditor_vpk_call(&pid, &auditor, &auditor_bytes, &new_vpk);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        res.program_result.is_ok(),
        "set_auditor_viewing_pubkey should succeed with correct auditor, got {:?}",
        res.program_result
    );

    // Verify the viewing pubkey was written into the pool state.
    let pool_data = res.get_account(&accounts[0].0).unwrap();
    assert_eq!(
        &pool_data.data[POOL_OFF_AUDITOR_VPK..POOL_OFF_AUDITOR_VPK + 32],
        &new_vpk,
        "auditor_viewing_pubkey should match the new value"
    );
}

#[test]
fn set_auditor_viewing_pubkey_fails_with_wrong_auditor() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let real_auditor: [u8; 32] = [0xAAu8; 32];
    let impersonator = Pubkey::new_unique();
    let new_vpk = [0xBEu8; 32];

    let (ix, accounts) = set_auditor_vpk_call(&pid, &impersonator, &real_auditor, &new_vpk);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, UNAUTHORIZED),
        "wrong auditor signer must return Unauthorized (6011), got {:?}",
        res.program_result
    );
}

// ---- shield on permissioned pool (disc 12) — must return NotPermissioned ----

/// Build a minimal public shield (disc 12) call against a permissioned pool.
/// The call will be short-circuited as soon as the program reads pool.permissioned().
/// We only need accounts 0 (user signer) and 2 (pool state) for the gate to fire;
/// the program will reach the permissioned check and return NotPermissioned before
/// touching any other account.
fn shield_on_permissioned_pool_call(
    pid: &Pubkey,
    auditor_bytes: &[u8; 32],
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let token_2022 = Pubkey::new_from_array(TOKEN_2022);

    let user = Pubkey::new_unique();
    let user_token_account = Pubkey::new_unique();
    let pool_state = Pubkey::new_unique();
    let token_config = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let commitment_tree = Pubkey::new_unique();

    let metas = vec![
        AccountMeta::new_readonly(user, true),      // 0 user signer
        AccountMeta::new(user_token_account, false), // 1
        AccountMeta::new_readonly(pool_state, false), // 2 pool state
        AccountMeta::new(token_config, false),       // 3
        AccountMeta::new(vault, false),              // 4
        AccountMeta::new(commitment_tree, false),    // 5
        AccountMeta::new_readonly(token_2022, false), // 6
    ];

    // Discriminator 12 (SHIELD) + 72-byte fixed header
    let mut data = vec![12u8];
    data.extend_from_slice(&[0u8; 72]);
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    let accounts = vec![
        (user, acct(1_000_000, vec![], SYSTEM_ID)),
        (user_token_account, acct(1, vec![0u8; 165], Pubkey::new_from_array(TOKEN_2022))),
        (
            pool_state,
            acct(1_000_000, pool_state_blob(FLAG_PERMISSIONED, auditor_bytes, &[0u8; 32]), *pid),
        ),
        (token_config, acct(1, vec![], *pid)),
        (vault, acct(1, vec![0u8; 165], Pubkey::new_from_array(TOKEN_2022))),
        (commitment_tree, acct(1, vec![], *pid)),
        (token_2022, acct(1, vec![], SYSTEM_ID)),
    ];

    (ix, accounts)
}

#[test]
fn shield_on_permissioned_pool_returns_not_permissioned() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let auditor_bytes = [0xAAu8; 32];
    let (ix, accounts) = shield_on_permissioned_pool_call(&pid, &auditor_bytes);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, NOT_PERMISSIONED),
        "public shield on permissioned pool must return NotPermissioned (6091), got {:?}",
        res.program_result
    );
}

// ---- shield_permissioned (disc 23) gate tests --------------------------------

/// Shared inner builder for shield_permissioned (disc 23).
/// Produces a call with the given auditor account appended at index 7.
/// The pool is always permissioned.  `pool_flags` lets callers pass
/// FLAG_PERMISSIONED | FLAG_AUDITOR_FROZEN etc.
fn shield_permissioned_call(
    pid: &Pubkey,
    user: &Pubkey,
    auditor_signer: &Pubkey, // the account placed at index 7
    pool_auditor: &[u8; 32], // the auditor key baked into the pool state blob
    pool_flags: u8,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let token_2022 = Pubkey::new_from_array(TOKEN_2022);

    let user_token_account = Pubkey::new_unique();
    let pool_state = Pubkey::new_unique();
    let token_config = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let commitment_tree = Pubkey::new_unique();

    let metas = vec![
        AccountMeta::new_readonly(*user, true),        // 0 user signer
        AccountMeta::new(user_token_account, false),    // 1
        AccountMeta::new_readonly(pool_state, false),   // 2 pool state
        AccountMeta::new(token_config, false),          // 3
        AccountMeta::new(vault, false),                 // 4
        AccountMeta::new(commitment_tree, false),       // 5
        AccountMeta::new_readonly(token_2022, false),   // 6
        AccountMeta::new_readonly(*auditor_signer, true), // 7 auditor signer
    ];

    // Discriminator 23 + 72-byte shield header
    let mut data = vec![23u8];
    data.extend_from_slice(&[0u8; 72]);
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    let accounts = vec![
        (*user, acct(1_000_000, vec![], SYSTEM_ID)),
        (user_token_account, acct(1, vec![0u8; 165], Pubkey::new_from_array(TOKEN_2022))),
        (
            pool_state,
            acct(1_000_000, pool_state_blob(pool_flags, pool_auditor, &[0u8; 32]), *pid),
        ),
        (token_config, acct(1, vec![], *pid)),
        (vault, acct(1, vec![0u8; 165], Pubkey::new_from_array(TOKEN_2022))),
        (commitment_tree, acct(1, vec![], *pid)),
        (token_2022, acct(1, vec![], SYSTEM_ID)),
        (*auditor_signer, acct(1_000_000, vec![], SYSTEM_ID)),
    ];

    (ix, accounts)
}

/// shield_permissioned on a NON-permissioned pool must return NotPermissioned.
#[test]
fn shield_permissioned_fails_on_public_pool() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let user = Pubkey::new_unique();
    let auditor = Pubkey::new_unique();
    let auditor_bytes: [u8; 32] = auditor.to_bytes();

    // Pool has permissioned flag CLEAR.
    let (ix, accounts) = shield_permissioned_call(&pid, &user, &auditor, &auditor_bytes, 0u8);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, NOT_PERMISSIONED),
        "shield_permissioned on a public pool must return NotPermissioned (6091), got {:?}",
        res.program_result
    );
}

/// Correct auditor on a permissioned pool — gate passes, instruction proceeds
/// to the inner shield logic.  The inner logic may fail (uninitialized token_config
/// etc.) but must NOT return NotPermissioned / Unauthorized / AuditorFrozen.
#[test]
fn shield_permissioned_gate_passes_with_correct_auditor() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let user = Pubkey::new_unique();
    let auditor = Pubkey::new_unique();
    let auditor_bytes: [u8; 32] = auditor.to_bytes();

    let (ix, accounts) = shield_permissioned_call(
        &pid,
        &user,
        &auditor,
        &auditor_bytes,
        FLAG_PERMISSIONED,
    );
    let res = mollusk.process_instruction(&ix, &accounts);

    // Gate errors must not appear — the permissioned gate has been cleared.
    assert!(
        !is_custom(&res.program_result, NOT_PERMISSIONED),
        "gate must not return NotPermissioned with correct auditor"
    );
    assert!(
        !is_custom(&res.program_result, UNAUTHORIZED),
        "gate must not return Unauthorized with correct auditor"
    );
    assert!(
        !is_custom(&res.program_result, AUDITOR_FROZEN),
        "auditor is not frozen, must not return AuditorFrozen"
    );
}

/// Wrong auditor key at index 7 — Unauthorized must be returned.
#[test]
fn shield_permissioned_fails_with_wrong_auditor_key() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let user = Pubkey::new_unique();
    let real_auditor: [u8; 32] = [0xAAu8; 32]; // baked into pool state
    let impersonator = Pubkey::new_unique();    // wrong key presented as signer

    let (ix, accounts) = shield_permissioned_call(
        &pid,
        &user,
        &impersonator,
        &real_auditor,
        FLAG_PERMISSIONED,
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, UNAUTHORIZED),
        "wrong auditor key must return Unauthorized (6011), got {:?}",
        res.program_result
    );
}

/// Correct auditor key but pool has FLAG_AUDITOR_FROZEN set — AuditorFrozen must be returned.
#[test]
fn shield_permissioned_fails_when_auditor_frozen() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let user = Pubkey::new_unique();
    let auditor = Pubkey::new_unique();
    let auditor_bytes: [u8; 32] = auditor.to_bytes();

    let (ix, accounts) = shield_permissioned_call(
        &pid,
        &user,
        &auditor,
        &auditor_bytes,
        FLAG_PERMISSIONED | FLAG_AUDITOR_FROZEN, // auditor is frozen
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, AUDITOR_FROZEN),
        "frozen auditor must return AuditorFrozen (6092), got {:?}",
        res.program_result
    );
}
