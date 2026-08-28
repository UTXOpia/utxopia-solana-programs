//! SVM-level adversarial regression tests (mollusk).
//!
//! Covers gate logic that cannot be exercised by host unit tests because it lives inside
//! instruction handlers (needs real AccountInfo + on-chain `find_program_address`):
//!
//! 2026-06-14 hardening:
//!   1. utxopia `complete_deposit` rejects a substituted token_config (cross-token mint).
//!   2. btc-light-client `verify_transaction` requires finality (block <= finalized_height).
//!   6. btc-light-client `extend_blockchain` rejects heavier forks whose fork point is
//!      strictly below `finalized_height` (mandatory fork-point gate, Sui parity).
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

/// utxopia's compiled-in BTC_LIGHT_CLIENT_PROGRAM_ID for the Devnet-regtest
/// artifact exercised by this suite.
///
/// NOTE: this pins the whole suite to a `cargo build-sbf --features devnet-regtest`
/// artifact. Build with any other feature and `--features devnet` selects a different
/// BTC_LIGHT_CLIENT_PROGRAM_ID, so every complete_deposit/complete_redemption test fails
/// at the owner check with a misleading InvalidAccountOwner long before its real assertion.
/// Run this suite via `bun run test:svm`, which builds the right artifact first.
const BTC_LC_OWNER: [u8; 32] = [
    0x72, 0x4d, 0xf9, 0x1e, 0xc8, 0xc4, 0x80, 0x2c, 0x6a, 0x7c, 0x00, 0x7a, 0x03, 0x44, 0x91, 0x2c,
    0x89, 0xe8, 0x73, 0x4e, 0x07, 0x71, 0x59, 0x93, 0xb3, 0x9c, 0xc3, 0xad, 0x89, 0x36, 0x61, 0x67,
];

const POLICY_PROGRAM: [u8; 32] = [
    127, 138, 197, 238, 106, 229, 114, 241, 179, 216, 130, 79, 100, 240, 58, 143, 160, 74, 31, 7,
    220, 81, 204, 120, 6, 48, 208, 221, 123, 198, 3, 214,
];

/// Token-2022 program id (validate_token_owner / validate_any_token_program_key).
const TOKEN_2022: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];

const INVALID_PDA: u32 = 6085; // UTXOpiaError::InvalidPDA
const INVALID_SPV_PROOF: u32 = 6019; // UTXOpiaError::InvalidSpvProof

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
    token_config_key: Option<&Pubkey>,
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
    let token_config_key = token_config_key.copied().unwrap_or_else(|| {
        Pubkey::find_program_address(
            &[b"token_config", pool_state.as_ref(), zkbtc_mint.as_ref()],
            pid,
        )
        .0
    });

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
        AccountMeta::new(token_config_key, false),
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
        (token_config_key, acct(1, vec![0u8; 164], *pid)),
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

    let (ix, accounts) = complete_deposit_call(&pid, &zkbtc_mint, Some(&wrong_token_config));
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
    let (ix, accounts) = complete_deposit_call(&pid, &zkbtc_mint, None);
    let res = mollusk.process_instruction(&ix, &accounts);

    // The binding gate is passed; the instruction then fails later (uninitialized pool state
    // etc.) with some OTHER error — it must NOT be InvalidPDA.
    assert!(
        !is_custom(&res.program_result, INVALID_PDA),
        "canonical token_config must pass the binding gate, got InvalidPDA"
    );
}

/// audit_1 F-BTC-04 — drive complete_deposit far enough to reach the SPV block.
///
/// The older complete_deposit fixture stops at the vault gate (custom 6081), well before any
/// SPV code runs, so the reorg check had no execution-level coverage. This builds real PDAs for
/// pool state, commitment tree, token config, deposit receipt, VerifiedTransaction and light
/// client so execution reaches `assert_block_still_canonical`.
///
/// `hi` chooses what to supply for the HeightIndex account the check looks up by address.
#[derive(Clone, Copy, PartialEq)]
enum HeightIdx {
    /// Names the same block the VerifiedTransaction does — still canonical.
    Canonical,
    /// Names a different block at that height — the reorg case.
    Reorged,
    /// Not passed at all. Must be an error, not a skipped check.
    Omitted,
}

const CT_DISC: u8 = 0x05;
const TC_DISC: u8 = 0x0B;
const VT_DISC: u8 = 0x08;

fn complete_deposit_spv_call(pid: &Pubkey, hi: HeightIdx) -> (Instruction, Vec<(Pubkey, Account)>) {
    let token_2022 = Pubkey::new_from_array(TOKEN_2022);
    let btc_lc = Pubkey::new_from_array(BTC_LC_OWNER);

    // ix_data is 80 zero bytes, so sweep_txid = [0;32], deposit_txid = [0;32], block_height = 0.
    let txid = [0u8; 32];
    let block_hash = [0x55u8; 32];
    let other_hash = [0x66u8; 32];
    let height: u64 = 0;

    let zkbtc_mint = Pubkey::new_unique();
    let (pool_state, pool_bump) =
        Pubkey::find_program_address(&[b"pool_state", zkbtc_mint.as_ref()], pid);
    let (commitment_tree, _) = Pubkey::find_program_address(
        &[b"commitment_tree", pool_state.as_ref(), &0u32.to_le_bytes()],
        pid,
    );
    let (token_config, _) = Pubkey::find_program_address(
        &[b"token_config", pool_state.as_ref(), zkbtc_mint.as_ref()],
        pid,
    );
    let (deposit_receipt, _) = Pubkey::find_program_address(&[b"deposit_receipt", &txid], pid);
    let (verified_tx, _) =
        Pubkey::find_program_address(&[b"verified_tx", &block_hash, &txid], &btc_lc);
    let (light_client, _) = Pubkey::find_program_address(&[b"btc_light_client"], &btc_lc);
    let (height_index, _) =
        Pubkey::find_program_address(&[b"height_index", &height.to_le_bytes()], &btc_lc);

    let authority = Pubkey::new_unique();
    let pool_vault = Pubkey::new_unique();
    let tx_buffer = Pubkey::new_unique();
    let deposit_tx_buffer = Pubkey::new_unique();
    let utxo_record = Pubkey::new_unique();
    let pool_config = Pubkey::new_unique();
    let (system_key, system_acct) = keyed_account_for_system_program();

    let mut metas = vec![
        AccountMeta::new(pool_state, false),
        AccountMeta::new_readonly(verified_tx, false),
        AccountMeta::new_readonly(light_client, false),
        AccountMeta::new(commitment_tree, false),
        AccountMeta::new_readonly(tx_buffer, false),
        AccountMeta::new(authority, true),
        AccountMeta::new_readonly(system_key, false),
        AccountMeta::new(zkbtc_mint, false),
        AccountMeta::new(pool_vault, false),
        AccountMeta::new_readonly(token_2022, false),
        AccountMeta::new_readonly(deposit_tx_buffer, false),
        AccountMeta::new(deposit_receipt, false),
        AccountMeta::new(utxo_record, false),
        AccountMeta::new(token_config, false),
        AccountMeta::new_readonly(pool_config, false),
    ];
    if hi != HeightIdx::Omitted {
        // Appended, not slotted at a fixed index — the check locates it by address.
        metas.push(AccountMeta::new_readonly(height_index, false));
    }

    let mut data = vec![11u8];
    data.extend_from_slice(&[0u8; 80]);
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    // PoolState: disc(0) bump(1) flags(2) _pad(3) authority(4..36) zkbtc_mint(36..68)
    // pool_vault(68..100); max_deposit(180..188) must be non-zero or the later amount check
    // would reject — it runs after the SPV block, but keep the fixture honest.
    let mut pool = vec![0u8; POOL_LEN];
    pool[0] = POOL_DISC;
    pool[1] = pool_bump;
    pool[4..36].copy_from_slice(authority.as_ref());
    pool[36..68].copy_from_slice(zkbtc_mint.as_ref());
    pool[68..100].copy_from_slice(pool_vault.as_ref());
    pool[180..188].copy_from_slice(&u64::MAX.to_le_bytes());

    // TokenConfig: disc(0) bump(1) mint(2..34) token_id(34..66) vault(66..98)
    // decimals(98) enabled(99) ... max_deposit(116..124)
    let mut tc = vec![0u8; 164];
    tc[0] = TC_DISC;
    tc[2..34].copy_from_slice(zkbtc_mint.as_ref());
    tc[66..98].copy_from_slice(pool_vault.as_ref());
    tc[99] = 1; // enabled
    tc[116..124].copy_from_slice(&u64::MAX.to_le_bytes());

    // VerifiedTransaction: disc(0) bump(1) _pad(2..4) block_height(4..8) block_hash(8..40)
    // txid(40..72) verified_at(72..80) tx_index(80..84) reinit_epoch(84..88)
    let mut vt = vec![0u8; 120];
    vt[0] = VT_DISC;
    vt[4..8].copy_from_slice(&(height as u32).to_le_bytes());
    vt[8..40].copy_from_slice(&block_hash);
    vt[40..72].copy_from_slice(&txid);

    let mut ct = vec![0u8; 64];
    ct[0] = CT_DISC;

    let mut accounts = vec![
        (pool_state, acct(1_000_000, pool, *pid)),
        (verified_tx, acct(1_000_000, vt, btc_lc)),
        (light_client, acct(1_000_000, lc_blob_for_extend(100, 100), btc_lc)),
        (commitment_tree, acct(1_000_000, ct, *pid)),
        (tx_buffer, acct(1, vec![], SYSTEM_ID)),
        (authority, acct(10_000_000_000, vec![], SYSTEM_ID)),
        (system_key, system_acct),
        (zkbtc_mint, acct(1, vec![0u8; 8], token_2022)),
        (pool_vault, acct(1, vec![0u8; 8], token_2022)),
        (token_2022, acct(1, vec![], SYSTEM_ID)),
        (deposit_tx_buffer, acct(1, vec![], SYSTEM_ID)),
        (deposit_receipt, acct(0, vec![], SYSTEM_ID)),
        (utxo_record, acct(0, vec![], SYSTEM_ID)),
        (token_config, acct(1_000_000, tc, *pid)),
        (pool_config, acct(1, vec![], *pid)),
    ];
    match hi {
        HeightIdx::Canonical => {
            accounts.push((height_index, acct(1_000_000, height_index_blob(&block_hash, height), btc_lc)))
        }
        HeightIdx::Reorged => {
            accounts.push((height_index, acct(1_000_000, height_index_blob(&other_hash, height), btc_lc)))
        }
        HeightIdx::Omitted => {}
    }

    (ix, accounts)
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
    let (verified_tx, _) = Pubkey::find_program_address(&[b"verified_tx", &block_hash, &txid], pid);
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
        (
            light_client,
            acct(1, light_client_blob(finalized_height), *pid),
        ),
        (
            block_header,
            acct(1, block_header_blob(&block_hash, &txid, block_height), *pid),
        ),
        (
            height_index,
            acct(1, height_index_blob(&block_hash, block_height), *pid),
        ),
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
const POOL_OFF_AUTHORITY: usize = 4;
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
        (*auditor_key, acct(1_000_000, vec![], SYSTEM_ID)),
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

    let (ix, accounts) =
        set_auditor_frozen_call(&pid, &impersonator, FLAG_PERMISSIONED, &real_auditor, 1u8);
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

// ---- rotate_auditor (disc 35) ----------------------------------------------

fn rotate_auditor_call(
    pid: &Pubkey,
    authority: &Pubkey,
    pool_authority: &[u8; 32],
    new_auditor: &[u8; 32],
    new_vpk: &[u8; 32],
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let pool_state = Pubkey::new_unique();
    let mut pool_data = pool_state_blob(
        FLAG_PERMISSIONED | FLAG_AUDITOR_FROZEN,
        &[0x11; 32],
        &[0x22; 32],
    );
    pool_data[POOL_OFF_AUTHORITY..POOL_OFF_AUTHORITY + 32].copy_from_slice(pool_authority);

    let mut data = vec![35u8];
    data.extend_from_slice(new_auditor);
    data.extend_from_slice(new_vpk);
    let ix = Instruction::new_with_bytes(
        *pid,
        &data,
        vec![
            AccountMeta::new(pool_state, false),
            AccountMeta::new_readonly(*authority, true),
        ],
    );
    let accounts = vec![
        (pool_state, acct(1_000_000, pool_data, *pid)),
        (*authority, acct(1_000_000, vec![], SYSTEM_ID)),
    ];
    (ix, accounts)
}

#[test]
fn rotate_auditor_atomically_recovers_permissioned_pool() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");
    let authority = Pubkey::new_unique();
    let new_auditor = [0x33; 32];
    let new_vpk = [0x44; 32];
    let (ix, accounts) = rotate_auditor_call(
        &pid,
        &authority,
        &authority.to_bytes(),
        &new_auditor,
        &new_vpk,
    );

    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        res.program_result.is_ok(),
        "rotation failed: {:?}",
        res.program_result
    );
    let pool = res.get_account(&accounts[0].0).unwrap();
    assert_eq!(
        &pool.data[POOL_OFF_AUDITOR..POOL_OFF_AUDITOR + 32],
        &new_auditor
    );
    assert_eq!(
        &pool.data[POOL_OFF_AUDITOR_VPK..POOL_OFF_AUDITOR_VPK + 32],
        &new_vpk
    );
    assert_eq!(pool.data[POOL_OFF_FLAGS] & FLAG_AUDITOR_FROZEN, 0);
}

#[test]
fn rotate_auditor_rejects_wrong_authority() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");
    let authority = Pubkey::new_unique();
    let (ix, accounts) =
        rotate_auditor_call(&pid, &authority, &[0x55; 32], &[0x33; 32], &[0x44; 32]);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(is_custom(&res.program_result, UNAUTHORIZED));
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
        AccountMeta::new_readonly(user, true),        // 0 user signer
        AccountMeta::new(user_token_account, false),  // 1
        AccountMeta::new_readonly(pool_state, false), // 2 pool state
        AccountMeta::new(token_config, false),        // 3
        AccountMeta::new(vault, false),               // 4
        AccountMeta::new(commitment_tree, false),     // 5
        AccountMeta::new_readonly(token_2022, false), // 6
    ];

    // Discriminator 12 (SHIELD) + 72-byte fixed header
    let mut data = vec![12u8];
    data.extend_from_slice(&[0u8; 72]);
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    let accounts = vec![
        (user, acct(1_000_000, vec![], SYSTEM_ID)),
        (
            user_token_account,
            acct(1, vec![0u8; 165], Pubkey::new_from_array(TOKEN_2022)),
        ),
        (
            pool_state,
            acct(
                1_000_000,
                pool_state_blob(FLAG_PERMISSIONED, auditor_bytes, &[0u8; 32]),
                *pid,
            ),
        ),
        (token_config, acct(1, vec![], *pid)),
        (
            vault,
            acct(1, vec![0u8; 165], Pubkey::new_from_array(TOKEN_2022)),
        ),
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
/// Produces a call with an invalid placeholder approval at index 7 and the
/// fixed policy program at index 8. Early pool gates run before approval
/// validation, while a valid pool proceeds to the approval owner check.
/// The pool is always permissioned.  `pool_flags` lets callers pass
/// FLAG_PERMISSIONED | FLAG_AUDITOR_FROZEN etc.
fn shield_permissioned_call(
    pid: &Pubkey,
    user: &Pubkey,
    approval: &Pubkey,
    pool_auditor: &[u8; 32], // the auditor key baked into the pool state blob
    pool_flags: u8,
    exit_registered: bool,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let token_2022 = Pubkey::new_from_array(TOKEN_2022);

    let user_token_account = Pubkey::new_unique();
    let pool_state = Pubkey::new_unique();
    let token_config = Pubkey::new_unique();
    let vault = Pubkey::new_unique();
    let commitment_tree = Pubkey::new_unique();
    let policy_program = Pubkey::new_from_array(POLICY_PROGRAM);
    let (exit_destination, exit_bump) = Pubkey::find_program_address(
        &[
            b"exit_destination",
            pool_state.as_ref(),
            &[EXIT_KIND_SOLANA_OWNER],
            user.as_ref(),
        ],
        pid,
    );

    let metas = vec![
        AccountMeta::new_readonly(*user, true),       // 0 user signer
        AccountMeta::new(user_token_account, false),  // 1
        AccountMeta::new_readonly(pool_state, false), // 2 pool state
        AccountMeta::new(token_config, false),        // 3
        AccountMeta::new(vault, false),               // 4
        AccountMeta::new(commitment_tree, false),     // 5
        AccountMeta::new_readonly(token_2022, false), // 6
        AccountMeta::new(*approval, false),           // 7 policy approval
        AccountMeta::new_readonly(policy_program, false), // 8 policy program
        AccountMeta::new_readonly(exit_destination, false), // 9 depositor's exit entry
    ];

    // Discriminator 23 + 72-byte shield header
    let mut data = vec![23u8];
    data.extend_from_slice(&[0u8; 72]);
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    let accounts = vec![
        (*user, acct(1_000_000, vec![], SYSTEM_ID)),
        (
            user_token_account,
            acct(1, vec![0u8; 165], Pubkey::new_from_array(TOKEN_2022)),
        ),
        (
            pool_state,
            acct(
                1_000_000,
                pool_state_blob(pool_flags, pool_auditor, &[0u8; 32]),
                *pid,
            ),
        ),
        (token_config, acct(1, vec![], *pid)),
        (
            vault,
            acct(1, vec![0u8; 165], Pubkey::new_from_array(TOKEN_2022)),
        ),
        (commitment_tree, acct(1, vec![], *pid)),
        (token_2022, acct(1, vec![], SYSTEM_ID)),
        (*approval, acct(1_000_000, vec![], SYSTEM_ID)),
        (
            policy_program,
            Account {
                lamports: 1,
                data: vec![],
                owner: SYSTEM_ID,
                executable: true,
                rent_epoch: 0,
            },
        ),
        (
            exit_destination,
            if exit_registered {
                acct(
                    1_000_000,
                    exit_destination_blob(exit_bump, EXIT_KIND_SOLANA_OWNER, &user.to_bytes()),
                    *pid,
                )
            } else {
                acct(0, vec![], SYSTEM_ID)
            },
        ),
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
    let (ix, accounts) = shield_permissioned_call(&pid, &user, &auditor, &auditor_bytes, 0u8, true);
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

    let (ix, accounts) =
        shield_permissioned_call(&pid, &user, &auditor, &auditor_bytes, FLAG_PERMISSIONED, true);
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

/// A placeholder not owned by the fixed policy program must fail closed.
#[test]
fn shield_permissioned_fails_with_invalid_policy_approval() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let user = Pubkey::new_unique();
    let real_auditor: [u8; 32] = [0xAAu8; 32];
    let invalid_approval = Pubkey::new_unique();

    let (ix, accounts) = shield_permissioned_call(
        &pid,
        &user,
        &invalid_approval,
        &real_auditor,
        FLAG_PERMISSIONED,
        true,
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, 6026),
        "invalid approval owner must fail closed (6026), got {:?}",
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
        true,
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, AUDITOR_FROZEN),
        "frozen auditor must return AuditorFrozen (6092), got {:?}",
        res.program_result
    );
}

// ============================================================================
// 6. extend_blockchain mandatory fork-point gate (Sui parity).
//
// Regression test for the below-finality reorg vulnerability: a heavier fork
// whose parent is STRICTLY BELOW `finalized_height` must be rejected by
// `extend_blockchain` regardless of accumulated chainwork.  A fork whose parent
// is AT `finalized_height` must pass the gate (it can only rewrite heights >=
// finalized_height+1 which have not yet been finalized).
//
// Both tests use NETWORK_REGTEST (3) so PoW / difficulty checks are skipped;
// the light client's `total_chainwork` is set to zero so any submitted block
// becomes the heavier chain (is_new_canonical = true).
// ============================================================================

/// Discriminator / layout constants (mirror the program's repr(C) structs).
const LC_NETWORK_OFFSET: usize = 3; // BitcoinLightClient.network
const LC_TIP_HEIGHT_OFFSET: usize = 136; // BitcoinLightClient.tip_height  [u8;8]
                                         // LC_FINALIZED_HEIGHT_OFFSET = 144 (already declared as the literal in light_client_blob)

const BH_BLOCK_HASH_OFFSET: usize = 84; // BlockHeader.block_hash  [u8;32]
const BH_HEIGHT_OFFSET: usize = 148; // BlockHeader.height      [u8;8]

const NETWORK_REGTEST: u8 = 3;

/// Build a BitcoinLightClient account blob for `extend_blockchain` tests.
/// `network` must be NETWORK_REGTEST (3) so PoW is skipped.
/// `total_chainwork` is left zero so any submitted block becomes canonical.
fn lc_blob_for_extend(tip_height: u64, finalized_height: u64) -> Vec<u8> {
    let mut d = vec![0u8; LC_LEN];
    d[0] = LC_DISC;
    d[LC_NETWORK_OFFSET] = NETWORK_REGTEST;
    // total_chainwork stays all-zero → any positive work beats it
    d[LC_TIP_HEIGHT_OFFSET..LC_TIP_HEIGHT_OFFSET + 8].copy_from_slice(&tip_height.to_le_bytes());
    d[144..152].copy_from_slice(&finalized_height.to_le_bytes());
    // reinit_epoch = 0 (default); parent header must also carry 0
    d
}

/// Build a BlockHeader account blob for a parent at the given height.
/// `block_hash` is the 32-byte value stored in the `block_hash` field (what the
/// instruction reads as `parent_hash`).  `reinit_epoch = 0` matches the LC blob.
fn parent_block_header_blob(block_hash: &[u8; 32], height: u64) -> Vec<u8> {
    let mut d = vec![0u8; BH_LEN];
    d[0] = BH_DISC;
    d[BH_BLOCK_HASH_OFFSET..BH_BLOCK_HASH_OFFSET + 32].copy_from_slice(block_hash);
    d[BH_HEIGHT_OFFSET..BH_HEIGHT_OFFSET + 8].copy_from_slice(&height.to_le_bytes());
    // chainwork stays zero; reinit_epoch (at offset 172) stays zero
    d
}

/// Craft an 80-byte regtest block header whose `prev_hash` field (bytes 4..36)
/// equals `parent_hash` and whose timestamp is 0 (passes the future-drift check).
/// Returns both the raw header bytes and the resulting block hash (double-SHA256).
fn make_raw_header(parent_hash: &[u8; 32]) -> ([u8; 80], [u8; 32]) {
    let mut raw = [0u8; 80];
    // version = 1 (bytes 0..4)
    raw[0] = 1;
    // prev_hash (bytes 4..36)
    raw[4..36].copy_from_slice(parent_hash);
    // merkle_root (bytes 36..68): all zero
    // timestamp (bytes 68..72): 0 → passes clock check
    // bits (bytes 72..76): 0x207fffff — regtest pow_limit.
    let bits: u32 = 0x207f_ffff;
    raw[72..76].copy_from_slice(&bits.to_le_bytes());
    // nonce (bytes 76..80): 0
    let block_hash = double_sha256(&raw);
    (raw, block_hash)
}

/// Build a complete `extend_blockchain` (disc 1) call for a single-block batch.
///
/// Accounts (6 total, matching expected_accounts = 4 + 2*1):
///   0  light_client_info   (writable, owned by pid)
///   1  submitter           (signer, writable)
///   2  system_program
///   3  parent_header_info  (read, owned by pid, PDA ["block", parent_hash])
///   4  block_header_info   (writable, empty, PDA ["block", new_block_hash])
///   5  height_index_info   (writable, empty, PDA ["height_index", parent_height+1])
///
/// The parent is placed at `parent_height`; the light-client's `finalized_height`
/// is the `finalized` argument.
/// What to supply for the mandatory parent-HeightIndex account (audit_1 F-BTC-03).
#[derive(Clone, Copy, PartialEq)]
enum ParentHi {
    /// The real thing: HeightIndex[parent_height].block_hash == parent_hash.
    Canonical,
    /// Parent is NOT the canonical block at its height — what a fork block staged by an
    /// earlier, non-canonical batch looks like. Must be rejected.
    Mismatched,
    /// The PDA exists as a bare system account — the only thing an attacker can actually pass
    /// for a fork block, since the non-canonical branch never creates a HeightIndex.
    Uninitialized,
    /// Account omitted entirely — the pre-fix caller. Must now be NotEnoughAccountKeys.
    Omitted,
}

fn extend_blockchain_call(
    pid: &Pubkey,
    parent_height: u64,
    finalized: u64,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    extend_blockchain_call_with(pid, parent_height, finalized, ParentHi::Canonical)
}

fn extend_blockchain_call_with(
    pid: &Pubkey,
    parent_height: u64,
    finalized: u64,
    parent_hi: ParentHi,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let parent_hash = [0x42u8; 32]; // arbitrary deterministic value
    let (raw_header, new_block_hash) = make_raw_header(&parent_hash);

    // Derive PDAs using the same program_id the runtime will use
    let (parent_pda, _) = Pubkey::find_program_address(&[b"block", &parent_hash], pid);
    let (block_pda, _) = Pubkey::find_program_address(&[b"block", &new_block_hash], pid);
    let new_height = parent_height + 1;
    let (hi_pda, _) =
        Pubkey::find_program_address(&[b"height_index", &new_height.to_le_bytes()], pid);

    let light_client = Pubkey::new_unique();
    let submitter = Pubkey::new_unique();
    let (system_key, system_acct) = keyed_account_for_system_program();

    // Instruction data: disc(1) + num_headers(1) + 80 bytes
    let mut data = vec![1u8]; // discriminator
    data.push(1u8); // num_headers = 1
    data.extend_from_slice(&raw_header);

    let mut metas = vec![
        AccountMeta::new(light_client, false),
        AccountMeta::new(submitter, true),
        AccountMeta::new_readonly(system_key, false),
        AccountMeta::new_readonly(parent_pda, false),
        AccountMeta::new(block_pda, false),
        AccountMeta::new(hi_pda, false),
    ];
    // Mandatory trailing account at index expected_accounts + num_ancestors = 6 + 0.
    let (parent_hi_pda, _) =
        Pubkey::find_program_address(&[b"height_index", &parent_height.to_le_bytes()], pid);
    if parent_hi != ParentHi::Omitted {
        metas.push(AccountMeta::new_readonly(parent_hi_pda, false));
    }
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    // tip_height of the LC doesn't affect the fork-point gate; set it equal to
    // parent_height so the existing chain looks like it ends there.
    let lc_data = lc_blob_for_extend(parent_height, finalized);
    let parent_bh_data = parent_block_header_blob(&parent_hash, parent_height);

    let mut accounts = vec![
        (light_client, acct(10_000_000_000, lc_data, *pid)),
        (submitter, acct(10_000_000_000, vec![], SYSTEM_ID)),
        (system_key, system_acct),
        (parent_pda, acct(1_000_000, parent_bh_data, *pid)),
        // New block header and height_index start empty (will be created by the program)
        (block_pda, acct(0, vec![], SYSTEM_ID)),
        (hi_pda, acct(0, vec![], SYSTEM_ID)),
    ];
    match parent_hi {
        ParentHi::Canonical => accounts.push((
            parent_hi_pda,
            acct(1_000_000, height_index_blob(&parent_hash, parent_height), *pid),
        )),
        ParentHi::Mismatched => accounts.push((
            parent_hi_pda,
            acct(
                1_000_000,
                height_index_blob(&[0x99u8; 32], parent_height),
                *pid,
            ),
        )),
        ParentHi::Uninitialized => {
            accounts.push((parent_hi_pda, acct(0, vec![], SYSTEM_ID)))
        }
        ParentHi::Omitted => {}
    }

    (ix, accounts)
}

/// Regression: a heavier fork whose parent is STRICTLY BELOW `finalized_height`
/// must be rejected with InvalidArgument (the mandatory fork-point gate).
///
/// Setup: finalized_height=10, parent_height=5 → parent_height < finalized → REJECT.
#[test]
fn extend_blockchain_rejects_fork_below_finality() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "btc_light_client");

    // parent at height 5, finalized at height 10 → fork point below finality
    let (ix, accounts) = extend_blockchain_call(&pid, 5, 10);
    let res = mollusk.process_instruction(&ix, &accounts);

    assert!(
        res.program_result.is_err(),
        "heavier fork from below finalized_height must be rejected, got {:?}",
        res.program_result
    );
    assert!(
        matches!(
            res.program_result,
            ProgramResult::Failure(ProgramError::InvalidArgument)
        ),
        "must return InvalidArgument (fork-point gate), got {:?}",
        res.program_result
    );
}

/// audit_1 F-BTC-03: the parent-HeightIndex account is MANDATORY.
///
/// It used to be enforced only `if accounts.len() > expected_accounts + num_ancestors`, i.e.
/// only when the caller volunteered it — so an attacker staging a multi-batch fork just left
/// it out. These three cases pin the three ways that can now go.
#[test]
fn extend_blockchain_requires_parent_height_index() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "btc_light_client");

    // 1. Omitted — the pre-fix caller. Rejected before any state is read.
    let (ix, accounts) = extend_blockchain_call_with(&pid, 10, 10, ParentHi::Omitted);
    assert!(
        matches!(
            mollusk.process_instruction(&ix, &accounts).program_result,
            ProgramResult::Failure(ProgramError::NotEnoughAccountKeys)
        ),
        "omitting the parent HeightIndex must not silently skip the canonicality check"
    );

    // 2. Uninitialized — what an attacker can actually pass for a fork block staged by an
    //    earlier non-canonical batch, since that branch never creates a HeightIndex.
    let (ix, accounts) = extend_blockchain_call_with(&pid, 10, 10, ParentHi::Uninitialized);
    assert!(
        mollusk.process_instruction(&ix, &accounts).program_result.is_err(),
        "an uninitialized parent HeightIndex must be rejected"
    );

    // 3. Present but naming a different block — the parent is not canonical at its height.
    let (ix, accounts) = extend_blockchain_call_with(&pid, 10, 10, ParentHi::Mismatched);
    assert!(
        matches!(
            mollusk.process_instruction(&ix, &accounts).program_result,
            ProgramResult::Failure(ProgramError::InvalidAccountData)
        ),
        "a parent that is not the canonical block at its height must be rejected"
    );
}

/// A fork whose parent is AT `finalized_height` must pass the gate (it can only
/// rewrite heights >= finalized_height+1, which are not yet finalized).
///
/// Setup: finalized_height=10, parent_height=10 → parent_height == finalized → gate PASSES.
/// The instruction proceeds past the gate (may succeed fully or fail later for an
/// unrelated reason); the important invariant is that the fork-point gate does NOT fire.
#[test]
fn extend_blockchain_accepts_fork_at_finality() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "btc_light_client");

    // parent at height 10, finalized at height 10 → fork point AT finality boundary → OK
    let (ix, accounts) = extend_blockchain_call(&pid, 10, 10);
    let res = mollusk.process_instruction(&ix, &accounts);

    // Gate must not fire: verify the error is NOT InvalidArgument from the gate.
    // A full success is also acceptable.
    assert!(
        !matches!(
            res.program_result,
            ProgramResult::Failure(ProgramError::InvalidArgument)
        ),
        "fork at finalized_height must NOT be rejected by the fork-point gate, got {:?}",
        res.program_result
    );
}

// ---- ragequit exit path (unshield disc 14, no approval accounts) ------------
//
// A permissioned pool exits either through an auditor approval or through the
// ragequit path, which needs no approval but only reaches destinations the
// auditor has registered. These tests pin the registry gate and — most
// importantly — that freezing the auditor does not close it. An auditor able to
// block withdrawal outright is the one power the design must not hand over.

const EXIT_DESTINATION_NOT_REGISTERED: u32 = 6097;
const INVALID_BOUND_PARAMS: u32 = 6067;

const EXIT_KIND_SOLANA_OWNER: u8 = 0;
const EXIT_KIND_BTC_SCRIPT: u8 = 1;

const TOKEN_CONFIG_DISC: u8 = 0x0B;
const TOKEN_CONFIG_LEN: usize = 164;
const EXIT_DESTINATION_DISC: u8 = 0x0d;
const EXIT_DESTINATION_LEN: usize = 36;

const POOL_OFF_BUMP: usize = 1;
const POOL_OFF_ZKBTC_MINT: usize = 36;

/// A token account blob: mint(32) || owner(32) || amount(8).
fn token_account_blob(mint: &Pubkey, owner: &Pubkey) -> Vec<u8> {
    let mut d = vec![0u8; 72];
    d[0..32].copy_from_slice(mint.as_ref());
    d[32..64].copy_from_slice(owner.as_ref());
    d
}

fn token_config_blob(bump: u8, mint: &Pubkey, vault: &Pubkey) -> Vec<u8> {
    let mut d = vec![0u8; TOKEN_CONFIG_LEN];
    d[0] = TOKEN_CONFIG_DISC;
    d[1] = bump;
    d[2..34].copy_from_slice(mint.as_ref());
    d[66..98].copy_from_slice(vault.as_ref());
    d[99] = 1; // enabled
    d
}

fn exit_destination_blob(bump: u8, kind: u8, key: &[u8; 32]) -> Vec<u8> {
    let mut d = vec![0u8; EXIT_DESTINATION_LEN];
    d[0] = EXIT_DESTINATION_DISC;
    d[1] = 1; // version
    d[2] = bump;
    d[3] = kind;
    d[4..36].copy_from_slice(key);
    d
}

/// What the caller passes in the single trailing ragequit slot.
enum RagequitSlot {
    /// Correct PDA for the recipient's owner, initialized.
    Registered,
    /// Correct PDA address, never created (the "not registered yet" case).
    Unregistered,
    /// A registered entry — for a *different* owner than the one being paid.
    RegisteredForAnotherOwner,
    /// A registered entry whose key matches, but under the BTC-script kind.
    RegisteredUnderBtcKind,
}

/// Build a 1-in / 1-out / 1-public-output unshield with no approval accounts,
/// i.e. the ragequit path. The proof and bound-params bytes are garbage: every
/// assertion here is about a gate that runs before they are examined.
fn unshield_ragequit_call(
    pid: &Pubkey,
    frozen: bool,
    slot: RagequitSlot,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let token_program = Pubkey::new_from_array(TOKEN_2022);
    let mint = Pubkey::new_unique();
    let (pool_state, pool_bump) = Pubkey::find_program_address(&[b"pool_state", mint.as_ref()], pid);
    let (token_config, tc_bump) =
        Pubkey::find_program_address(&[b"token_config", pool_state.as_ref(), mint.as_ref()], pid);
    let (tree, _) = Pubkey::find_program_address(
        &[b"commitment_tree", pool_state.as_ref(), &0u32.to_le_bytes()],
        pid,
    );

    let vk_registry = Pubkey::new_unique();
    let user = Pubkey::new_unique();
    let system_key = SYSTEM_ID;
    let vault = Pubkey::new_unique();
    let recipient = Pubkey::new_unique();
    let recipient_owner = Pubkey::new_unique();
    let nullifier_record = Pubkey::new_unique();

    // The registry key is the destination that actually gets paid: the token
    // account's OWNER, which is also what bound-params binds.
    let paid_owner: [u8; 32] = recipient_owner.to_bytes();
    let other_owner: [u8; 32] = Pubkey::new_unique().to_bytes();

    let (dest_key, dest_kind) = match slot {
        RagequitSlot::RegisteredForAnotherOwner => (other_owner, EXIT_KIND_SOLANA_OWNER),
        RagequitSlot::RegisteredUnderBtcKind => (paid_owner, EXIT_KIND_BTC_SCRIPT),
        _ => (paid_owner, EXIT_KIND_SOLANA_OWNER),
    };
    let (exit_destination, exit_bump) = Pubkey::find_program_address(
        &[
            b"exit_destination",
            pool_state.as_ref(),
            &[dest_kind],
            &dest_key,
        ],
        pid,
    );

    // header(4) + proof(256) + merkle_root(32) + bound_params(32)
    //   + nullifiers(1*32) + commitments_out(1*32) + stealth_data(0) + amounts(1*8)
    let mut data = vec![14u8]; // discriminator
    data.extend_from_slice(&[1u8, 1, 1, 0]); // n_in, n_out, n_pub, proof_source=inline
    data.extend_from_slice(&[7u8; 256]); // proof (garbage)
    data.extend_from_slice(&[0u8; 32]); // merkle_root
    data.extend_from_slice(&[0u8; 32]); // bound_params_hash (garbage)
    data.extend_from_slice(&[1u8; 32]); // nullifier
    data.extend_from_slice(&[2u8; 32]); // commitment_out
    data.extend_from_slice(&1_000u64.to_le_bytes()); // unshield amount

    let metas = vec![
        AccountMeta::new(pool_state, false),
        AccountMeta::new(tree, false),
        AccountMeta::new_readonly(vk_registry, false),
        AccountMeta::new(user, true),
        AccountMeta::new_readonly(system_key, false),
        AccountMeta::new(token_config, false),
        AccountMeta::new(vault, false),
        AccountMeta::new_readonly(token_program, false),
        AccountMeta::new(recipient, false),
        AccountMeta::new(nullifier_record, false),
        AccountMeta::new_readonly(exit_destination, false),
    ];
    let ix = Instruction::new_with_bytes(*pid, &data, metas);

    let mut flags = FLAG_PERMISSIONED;
    if frozen {
        flags |= FLAG_AUDITOR_FROZEN;
    }
    let mut pool_blob = pool_state_blob(flags, &[9u8; 32], &[0u8; 32]);
    pool_blob[POOL_OFF_BUMP] = pool_bump;
    pool_blob[POOL_OFF_ZKBTC_MINT..POOL_OFF_ZKBTC_MINT + 32].copy_from_slice(mint.as_ref());

    let exit_account = match slot {
        RagequitSlot::Unregistered => acct(0, vec![], SYSTEM_ID),
        _ => acct(
            1_000_000,
            exit_destination_blob(exit_bump, dest_kind, &dest_key),
            *pid,
        ),
    };

    let (system_pk, system_acct) = keyed_account_for_system_program();
    let accounts = vec![
        (pool_state, acct(1_000_000, pool_blob, *pid)),
        (tree, acct(1_000_000, vec![0u8; 128], *pid)),
        (vk_registry, acct(1, vec![0u8; 8], *pid)),
        (user, acct(1_000_000_000, vec![], SYSTEM_ID)),
        (system_pk, system_acct),
        (
            token_config,
            acct(1, token_config_blob(tc_bump, &mint, &vault), *pid),
        ),
        (
            vault,
            acct(1, token_account_blob(&mint, &pool_state), token_program),
        ),
        (token_program, acct(1, vec![], SYSTEM_ID)),
        (
            recipient,
            acct(1, token_account_blob(&mint, &recipient_owner), token_program),
        ),
        (nullifier_record, acct(0, vec![], SYSTEM_ID)),
        (exit_destination, exit_account),
    ];

    (ix, accounts)
}

fn run_ragequit(frozen: bool, slot: RagequitSlot) -> ProgramResult {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");
    let (ix, accounts) = unshield_ragequit_call(&pid, frozen, slot);
    mollusk.process_instruction(&ix, &accounts).program_result
}

#[test]
fn ragequit_rejects_an_unregistered_destination() {
    let res = run_ragequit(false, RagequitSlot::Unregistered);
    assert!(
        is_custom(&res, EXIT_DESTINATION_NOT_REGISTERED),
        "an unapproved exit must not reach an unvetted address, got {res:?}"
    );
}

/// The registry entry is derived from the owner actually being paid, so holding
/// *some* registration is not enough — a spender cannot borrow another
/// participant's entry to reach their address.
#[test]
fn ragequit_rejects_a_registration_for_a_different_owner() {
    let res = run_ragequit(false, RagequitSlot::RegisteredForAnotherOwner);
    assert!(
        is_custom(&res, EXIT_DESTINATION_NOT_REGISTERED),
        "registry entry must bind to the destination being paid, got {res:?}"
    );
}

/// A Solana owner and a BTC script hash share one 32-byte key space; only the
/// kind seed stops a registration for one from authorizing the other.
#[test]
fn ragequit_rejects_a_btc_registration_used_as_a_solana_destination() {
    let res = run_ragequit(false, RagequitSlot::RegisteredUnderBtcKind);
    assert!(
        is_custom(&res, EXIT_DESTINATION_NOT_REGISTERED),
        "kind must separate the two destination spaces, got {res:?}"
    );
}

/// The load-bearing guarantee: freezing is the auditor's strongest lever and it
/// still cannot close the exit. Reaching the bound-params check means the freeze
/// and the registry gate both let this through — everything past it is ordinary
/// proof validation, which garbage bytes are expected to fail.
#[test]
fn a_frozen_auditor_cannot_close_the_ragequit_exit() {
    let res = run_ragequit(true, RagequitSlot::Registered);
    assert!(
        is_custom(&res, INVALID_BOUND_PARAMS),
        "a frozen pool must still be exitable to a registered address, got {res:?}"
    );
    assert!(
        !is_custom(&res, AUDITOR_FROZEN),
        "freezing must never block the ragequit path"
    );
}

/// The same call on an unfrozen pool must behave identically — otherwise the
/// test above would pass for the wrong reason.
#[test]
fn ragequit_to_a_registered_destination_passes_the_gate() {
    let res = run_ragequit(false, RagequitSlot::Registered);
    assert!(
        is_custom(&res, INVALID_BOUND_PARAMS),
        "a registered destination must pass the registry gate, got {res:?}"
    );
}

// ---- redemption driver gate (mark_processing disc 18) ----------------------
//
// The BTC legs of a redemption used to be pool-authority-only, which let a
// silent operator strand a withdrawal the pool has no right to prevent. They now
// also accept the requester. They are NOT open to anyone: a third party could
// otherwise push a redemption into Processing with a bad input set, and only a
// cancel — which waits out the processing timeout — could undo it.

const REDEMPTION_DISC: u8 = 0x04;
const RED_OFF_REQUEST_ID: usize = 8;
const RED_OFF_REQUESTER: usize = 16;
/// Comfortably larger than RedemptionRequest::LEN; `from_bytes` only requires a
/// lower bound, and every field this test sets sits in the fixed prefix.
const REDEMPTION_BLOB_LEN: usize = 512;

fn redemption_blob(requester: &Pubkey, request_id: u64) -> Vec<u8> {
    let mut d = vec![0u8; REDEMPTION_BLOB_LEN];
    d[0] = REDEMPTION_DISC;
    d[1] = 0; // status = Pending
    d[RED_OFF_REQUEST_ID..RED_OFF_REQUEST_ID + 8].copy_from_slice(&request_id.to_le_bytes());
    d[RED_OFF_REQUESTER..RED_OFF_REQUESTER + 32].copy_from_slice(requester.as_ref());
    d
}

/// Call mark_processing with an empty payload: every assertion here is about the
/// driver gate, which runs before the payload is parsed.
fn mark_processing_call(
    pid: &Pubkey,
    signer: MarkProcessingSigner,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let mint = Pubkey::new_unique();
    let (pool_state, pool_bump) = Pubkey::find_program_address(&[b"pool_state", mint.as_ref()], pid);

    let operator = Pubkey::new_unique();
    let requester = Pubkey::new_unique();
    let stranger = Pubkey::new_unique();
    let request_id: u64 = 1;
    let (redemption, _) = Pubkey::find_program_address(
        &[
            b"redemption",
            pool_state.as_ref(),
            requester.as_ref(),
            &request_id.to_le_bytes(),
        ],
        pid,
    );

    let caller = match signer {
        MarkProcessingSigner::Operator => operator,
        MarkProcessingSigner::Requester => requester,
        MarkProcessingSigner::Stranger => stranger,
    };

    let metas = vec![
        AccountMeta::new(pool_state, false),
        AccountMeta::new(redemption, false),
        AccountMeta::new_readonly(caller, true),
    ];
    let ix = Instruction::new_with_bytes(*pid, &[18u8], metas);

    let mut pool_blob = pool_state_blob(0, &[0u8; 32], &[0u8; 32]);
    pool_blob[POOL_OFF_BUMP] = pool_bump;
    pool_blob[POOL_OFF_ZKBTC_MINT..POOL_OFF_ZKBTC_MINT + 32].copy_from_slice(mint.as_ref());
    pool_blob[POOL_OFF_AUTHORITY..POOL_OFF_AUTHORITY + 32].copy_from_slice(operator.as_ref());

    let accounts = vec![
        (pool_state, acct(1_000_000, pool_blob, *pid)),
        (
            redemption,
            acct(1_000_000, redemption_blob(&requester, request_id), *pid),
        ),
        (caller, acct(1_000_000_000, vec![], SYSTEM_ID)),
    ];

    (ix, accounts)
}

enum MarkProcessingSigner {
    Operator,
    Requester,
    Stranger,
}

fn run_mark_processing(signer: MarkProcessingSigner) -> ProgramResult {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");
    let (ix, accounts) = mark_processing_call(&pid, signer);
    mollusk.process_instruction(&ix, &accounts).program_result
}

#[test]
fn the_operator_still_drives_a_redemption() {
    let res = run_mark_processing(MarkProcessingSigner::Operator);
    assert!(
        !is_custom(&res, UNAUTHORIZED),
        "operator must keep its existing path, got {res:?}"
    );
}

/// The guarantee: a withdrawal does not depend on the operator answering.
#[test]
fn the_requester_can_drive_their_own_redemption_on_chain() {
    let res = run_mark_processing(MarkProcessingSigner::Requester);
    assert!(
        !is_custom(&res, UNAUTHORIZED),
        "requester must be able to push their own redemption, got {res:?}"
    );
}

/// ...and its limit: not open to the world, or a stranger could wedge a
/// redemption into Processing with an input set only a cancel can undo.
#[test]
fn a_stranger_cannot_drive_someone_elses_redemption_on_chain() {
    let res = run_mark_processing(MarkProcessingSigner::Stranger);
    assert!(
        is_custom(&res, UNAUTHORIZED),
        "third parties must not drive redemptions, got {res:?}"
    );
}

/// Value must not enter without a way back out: an SPL depositor with no entry
/// in the exit registry is refused before the approval is even consumed. This is
/// what turns "nobody can be trapped" from an onboarding promise into an
/// on-chain invariant.
#[test]
fn shield_permissioned_refuses_a_depositor_with_no_registered_exit() {
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
        false,
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, EXIT_DESTINATION_NOT_REGISTERED),
        "a depositor with no exit must be refused, got {:?}",
        res.program_result
    );
}

/// ...and the same call with the entry present gets past it, so the test above
/// cannot be passing for some unrelated reason.
#[test]
fn shield_permissioned_accepts_a_depositor_with_a_registered_exit() {
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
        true,
    );
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        !is_custom(&res.program_result, EXIT_DESTINATION_NOT_REGISTERED),
        "a registered depositor must clear the exit gate, got {:?}",
        res.program_result
    );
}


/// audit_1 F-BTC-04: a VerifiedTransaction is a permanent record of a proof that was valid
/// once. `assert_canonical_verified_tx` re-derives the PDA from the block hash and txid stored
/// inside that same account, so it cannot notice a reorg, and the confirmation count is computed
/// against `tip`, which only grows. Without a live HeightIndex lookup, a deposit settles against
/// a transaction that is no longer in the chain.
///
/// InvalidSpvProof (6019) is the check firing. The canonical case must get PAST it — it then
/// fails at the ChadBuffer owner check with the builtin InvalidAccountOwner, which is a
/// different error and proves execution moved on rather than tripping the same gate.
#[test]
fn complete_deposit_requires_the_block_to_still_be_canonical() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    // Reorged: the height index has moved on to a different block at that height.
    let (ix, accounts) = complete_deposit_spv_call(&pid, HeightIdx::Reorged);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, INVALID_SPV_PROOF),
        "a reorged-out block must be rejected, got {:?}",
        res.program_result
    );

    // Omitted: an absent account must be an error, never a skipped check — that is exactly
    // what made the F-BTC-03 fork-point gate bypassable.
    let (ix, accounts) = complete_deposit_spv_call(&pid, HeightIdx::Omitted);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        is_custom(&res.program_result, INVALID_SPV_PROOF),
        "omitting the HeightIndex must not silently skip the check, got {:?}",
        res.program_result
    );

    // Canonical: passes, and stops somewhere else entirely.
    let (ix, accounts) = complete_deposit_spv_call(&pid, HeightIdx::Canonical);
    let res = mollusk.process_instruction(&ix, &accounts);
    assert!(
        !is_custom(&res.program_result, INVALID_SPV_PROOF),
        "a still-canonical block must pass the check, got {:?}",
        res.program_result
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// validate_upgrade_authority — the C-1 remediation guard.
//
// audit_1 closed C-1 (VK-registry cross-pool takeover) by gating every VK-registry
// instruction on the program's own upgrade authority, and audit_1 F-BC-10 then flagged that
// nothing in the repo asserts the guard rejects anything: `validation_tests.rs` covers only
// `programdata_upgrade_authority`, the byte parse, and no SVM test drove disc 6/7/16. So the
// parse was tested and the *authorization* was not.
//
// These drive disc 6 (`init_vk_registry`) through mollusk and pin all four rejection paths
// plus a positive control. The control matters: with a correct authority the call fails
// *later* and with a different code, which is what proves the negative tests fail at the
// guard rather than somewhere earlier for an unrelated reason.
// ─────────────────────────────────────────────────────────────────────────────

/// BPFLoaderUpgradeab1e11111111111111111111111
const BPF_LOADER_UPGRADEABLE: [u8; 32] = [
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0, 0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2, 0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
];

const VK_HASH_MISMATCH: u32 = 6105; // UTXOpiaError::VkHashMismatch

/// `UpgradeableLoaderState::ProgramData`: u32 tag(3) | u64 slot | Option<Pubkey>(1 + 32).
fn programdata_blob(authority: &[u8; 32]) -> Vec<u8> {
    let mut d = 3u32.to_le_bytes().to_vec();
    d.extend_from_slice(&7u64.to_le_bytes());
    d.push(1); // Some(..)
    d.extend_from_slice(authority);
    d
}

/// disc 6 payload for JoinSplit(1,2): n_in | n_out | vk_hash(32) | delta_g2(128) | ic_len | ic.
/// The vk_hash is deliberately bogus — every negative case rejects long before `set_vk` reads
/// it, and the positive control *wants* to reach `set_vk` and be rejected there.
fn init_vk_registry_data() -> Vec<u8> {
    let ic_len: u8 = 6; // 2 + n_in + n_out + 1
    let mut d = vec![6u8, 1, 2];
    d.extend_from_slice(&[0xAAu8; 32]); // vk_hash
    d.extend_from_slice(&[0x11u8; 128]); // delta_g2
    d.push(ic_len);
    for _ in 0..ic_len {
        d.extend_from_slice(&[0x22u8; 64]);
    }
    d
}

struct UpgradeAuthCase {
    /// Key that signs the instruction.
    signer: Pubkey,
    /// Whether it is actually marked as a signer.
    is_signer: bool,
    /// Authority recorded inside the ProgramData account.
    stored_authority: [u8; 32],
    /// Override the ProgramData address (defaults to the canonical PDA).
    program_data_key: Option<Pubkey>,
    /// Owner of the ProgramData account (defaults to the loader).
    program_data_owner: Option<Pubkey>,
}

fn init_vk_registry_call(
    pid: &Pubkey,
    case: UpgradeAuthCase,
) -> (Instruction, Vec<(Pubkey, Account)>) {
    let loader = Pubkey::new_from_array(BPF_LOADER_UPGRADEABLE);
    let (canonical_pd, _) = Pubkey::find_program_address(&[pid.as_ref()], &loader);
    let pd_key = case.program_data_key.unwrap_or(canonical_pd);
    let pd_owner = case.program_data_owner.unwrap_or(loader);
    let (vk_registry, _) = Pubkey::find_program_address(&[b"vk_registry", &[1u8], &[2u8]], pid);

    let (system_key, system_account) = keyed_account_for_system_program();

    let metas = vec![
        AccountMeta::new_readonly(pd_key, false),
        AccountMeta::new(vk_registry, false),
        AccountMeta::new(case.signer, case.is_signer),
        AccountMeta::new_readonly(system_key, false),
    ];
    let ix = Instruction::new_with_bytes(*pid, &init_vk_registry_data(), metas);

    let accounts = vec![
        (
            pd_key,
            acct(1_000_000, programdata_blob(&case.stored_authority), pd_owner),
        ),
        (vk_registry, acct(0, vec![], SYSTEM_ID)),
        (case.signer, acct(10_000_000_000, vec![], SYSTEM_ID)),
        (system_key, system_account),
    ];

    (ix, accounts)
}

fn upgrade_auth_case(signer: Pubkey, stored_authority: [u8; 32]) -> UpgradeAuthCase {
    UpgradeAuthCase {
        signer,
        is_signer: true,
        stored_authority,
        program_data_key: None,
        program_data_owner: None,
    }
}

/// Positive control: the real upgrade authority gets *past* the guard and dies later, at the
/// vk_hash recomputation. Without this, every negative test below could be passing because
/// the instruction never reaches `validate_upgrade_authority` at all.
#[test]
fn init_vk_registry_passes_the_guard_for_the_real_upgrade_authority() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    let authority = Pubkey::new_unique();
    let (ix, accounts) = init_vk_registry_call(&pid, upgrade_auth_case(authority, authority.to_bytes()));
    let res = mollusk.process_instruction(&ix, &accounts);

    assert!(
        is_custom(&res.program_result, VK_HASH_MISMATCH),
        "the real upgrade authority must clear the guard and be stopped later by the vk_hash \
         recomputation (6105), got {:?}",
        res.program_result
    );
}

#[test]
fn init_vk_registry_rejects_a_signer_that_is_not_the_upgrade_authority() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    // Signs, is funded, and is simply not the key recorded in ProgramData.
    let impersonator = Pubkey::new_unique();
    let (ix, accounts) = init_vk_registry_call(&pid, upgrade_auth_case(impersonator, [0xAAu8; 32]));
    let res = mollusk.process_instruction(&ix, &accounts);

    assert!(
        is_custom(&res.program_result, UNAUTHORIZED),
        "a signer that is not the upgrade authority must be Unauthorized (6011), got {:?}",
        res.program_result
    );
}

#[test]
fn init_vk_registry_rejects_the_authority_when_it_does_not_sign() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    // The correct key, present but unsigned — the guard must not accept presence for consent.
    let authority = Pubkey::new_unique();
    let mut case = upgrade_auth_case(authority, authority.to_bytes());
    case.is_signer = false;
    let (ix, accounts) = init_vk_registry_call(&pid, case);
    let res = mollusk.process_instruction(&ix, &accounts);

    assert_eq!(
        res.program_result,
        ProgramResult::Failure(ProgramError::MissingRequiredSignature),
        "an unsigned upgrade authority must be MissingRequiredSignature, got {:?}",
        res.program_result
    );
}

#[test]
fn init_vk_registry_rejects_a_substituted_program_data_account() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    // A loader-owned ProgramData blob naming the attacker, at an address that is not this
    // program's PDA — i.e. some other program's ProgramData, or a forgery.
    let attacker = Pubkey::new_unique();
    let mut case = upgrade_auth_case(attacker, attacker.to_bytes());
    case.program_data_key = Some(Pubkey::new_unique());
    let (ix, accounts) = init_vk_registry_call(&pid, case);
    let res = mollusk.process_instruction(&ix, &accounts);

    assert_eq!(
        res.program_result,
        ProgramResult::Failure(ProgramError::InvalidArgument),
        "ProgramData at a non-canonical address must be InvalidArgument, got {:?}",
        res.program_result
    );
}

#[test]
fn init_vk_registry_rejects_program_data_not_owned_by_the_loader() {
    std::env::set_var("SBF_OUT_DIR", so_dir());
    let pid = Pubkey::new_unique();
    let mollusk = Mollusk::new(&pid, "utxopia");

    // Right address, right contents, wrong owner: anyone can create a system-owned account and
    // write these bytes, so the owner check is what makes the address meaningful.
    let attacker = Pubkey::new_unique();
    let mut case = upgrade_auth_case(attacker, attacker.to_bytes());
    case.program_data_owner = Some(SYSTEM_ID);
    let (ix, accounts) = init_vk_registry_call(&pid, case);
    let res = mollusk.process_instruction(&ix, &accounts);

    assert_eq!(
        res.program_result,
        ProgramResult::Failure(ProgramError::InvalidArgument),
        "ProgramData not owned by the loader must be InvalidArgument, got {:?}",
        res.program_result
    );
}
