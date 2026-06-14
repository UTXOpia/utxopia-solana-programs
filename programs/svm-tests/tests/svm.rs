//! SVM-level adversarial regression tests (mollusk) for the 2026-06-14 hardening.
//!
//! Covers the two fixes that cannot be exercised by host unit tests because they live inside
//! instruction handlers (need real AccountInfo + on-chain `find_program_address`):
//!   1. utxopia `complete_deposit` rejects a substituted token_config (cross-token mint).
//!   2. btc-light-client `verify_transaction` requires finality (block <= finalized_height).
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
const BTC_LC_OWNER: [u8; 32] = [
    0xf9, 0x89, 0xe5, 0x99, 0x89, 0xcc, 0x7e, 0xc1, 0xa0, 0x54, 0xb3, 0x8a, 0x3f, 0xa4, 0x56, 0x44,
    0x9a, 0x2e, 0x83, 0xd2, 0xbe, 0xf4, 0x78, 0x48, 0x02, 0x46, 0xb5, 0x87, 0x45, 0xea, 0x9d, 0xb0,
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

    let accounts = vec![
        (pool_state, acct(1, vec![], *pid)),
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
