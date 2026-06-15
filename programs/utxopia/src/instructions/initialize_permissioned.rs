//! InitializePermissioned instruction - sets up the UTXOpia pool in permissioned mode

use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

use crate::utils::{create_pda_account, validate_system_program, validate_token_owner};

use crate::constants::{MAX_DEPOSIT_SATS, MAX_FEE_BPS, MIN_DEPOSIT_SATS};
use crate::error::UTXOpiaError;
use crate::state::{CommitmentTree, PoolState, POOL_STATE_DISCRIMINATOR};

/// InitializePermissioned instruction data
/// Layout: pool_bump(1) + tree_bump(1) + deposit_fee_bps(2) + withdrawal_fee_bps(2)
///       + auditor(32) + auditor_viewing_pubkey(32)
pub struct InitializePermissionedData {
    pub pool_bump: u8,
    pub tree_bump: u8,
    pub deposit_fee_bps: u16,
    pub withdrawal_fee_bps: u16,
    pub auditor: [u8; 32],
    pub auditor_viewing_pubkey: [u8; 32],
}

impl InitializePermissionedData {
    /// Minimum byte length: 6 base bytes + 32 auditor + 32 viewing pubkey
    const MIN_LEN: usize = 6 + 32 + 32;

    pub fn from_bytes(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < Self::MIN_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut auditor = [0u8; 32];
        auditor.copy_from_slice(&data[6..38]);
        let mut auditor_viewing_pubkey = [0u8; 32];
        auditor_viewing_pubkey.copy_from_slice(&data[38..70]);
        Ok(Self {
            pool_bump: data[0],
            tree_bump: data[1],
            deposit_fee_bps: u16::from_le_bytes(data[2..4].try_into().unwrap()),
            withdrawal_fee_bps: u16::from_le_bytes(data[4..6].try_into().unwrap()),
            auditor,
            auditor_viewing_pubkey,
        })
    }
}

/// Initialize accounts (same layout as initialize)
pub struct InitializePermissionedAccounts<'a> {
    pub pool_state: &'a AccountInfo,
    pub commitment_tree: &'a AccountInfo,
    pub zkbtc_mint: &'a AccountInfo,
    pub pool_vault: &'a AccountInfo,
    pub deposit_vault: &'a AccountInfo,
    pub authority: &'a AccountInfo,
    pub system_program: &'a AccountInfo,
}

impl<'a> InitializePermissionedAccounts<'a> {
    pub fn from_accounts(accounts: &'a [AccountInfo]) -> Result<Self, ProgramError> {
        if accounts.len() < 7 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }

        let pool_state = &accounts[0];
        let commitment_tree = &accounts[1];
        let zkbtc_mint = &accounts[2];
        let pool_vault = &accounts[3];
        let deposit_vault = &accounts[4];
        let authority = &accounts[5];
        let system_program = &accounts[6];

        // Validate authority is signer
        if !authority.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }

        Ok(Self {
            pool_state,
            commitment_tree,
            zkbtc_mint,
            pool_vault,
            deposit_vault,
            authority,
            system_program,
        })
    }
}

/// Initialize the UTXOpia pool in permissioned mode
pub fn process_initialize_permissioned(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let accounts = InitializePermissionedAccounts::from_accounts(accounts)?;
    let ix_data = InitializePermissionedData::from_bytes(data)?;

    // Validate zkbtc_mint is owned by Token-2022
    validate_token_owner(accounts.zkbtc_mint)?;
    validate_system_program(accounts.system_program)?;

    // Verify pool_state PDA
    let pool_seeds: &[&[u8]] = &[PoolState::SEED];
    let (expected_pool_pda, pool_bump) = find_program_address(pool_seeds, program_id);
    if accounts.pool_state.key() != &expected_pool_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Verify commitment_tree PDA
    let tree_index_bytes = 0u32.to_le_bytes();
    let tree_seeds: &[&[u8]] = &[CommitmentTree::SEED_PREFIX, &tree_index_bytes];
    let (expected_tree_pda, tree_bump) = find_program_address(tree_seeds, program_id);
    if accounts.commitment_tree.key() != &expected_tree_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Get rent for account sizes
    let rent = Rent::get()?;
    let pool_lamports = rent.minimum_balance(PoolState::LEN);
    let tree_lamports = rent.minimum_balance(CommitmentTree::LEN);

    // Check if pool_state already exists
    let pool_data_len = accounts.pool_state.data_len();

    if pool_data_len > 0 {
        // Account exists, check if initialized
        let pool_data = accounts.pool_state.try_borrow_data()?;
        if pool_data[0] == POOL_STATE_DISCRIMINATOR {
            return Err(UTXOpiaError::AlreadyInitialized.into());
        }
    } else {
        // Create pool_state PDA
        let pool_bump_bytes = [pool_bump];
        let pool_signer_seeds: &[&[u8]] = &[PoolState::SEED, &pool_bump_bytes];

        create_pda_account(
            accounts.authority,
            accounts.pool_state,
            program_id,
            pool_lamports,
            PoolState::LEN as u64,
            pool_signer_seeds,
        )?;
    }

    // Check if commitment_tree already exists
    let tree_data_len = accounts.commitment_tree.data_len();

    if tree_data_len == 0 {
        // Create commitment_tree PDA
        let tree_bump_bytes = [tree_bump];
        let tree_signer_seeds: &[&[u8]] = &[
            CommitmentTree::SEED_PREFIX,
            &tree_index_bytes,
            &tree_bump_bytes,
        ];

        create_pda_account(
            accounts.authority,
            accounts.commitment_tree,
            program_id,
            tree_lamports,
            CommitmentTree::LEN as u64,
            tree_signer_seeds,
        )?;
    }

    // Get clock for timestamp
    let clock = Clock::get()?;

    // Reject fees that would consume the entire deposit/withdrawal (100%+ fee DoS).
    if ix_data.deposit_fee_bps >= MAX_FEE_BPS || ix_data.withdrawal_fee_bps >= MAX_FEE_BPS {
        return Err(UTXOpiaError::InvalidTokenConfig.into());
    }

    // Initialize pool state
    {
        let mut pool_data = accounts.pool_state.try_borrow_mut_data()?;
        let pool = PoolState::init(&mut pool_data)?;

        pool.bump = pool_bump;
        pool.authority
            .copy_from_slice(accounts.authority.key().as_ref());
        pool.zkbtc_mint
            .copy_from_slice(accounts.zkbtc_mint.key().as_ref());
        pool.pool_vault
            .copy_from_slice(accounts.pool_vault.key().as_ref());
        pool.deposit_vault
            .copy_from_slice(accounts.deposit_vault.key().as_ref());
        pool.set_min_deposit(MIN_DEPOSIT_SATS);
        pool.set_max_deposit(MAX_DEPOSIT_SATS);
        pool.set_service_fee_base(2_000);
        pool.set_deposit_fee_bps(ix_data.deposit_fee_bps);
        pool.set_withdrawal_fee_bps(ix_data.withdrawal_fee_bps);
        pool.set_last_update(clock.unix_timestamp);
        pool.set_paused(false);

        // Permissioned-mode fields
        pool.set_permissioned(true);
        pool.set_auditor(&ix_data.auditor);
        pool.set_auditor_viewing_pubkey(&ix_data.auditor_viewing_pubkey);
        pool.set_auditor_frozen(false);
    }

    // Initialize commitment tree
    {
        let mut tree_data = accounts.commitment_tree.try_borrow_mut_data()?;
        let tree = CommitmentTree::init(&mut tree_data)?;
        tree.bump = tree_bump;
        tree.set_tree_index(0); // first tree; enables O(1) frozen-tree validation (f23)
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `InitializePermissionedData::from_bytes` parses all fields correctly
    /// and that the permissioned flag setters work as expected on a zeroed PoolState buffer.
    #[test]
    fn test_initialize_permissioned_data_parsing() {
        let auditor_key: [u8; 32] = [0xAB; 32];
        let viewing_key: [u8; 32] = [0xCD; 32];

        let mut raw = vec![0u8; 70];
        raw[0] = 7u8;  // pool_bump
        raw[1] = 3u8;  // tree_bump
        raw[2..4].copy_from_slice(&50u16.to_le_bytes());   // deposit_fee_bps = 50
        raw[4..6].copy_from_slice(&100u16.to_le_bytes());  // withdrawal_fee_bps = 100
        raw[6..38].copy_from_slice(&auditor_key);
        raw[38..70].copy_from_slice(&viewing_key);

        let parsed = InitializePermissionedData::from_bytes(&raw).unwrap();
        assert_eq!(parsed.pool_bump, 7);
        assert_eq!(parsed.tree_bump, 3);
        assert_eq!(parsed.deposit_fee_bps, 50);
        assert_eq!(parsed.withdrawal_fee_bps, 100);
        assert_eq!(parsed.auditor, auditor_key);
        assert_eq!(parsed.auditor_viewing_pubkey, viewing_key);
    }

    #[test]
    fn test_initialize_permissioned_data_too_short() {
        let raw = vec![0u8; 69]; // one byte short of MIN_LEN
        assert!(InitializePermissionedData::from_bytes(&raw).is_err());
    }

    /// Verify field-setting logic in isolation: allocate a raw buffer, run PoolState::init,
    /// apply the permissioned setters, then assert all four fields.
    #[test]
    fn test_permissioned_pool_state_fields() {
        let auditor_key: [u8; 32] = [0x11; 32];
        let viewing_key: [u8; 32] = [0x22; 32];

        let mut buf = vec![0u8; PoolState::LEN];
        let pool = PoolState::init(&mut buf).unwrap();

        pool.set_permissioned(true);
        pool.set_auditor(&auditor_key);
        pool.set_auditor_viewing_pubkey(&viewing_key);
        pool.set_auditor_frozen(false);

        assert!(pool.permissioned(), "pool should be permissioned");
        assert_eq!(pool.auditor(), &auditor_key, "auditor key mismatch");
        assert_eq!(
            pool.auditor_viewing_pubkey(),
            &viewing_key,
            "viewing pubkey mismatch"
        );
        assert!(!pool.auditor_is_frozen(), "auditor should not be frozen");
    }

    #[test]
    fn test_permissioned_does_not_set_paused() {
        let mut buf = vec![0u8; PoolState::LEN];
        let pool = PoolState::init(&mut buf).unwrap();
        pool.set_permissioned(true);
        assert!(!pool.is_paused(), "permissioned pool should not be paused");
    }
}
