//! Register a new token for the multi-token shielded pool.
//!
//! Admin-only instruction that creates a TokenConfig PDA for a whitelisted SPL token.
//!
//! # Accounts
//! 0. `[signer]`   Authority (must match pool.authority)
//! 1. `[]`         Pool state PDA
//! 2. `[]`         SPL mint account (Token-2022)
//! 3. `[writable]` TokenConfig PDA (to create; seeds: ["token_config", mint])
//! 4. `[]`         Vault token account (PDA-owned)
//! 5. `[]`         System program

use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError};
use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolState, TokenConfig};
use crate::utils::{
    create_pda_account, crypto::compute_token_id, mint_has_unsupported_pool_extension,
    validate_account_writable, validate_program_owner, validate_system_program,
    validate_token_owner,
};

/// Instruction data layout:
/// service_fee(8) + min_deposit(8) + max_deposit(8) + deposit_cap(8) = 32 bytes
const DATA_LEN: usize = 32;

pub fn process_register_token(
    program_id: &crate::pinocchio_compat::Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() < 6 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() < DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }

    let authority = &accounts[0];
    let pool_state_info = &accounts[1];
    let mint_info = &accounts[2];
    let token_config_info = &accounts[3];
    let vault_info = &accounts[4];
    let _system_program = &accounts[5];

    // Validate signer
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Validate pool state and authority
    validate_program_owner(pool_state_info, program_id)?;
    validate_system_program(_system_program)?;
    validate_account_writable(token_config_info)?;
    {
        let pool_data = pool_state_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.address().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    // Validate mint is Token-2022
    validate_token_owner(mint_info)?;

    // Vault must be an SPL token account whose authority is the pool PDA. Deposits land in this
    // vault and unshield/claim_fees sign transfers OUT of it as the pool PDA; if the vault were
    // controlled by anyone else, those flows would break and deposited funds would be
    // misdirected to an account the program cannot spend from (audit f27). Token account layout:
    // [0..32] mint, [32..64] owner/authority.
    validate_token_owner(vault_info)?;
    {
        let vault_data = vault_info.try_borrow()?;
        if vault_data.len() < 64 {
            return Err(UTXOpiaError::InvalidAccountData.into());
        }
        if vault_data[32..64] != pool_state_info.address().as_ref()[..] {
            return Err(UTXOpiaError::InvalidVault.into());
        }
    }

    // Reject Token-2022 extensions that can bypass custody or invalidate amount accounting:
    // transfer fees, permanent delegates, and transfer hooks.
    let decimals = {
        let mint_data = mint_info.try_borrow()?;
        if mint_data.len() < 82 {
            return Err(ProgramError::InvalidAccountData);
        }

        if mint_has_unsupported_pool_extension(&mint_data) {
            return Err(UTXOpiaError::InvalidMint.into());
        }

        mint_data[44]
    };

    // Derive and validate TokenConfig PDA
    let tc_seeds: &[&[u8]] = &[TokenConfig::SEED, mint_info.address().as_ref()];
    let (expected_pda, tc_bump) = find_program_address(tc_seeds, program_id);
    if token_config_info.address() != &expected_pda {
        return Err(UTXOpiaError::InvalidPDA.into());
    }

    // Compute token_id = Poseidon(reduce_to_field(mint), 0)
    let mint_bytes: &[u8; 32] = mint_info.address().as_ref().try_into().unwrap();
    let token_id = compute_token_id(mint_bytes)?;

    // Reject re-registration of an already-initialized token: create_pda_account is a no-op on
    // an existing PDA, so without this guard the authority could re-run register_token and wipe
    // a live TokenConfig (accumulated_fees, total_shielded, etc.) back to zero (audit f37).
    {
        let tc_data = token_config_info.try_borrow()?;
        if !tc_data.is_empty()
            && tc_data[0] == crate::state::token_config::TOKEN_CONFIG_DISCRIMINATOR
        {
            return Err(UTXOpiaError::AlreadyInitialized.into());
        }
    }

    // Create TokenConfig PDA
    let rent = Rent::get()?;
    let lamports = rent.minimum_balance(TokenConfig::LEN);
    let bump_bytes = [tc_bump];
    let create_seeds: &[&[u8]] = &[TokenConfig::SEED, mint_info.address().as_ref(), &bump_bytes];

    create_pda_account(
        authority,
        token_config_info,
        program_id,
        lamports,
        TokenConfig::LEN as u64,
        create_seeds,
    )?;

    // Parse instruction data
    let service_fee = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let min_deposit = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let max_deposit = u64::from_le_bytes(data[16..24].try_into().unwrap());
    let deposit_cap = u64::from_le_bytes(data[24..32].try_into().unwrap());

    // Validate limits: a deposit must be possible and bounded by the cap.
    if min_deposit == 0 || min_deposit > max_deposit || max_deposit > deposit_cap {
        return Err(UTXOpiaError::InvalidTokenConfig.into());
    }

    // Initialize TokenConfig
    {
        let mut tc_data = token_config_info.try_borrow_mut()?;
        let tc = TokenConfig::init(&mut tc_data)?;
        tc.bump = tc_bump;
        tc.mint.copy_from_slice(mint_info.address().as_ref());
        tc.token_id = token_id;
        tc.vault.copy_from_slice(vault_info.address().as_ref());
        tc.decimals = decimals;
        tc.set_enabled(true);
        tc.set_service_fee(service_fee);
        tc.set_min_deposit(min_deposit);
        tc.set_max_deposit(max_deposit);
        tc.set_deposit_cap(deposit_cap);
    }

    solana_program_log::log!("UTXOpia: registered token");
    Ok(())
}

#[cfg(test)]
mod transfer_fee_tests {
    use crate::utils::token::{
        mint_has_unsupported_pool_extension, EXT_PERMANENT_DELEGATE, EXT_TRANSFER_HOOK,
    };

    fn mint_with_exts(exts: &[(u16, &[u8])]) -> Vec<u8> {
        let mut v = vec![0u8; 166];
        v[165] = 1; // account_type = Mint
        for (ty, data) in exts {
            v.extend_from_slice(&ty.to_le_bytes());
            v.extend_from_slice(&(data.len() as u16).to_le_bytes());
            v.extend_from_slice(data);
        }
        v
    }

    #[test]
    fn plain_mint_82_bytes_has_no_fee() {
        assert!(!mint_has_unsupported_pool_extension(&[0u8; 82]));
    }

    #[test]
    fn mint_with_metadata_pointer_only_has_no_fee() {
        // ExtensionType 18 = MetadataPointer (not a transfer fee).
        let m = mint_with_exts(&[(18, &[0u8; 64])]);
        assert!(!mint_has_unsupported_pool_extension(&m));
    }

    #[test]
    fn mint_with_transfer_fee_config_is_detected() {
        // ExtensionType 1 = TransferFeeConfig.
        let m = mint_with_exts(&[(1, &[0u8; 108])]);
        assert!(mint_has_unsupported_pool_extension(&m));
    }

    #[test]
    fn transfer_fee_after_another_extension_is_detected() {
        let m = mint_with_exts(&[(3, &[0u8; 32]), (1, &[0u8; 108])]);
        assert!(mint_has_unsupported_pool_extension(&m));
    }

    #[test]
    fn custody_bypassing_extensions_are_detected() {
        for extension_type in [EXT_PERMANENT_DELEGATE, EXT_TRANSFER_HOOK] {
            let m = mint_with_exts(&[(extension_type, &[0u8; 32])]);
            assert!(mint_has_unsupported_pool_extension(&m));
        }
    }
}
