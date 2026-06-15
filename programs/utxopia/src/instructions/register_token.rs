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

use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::find_program_address,
    sysvars::rent::Rent, sysvars::Sysvar, ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{PoolState, TokenConfig};
use crate::utils::{
    create_pda_account, crypto::compute_token_id, validate_account_writable,
    validate_program_owner, validate_system_program, validate_token_owner,
};

/// Instruction data layout:
/// service_fee(8) + min_deposit(8) + max_deposit(8) + deposit_cap(8) = 32 bytes
const DATA_LEN: usize = 32;

pub fn process_register_token(
    program_id: &pinocchio::pubkey::Pubkey,
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
        let pool_data = pool_state_info.try_borrow_data()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    // Validate mint is Token-2022
    validate_token_owner(mint_info)?;

    // Read decimals from mint (offset 44 in Token-2022 mint layout) and reject fee-on-transfer
    // mints. A TransferFeeConfig extension makes the vault receive fewer tokens than the credited
    // amount on the withdrawal side and strands protocol fees; refuse such mints at registration.
    // (The deposit side additionally measures the actual vault balance delta — see shield.rs.)
    let decimals = {
        let mint_data = mint_info.try_borrow_data()?;
        if mint_data.len() < 82 {
            return Err(ProgramError::InvalidAccountData);
        }

        if mint_has_transfer_fee(&mint_data) {
            return Err(UTXOpiaError::InvalidMint.into());
        }

        mint_data[44]
    };

    // Derive and validate TokenConfig PDA
    let tc_seeds: &[&[u8]] = &[TokenConfig::SEED, mint_info.key().as_ref()];
    let (expected_pda, tc_bump) = find_program_address(tc_seeds, program_id);
    if token_config_info.key() != &expected_pda {
        return Err(UTXOpiaError::InvalidPDA.into());
    }

    // Compute token_id = Poseidon(reduce_to_field(mint), 0)
    let mint_bytes: &[u8; 32] = mint_info.key().as_ref().try_into().unwrap();
    let token_id = compute_token_id(mint_bytes)?;

    // Reject re-registration of an already-initialized token: create_pda_account is a no-op on
    // an existing PDA, so without this guard the authority could re-run register_token and wipe
    // a live TokenConfig (accumulated_fees, total_shielded, etc.) back to zero (audit f37).
    {
        let tc_data = token_config_info.try_borrow_data()?;
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
    let create_seeds: &[&[u8]] = &[TokenConfig::SEED, mint_info.key().as_ref(), &bump_bytes];

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
        let mut tc_data = token_config_info.try_borrow_mut_data()?;
        let tc = TokenConfig::init(&mut tc_data)?;
        tc.bump = tc_bump;
        tc.mint.copy_from_slice(mint_info.key().as_ref());
        tc.token_id = token_id;
        tc.vault.copy_from_slice(vault_info.key().as_ref());
        tc.decimals = decimals;
        tc.set_enabled(true);
        tc.set_service_fee(service_fee);
        tc.set_min_deposit(min_deposit);
        tc.set_max_deposit(max_deposit);
        tc.set_deposit_cap(deposit_cap);
    }

    pinocchio::msg!("UTXOpia: registered token");
    Ok(())
}

/// Return true if a Token-2022 mint carries the TransferFeeConfig extension (fee-on-transfer).
///
/// Token-2022 accounts with extensions: the 82-byte base mint is padded to 165, then a 1-byte
/// account_type (1 = Mint) at offset 165, then TLV extensions from offset 166. Each TLV entry is
/// type(u16 LE) + length(u16 LE) + value; ExtensionType 1 is TransferFeeConfig.
pub(crate) fn mint_has_transfer_fee(mint_data: &[u8]) -> bool {
    if mint_data.len() <= 165 || mint_data[165] != 1 {
        return false;
    }
    let mut off = 166usize;
    while off + 4 <= mint_data.len() {
        let ext_type = u16::from_le_bytes([mint_data[off], mint_data[off + 1]]);
        if ext_type == 0 {
            break; // Uninitialized slot — end of extension list
        }
        if ext_type == 1 {
            return true; // TransferFeeConfig
        }
        let ext_len = u16::from_le_bytes([mint_data[off + 2], mint_data[off + 3]]) as usize;
        match off.checked_add(4 + ext_len) {
            Some(next) => off = next,
            None => break,
        }
    }
    false
}

#[cfg(test)]
mod transfer_fee_tests {
    use super::mint_has_transfer_fee;

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
        assert!(!mint_has_transfer_fee(&[0u8; 82]));
    }

    #[test]
    fn mint_with_metadata_pointer_only_has_no_fee() {
        // ExtensionType 18 = MetadataPointer (not a transfer fee).
        let m = mint_with_exts(&[(18, &[0u8; 64])]);
        assert!(!mint_has_transfer_fee(&m));
    }

    #[test]
    fn mint_with_transfer_fee_config_is_detected() {
        // ExtensionType 1 = TransferFeeConfig.
        let m = mint_with_exts(&[(1, &[0u8; 108])]);
        assert!(mint_has_transfer_fee(&m));
    }

    #[test]
    fn transfer_fee_after_another_extension_is_detected() {
        let m = mint_with_exts(&[(3, &[0u8; 32]), (1, &[0u8; 108])]);
        assert!(mint_has_transfer_fee(&m));
    }
}
