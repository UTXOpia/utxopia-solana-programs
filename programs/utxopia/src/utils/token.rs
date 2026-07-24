//! Token-2022 helper functions for Pinocchio

use pinocchio::{
    account_info::AccountInfo,
    cpi::{invoke, invoke_signed},
    instruction::{AccountMeta, Instruction, Seed, Signer},
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

use crate::constants::TOKEN_2022_PROGRAM_ID;
use crate::error::UTXOpiaError;

const SPL_MINT_BASE_LEN: usize = 82;
const SPL_MINT_AUTHORITY_TAG_OFFSET: usize = 0;
const SPL_MINT_AUTHORITY_OFFSET: usize = 4;
const SPL_MINT_DECIMALS_OFFSET: usize = 44;
const SPL_MINT_INITIALIZED_OFFSET: usize = 45;
const SPL_MINT_FREEZE_AUTHORITY_TAG_OFFSET: usize = 46;
const SPL_MINT_FREEZE_AUTHORITY_OFFSET: usize = 50;
const TOKEN_2022_ACCOUNT_TYPE_OFFSET: usize = 165;
const TOKEN_2022_TLV_OFFSET: usize = 166;

pub(crate) const EXT_TRANSFER_FEE_CONFIG: u16 = 1;
pub(crate) const EXT_PERMANENT_DELEGATE: u16 = 12;
pub(crate) const EXT_TRANSFER_HOOK: u16 = 14;

/// Returns true when a Token-2022 mint contains an extension whose semantics can make
/// UTXOpia's balance accounting or PDA custody assumptions invalid.
pub(crate) fn mint_has_unsupported_pool_extension(mint_data: &[u8]) -> bool {
    if mint_data.len() <= TOKEN_2022_ACCOUNT_TYPE_OFFSET
        || mint_data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] != 1
    {
        return false;
    }

    let mut off = TOKEN_2022_TLV_OFFSET;
    while off + 4 <= mint_data.len() {
        let ext_type = u16::from_le_bytes([mint_data[off], mint_data[off + 1]]);
        if ext_type == 0 {
            break;
        }
        if matches!(
            ext_type,
            EXT_TRANSFER_FEE_CONFIG | EXT_PERMANENT_DELEGATE | EXT_TRANSFER_HOOK
        ) {
            return true;
        }
        let ext_len = u16::from_le_bytes([mint_data[off + 2], mint_data[off + 3]]) as usize;
        match off.checked_add(4).and_then(|v| v.checked_add(ext_len)) {
            Some(next) if next <= mint_data.len() => off = next,
            _ => return true, // malformed TLV data is never safe to register
        }
    }
    false
}

/// Validate the zkBTC mint invariant used by the bridge.
///
/// zkBTC is denominated in satoshis, must be initialized under Token-2022, and the pool PDA
/// must be the only authority capable of minting (and freezing, when a freeze authority exists).
pub fn validate_pool_controlled_zkbtc_mint(
    mint: &AccountInfo,
    pool_state: &Pubkey,
) -> Result<(), ProgramError> {
    if mint.owner().as_ref() != TOKEN_2022_PROGRAM_ID {
        return Err(UTXOpiaError::InvalidMint.into());
    }
    let data = mint.try_borrow_data()?;
    validate_pool_controlled_zkbtc_mint_data(&data, pool_state)
}

pub(crate) fn validate_pool_controlled_zkbtc_mint_data(
    data: &[u8],
    pool_state: &Pubkey,
) -> Result<(), ProgramError> {
    if data.len() < SPL_MINT_BASE_LEN
        || (data.len() > SPL_MINT_BASE_LEN && data.len() < TOKEN_2022_TLV_OFFSET)
        || data[SPL_MINT_INITIALIZED_OFFSET] != 1
        || data[SPL_MINT_DECIMALS_OFFSET] != 8
    {
        return Err(UTXOpiaError::InvalidMint.into());
    }

    let mint_authority_tag = u32::from_le_bytes(
        data[SPL_MINT_AUTHORITY_TAG_OFFSET..SPL_MINT_AUTHORITY_OFFSET]
            .try_into()
            .map_err(|_| UTXOpiaError::InvalidMint)?,
    );
    if mint_authority_tag != 1
        || data[SPL_MINT_AUTHORITY_OFFSET..SPL_MINT_AUTHORITY_OFFSET + 32]
            != pool_state.as_ref()[..]
    {
        return Err(UTXOpiaError::InvalidMint.into());
    }

    let freeze_authority_tag = u32::from_le_bytes(
        data[SPL_MINT_FREEZE_AUTHORITY_TAG_OFFSET..SPL_MINT_FREEZE_AUTHORITY_OFFSET]
            .try_into()
            .map_err(|_| UTXOpiaError::InvalidMint)?,
    );
    if freeze_authority_tag > 1
        || (freeze_authority_tag == 1
            && data[SPL_MINT_FREEZE_AUTHORITY_OFFSET..SPL_MINT_FREEZE_AUTHORITY_OFFSET + 32]
                != pool_state.as_ref()[..])
        || mint_has_unsupported_pool_extension(data)
    {
        return Err(UTXOpiaError::InvalidMint.into());
    }

    Ok(())
}

/// Token instruction discriminators (same for both Token and Token-2022)
mod token_instruction {
    pub const MINT_TO: u8 = 7;
    pub const BURN: u8 = 8;
    pub const TRANSFER: u8 = 3;
    pub const UNWRAP_LAMPORTS: u8 = 45;
}

/// Return whether `mint` is the canonical native-SOL mint for `token_program`.
#[inline(always)]
pub fn is_native_sol_mint(mint: &[u8; 32], token_program: &Pubkey) -> bool {
    use crate::constants::{
        NATIVE_SOL_2022_MINT, NATIVE_SOL_MINT, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
    };

    let program = token_program.as_ref();
    (program == TOKEN_PROGRAM_ID && *mint == NATIVE_SOL_MINT)
        || (program == TOKEN_2022_PROGRAM_ID && *mint == NATIVE_SOL_2022_MINT)
}

/// Read the mint from the common prefix of a Token / Token-2022 account and
/// determine whether it is a native-SOL account owned by `token_program`.
pub fn is_native_sol_account(
    account: &AccountInfo,
    token_program: &AccountInfo,
) -> Result<bool, ProgramError> {
    if account.owner() != token_program.key() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = account.try_borrow_data()?;
    if data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mint: &[u8; 32] = data[0..32]
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(is_native_sol_mint(mint, token_program.key()))
}

/// Partially unwrap native SOL from a PDA-controlled wSOL account without
/// closing it. `amount` is always explicit so the pool vault can never be
/// drained by the Token Program's "unwrap all" form.
pub fn unwrap_lamports_signed(
    token_program: &AccountInfo,
    source: &AccountInfo,
    destination: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = [0u8; 10];
    data[0] = token_instruction::UNWRAP_LAMPORTS;
    data[1] = 1; // Some(amount), never the unwrap-all variant.
    data[2..10].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        AccountMeta::writable(source.key()),
        AccountMeta::writable(destination.key()),
        AccountMeta::readonly_signer(authority.key()),
    ];
    let instruction = Instruction {
        program_id: token_program.key(),
        accounts: &accounts,
        data: &data,
    };

    let seeds: [Seed; 2] = [Seed::from(signer_seeds[0]), Seed::from(signer_seeds[1])];
    let signer = Signer::from(&seeds[..]);
    let signers = [signer];
    invoke_signed(&instruction, &[source, destination, authority], &signers)
}

/// Mint zkBTC tokens to a user account
///
/// # Arguments
/// * `mint` - The zkBTC mint account
/// * `destination` - The user's token account
/// * `authority` - The mint authority (pool PDA)
/// * `amount` - Amount to mint (in satoshis)
/// * `signer_seeds` - PDA signer seeds
pub fn mint_zkbtc(
    token_program: &AccountInfo,
    mint: &AccountInfo,
    destination: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = [0u8; 9];
    data[0] = token_instruction::MINT_TO;
    data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        AccountMeta::writable(mint.key()),
        AccountMeta::writable(destination.key()),
        AccountMeta::readonly_signer(authority.key()),
    ];

    let instruction = Instruction {
        program_id: token_program.key(),
        accounts: &accounts,
        data: &data,
    };

    let seeds: [Seed; 2] = [Seed::from(signer_seeds[0]), Seed::from(signer_seeds[1])];
    let signer = Signer::from(&seeds[..]);
    let signers = [signer];

    invoke_signed(&instruction, &[mint, destination, authority], &signers)
}

/// Burn zkBTC tokens from a user account
///
/// # Arguments
/// * `mint` - The zkBTC mint account
/// * `source` - The user's token account to burn from
/// * `authority` - The token account authority (user)
/// * `amount` - Amount to burn (in satoshis)
pub fn burn_zkbtc(
    token_program: &AccountInfo,
    mint: &AccountInfo,
    source: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
) -> ProgramResult {
    let mut data = [0u8; 9];
    data[0] = token_instruction::BURN;
    data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        AccountMeta::writable(source.key()),
        AccountMeta::writable(mint.key()),
        AccountMeta::readonly_signer(authority.key()),
    ];

    let instruction = Instruction {
        program_id: token_program.key(),
        accounts: &accounts,
        data: &data,
    };

    invoke(&instruction, &[source, mint, authority])
}

/// Burn zkBTC tokens from a PDA-controlled account (e.g., pool vault)
///
/// # Arguments
/// * `mint` - The zkBTC mint account
/// * `source` - The PDA-controlled token account to burn from
/// * `authority` - The PDA authority
/// * `amount` - Amount to burn (in satoshis)
/// * `signer_seeds` - PDA signer seeds
pub fn burn_zkbtc_signed(
    token_program: &AccountInfo,
    mint: &AccountInfo,
    source: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = [0u8; 9];
    data[0] = token_instruction::BURN;
    data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        AccountMeta::writable(source.key()),
        AccountMeta::writable(mint.key()),
        AccountMeta::readonly_signer(authority.key()),
    ];

    let instruction = Instruction {
        program_id: token_program.key(),
        accounts: &accounts,
        data: &data,
    };

    let seeds: [Seed; 2] = [Seed::from(signer_seeds[0]), Seed::from(signer_seeds[1])];
    let signer = Signer::from(&seeds[..]);
    let signers = [signer];

    invoke_signed(&instruction, &[source, mint, authority], &signers)
}

/// Transfer tokens between accounts.
/// Uses the passed token_program's key so it works with both
/// legacy Token program and Token-2022.
pub fn transfer_zkbtc(
    token_program: &AccountInfo,
    source: &AccountInfo,
    destination: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
    signer_seeds: &[&[u8]],
) -> ProgramResult {
    let mut data = [0u8; 9];
    data[0] = token_instruction::TRANSFER;
    data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        AccountMeta::writable(source.key()),
        AccountMeta::writable(destination.key()),
        AccountMeta::readonly_signer(authority.key()),
    ];

    let instruction = Instruction {
        program_id: token_program.key(),
        accounts: &accounts,
        data: &data,
    };

    if signer_seeds.is_empty() {
        invoke(&instruction, &[source, destination, authority])
    } else {
        let seeds: [Seed; 2] = [Seed::from(signer_seeds[0]), Seed::from(signer_seeds[1])];
        let signer = Signer::from(&seeds[..]);
        let signers = [signer];
        invoke_signed(&instruction, &[source, destination, authority], &signers)
    }
}

/// Transfer tokens from a user-signed account (no PDA signing needed).
/// Uses the passed token_program account's key so it works with both
/// legacy Token program and Token-2022.
pub fn transfer_token_user(
    token_program: &AccountInfo,
    source: &AccountInfo,
    destination: &AccountInfo,
    authority: &AccountInfo,
    amount: u64,
) -> ProgramResult {
    let mut data = [0u8; 9];
    data[0] = token_instruction::TRANSFER;
    data[1..9].copy_from_slice(&amount.to_le_bytes());

    let accounts = [
        AccountMeta::writable(source.key()),
        AccountMeta::writable(destination.key()),
        AccountMeta::readonly_signer(authority.key()),
    ];

    let instruction = Instruction {
        program_id: token_program.key(),
        accounts: &accounts,
        data: &data,
    };

    invoke(&instruction, &[source, destination, authority])
}

#[cfg(test)]
mod mint_validation_tests {
    use super::*;

    fn valid_mint(pool: &Pubkey) -> Vec<u8> {
        let mut data = vec![0u8; SPL_MINT_BASE_LEN];
        data[0..4].copy_from_slice(&1u32.to_le_bytes());
        data[4..36].copy_from_slice(pool.as_ref());
        data[SPL_MINT_DECIMALS_OFFSET] = 8;
        data[SPL_MINT_INITIALIZED_OFFSET] = 1;
        data
    }

    fn with_extension(mut data: Vec<u8>, extension_type: u16) -> Vec<u8> {
        data.resize(TOKEN_2022_TLV_OFFSET, 0);
        data[TOKEN_2022_ACCOUNT_TYPE_OFFSET] = 1;
        data.extend_from_slice(&extension_type.to_le_bytes());
        data.extend_from_slice(&1u16.to_le_bytes());
        data.push(0);
        data
    }

    #[test]
    fn accepts_pool_controlled_initialized_eight_decimal_mint() {
        let pool = [7u8; 32];
        assert!(validate_pool_controlled_zkbtc_mint_data(&valid_mint(&pool), &pool).is_ok());
    }

    #[test]
    fn rejects_external_mint_authority() {
        let pool = [7u8; 32];
        let mut data = valid_mint(&pool);
        data[4..36].copy_from_slice(&[8u8; 32]);
        assert!(validate_pool_controlled_zkbtc_mint_data(&data, &pool).is_err());
    }

    #[test]
    fn rejects_permanent_delegate_and_transfer_hook() {
        let pool = [7u8; 32];
        for extension_type in [EXT_PERMANENT_DELEGATE, EXT_TRANSFER_HOOK] {
            let data = with_extension(valid_mint(&pool), extension_type);
            assert!(validate_pool_controlled_zkbtc_mint_data(&data, &pool).is_err());
        }
    }
}

/// Check if account is owned by either Token or Token-2022 program
#[inline(always)]
pub fn is_token_account(account: &AccountInfo) -> bool {
    use crate::constants::{TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID};
    let owner = account.owner().as_ref();
    owner == TOKEN_2022_PROGRAM_ID || owner == TOKEN_PROGRAM_ID
}

/// Validate token account basics (works with both Token and Token-2022)
pub fn validate_token_account(
    account: &AccountInfo,
    expected_mint: &Pubkey,
    expected_owner: &Pubkey,
) -> Result<(), ProgramError> {
    if !is_token_account(account) {
        return Err(ProgramError::InvalidAccountOwner);
    }

    // Token account data layout:
    // [0..32] mint
    // [32..64] owner
    // [64..72] amount
    // ...
    let data = account.try_borrow_data()?;
    if data.len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Check mint
    let mint = Pubkey::from(<[u8; 32]>::try_from(&data[0..32]).unwrap());
    if &mint != expected_mint {
        return Err(ProgramError::InvalidAccountData);
    }

    // Check owner
    let owner = Pubkey::from(<[u8; 32]>::try_from(&data[32..64]).unwrap());
    if &owner != expected_owner {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::is_native_sol_mint;
    use crate::constants::{
        NATIVE_SOL_2022_MINT, NATIVE_SOL_MINT, TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID,
    };
    use pinocchio::pubkey::Pubkey;

    #[test]
    fn detects_native_mint_for_matching_token_program() {
        let token = Pubkey::from(TOKEN_PROGRAM_ID);
        let token_2022 = Pubkey::from(TOKEN_2022_PROGRAM_ID);
        assert!(is_native_sol_mint(&NATIVE_SOL_MINT, &token));
        assert!(is_native_sol_mint(&NATIVE_SOL_2022_MINT, &token_2022));
    }

    #[test]
    fn rejects_native_mint_with_wrong_program() {
        let token = Pubkey::from(TOKEN_PROGRAM_ID);
        let token_2022 = Pubkey::from(TOKEN_2022_PROGRAM_ID);
        assert!(!is_native_sol_mint(&NATIVE_SOL_MINT, &token_2022));
        assert!(!is_native_sol_mint(&NATIVE_SOL_2022_MINT, &token));
    }
}

/// Get token account balance
pub fn get_token_balance(account: &AccountInfo) -> Result<u64, ProgramError> {
    let data = account.try_borrow_data()?;
    if data.len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(u64::from_le_bytes(data[64..72].try_into().unwrap()))
}
