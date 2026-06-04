//! Token-2022 helper functions for Pinocchio

use pinocchio::{
    account_info::AccountInfo,
    cpi::{invoke, invoke_signed},
    instruction::{AccountMeta, Instruction, Signer, Seed},
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

/// Token instruction discriminators (same for both Token and Token-2022)
mod token_instruction {
    pub const MINT_TO: u8 = 7;
    pub const BURN: u8 = 8;
    pub const TRANSFER: u8 = 3;
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

    let seeds: [Seed; 2] = [
        Seed::from(signer_seeds[0]),
        Seed::from(signer_seeds[1]),
    ];
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

    let seeds: [Seed; 2] = [
        Seed::from(signer_seeds[0]),
        Seed::from(signer_seeds[1]),
    ];
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
        let seeds: [Seed; 2] = [
            Seed::from(signer_seeds[0]),
            Seed::from(signer_seeds[1]),
        ];
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

/// Check if account is owned by either Token or Token-2022 program
#[inline(always)]
pub fn is_token_account(account: &AccountInfo) -> bool {
    use crate::constants::{TOKEN_2022_PROGRAM_ID, TOKEN_PROGRAM_ID};
    let owner = account.owner().as_ref();
    owner == &TOKEN_2022_PROGRAM_ID || owner == &TOKEN_PROGRAM_ID
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

/// Get token account balance
pub fn get_token_balance(account: &AccountInfo) -> Result<u64, ProgramError> {
    let data = account.try_borrow_data()?;
    if data.len() < 72 {
        return Err(ProgramError::InvalidAccountData);
    }

    Ok(u64::from_le_bytes(data[64..72].try_into().unwrap()))
}
