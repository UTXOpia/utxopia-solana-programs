//! ChadBuffer utilities for reading large transaction data
//!
//! ChadBuffer is a Solana program that allows storing large data chunks
//! in separate accounts. This module provides utilities to read raw
//! Bitcoin transaction data from ChadBuffer accounts.
//!
//! Reference: https://github.com/deanmlittle/chadbuffer

use pinocchio::account_info::AccountInfo;
use pinocchio::program_error::ProgramError;
use pinocchio::pubkey::Pubkey;

/// Validate that an account is owned by the ChadBuffer program.
/// Prevents attackers from passing crafted accounts with fake proof data.
#[inline(always)]
pub fn validate_chadbuffer_owner(account: &AccountInfo) -> Result<(), ProgramError> {
    if account.owner() != &CHADBUFFER_PROGRAM_ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}

/// ChadBuffer program ID
/// Localnet: GCqDhPcPa3ywzye9pgfC2YaFiRXQdTqX4XbzT79qVLu6 (regenerated; original keypair lost)
/// Devnet/Mainnet: C5RpjtTMFXKVZCtXSzKXD4CDNTaWBg3dVeMfYvjZYHDF
#[cfg(not(feature = "devnet"))]
pub const CHADBUFFER_PROGRAM_ID: Pubkey = [
    0xe1, 0xe7, 0x36, 0xce, 0x1d, 0xf6, 0x1d, 0x31, 0xdb, 0x0b, 0xf1, 0xa5, 0x3a, 0xad, 0xee, 0xca,
    0xc0, 0x99, 0x57, 0x22, 0x72, 0xf1, 0x75, 0x6b, 0x37, 0xc4, 0xc9, 0xe9, 0x6a, 0x46, 0xd5, 0x59,
];

#[cfg(feature = "devnet")]
pub const CHADBUFFER_PROGRAM_ID: Pubkey = [
    0xa4, 0x92, 0xf2, 0x6d, 0xc8, 0xe5, 0x36, 0x8b, 0xe6, 0xef, 0xa8, 0x84, 0x94, 0xdc, 0x7f, 0xbc,
    0xec, 0x8a, 0xc6, 0x58, 0xa0, 0x7e, 0xf4, 0x36, 0x76, 0x70, 0xde, 0xc6, 0x9b, 0xe5, 0xe0, 0xde,
];

/// Buffer header size (authority pubkey)
pub const BUFFER_HEADER_SIZE: usize = 32;

/// Read transaction data from a ChadBuffer account
///
/// # Arguments
/// * `buffer_data` - Raw account data from the buffer
/// * `transaction_size` - Expected size of the transaction
///
/// # Returns
/// Slice containing the raw transaction data (without header)
///
/// # Buffer Format
/// ```text
/// [authority (32 bytes)][raw_tx_data...]
/// ```
pub fn read_transaction_from_buffer(
    buffer_data: &[u8],
    transaction_size: usize,
) -> Result<&[u8], ProgramError> {
    // Minimum size: header + at least 1 byte of tx data
    if buffer_data.len() < BUFFER_HEADER_SIZE + 1 {
        return Err(ProgramError::InvalidAccountData);
    }

    // Check we have enough data
    let expected_size = BUFFER_HEADER_SIZE + transaction_size;
    if buffer_data.len() < expected_size {
        return Err(ProgramError::InvalidAccountData);
    }

    // Return slice after header
    Ok(&buffer_data[BUFFER_HEADER_SIZE..expected_size])
}

/// Validate that an account is a ChadBuffer account
///
/// Note: In production, you should verify the owner matches
/// the ChadBuffer program ID. This is a simplified check.
pub fn validate_buffer_account(
    account_data: &[u8],
    expected_authority: Option<&[u8; 32]>,
) -> Result<(), ProgramError> {
    if account_data.len() < BUFFER_HEADER_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }

    // If authority is specified, verify it matches
    if let Some(authority) = expected_authority {
        if &account_data[0..32] != authority {
            return Err(ProgramError::InvalidAccountData);
        }
    }

    Ok(())
}

/// Extract the authority pubkey from a ChadBuffer account
pub fn get_buffer_authority(buffer_data: &[u8]) -> Result<[u8; 32], ProgramError> {
    if buffer_data.len() < BUFFER_HEADER_SIZE {
        return Err(ProgramError::InvalidAccountData);
    }

    let mut authority = [0u8; 32];
    authority.copy_from_slice(&buffer_data[0..32]);
    Ok(authority)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_transaction_from_buffer() {
        // Create mock buffer: 32-byte header + 10-byte tx
        let mut buffer = vec![0u8; 32]; // header (authority)
        buffer.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]); // tx data

        let tx = read_transaction_from_buffer(&buffer, 10).unwrap();
        assert_eq!(tx, &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_buffer_too_small() {
        let buffer = vec![0u8; 31]; // Less than header size
        assert!(read_transaction_from_buffer(&buffer, 10).is_err());
    }

    #[test]
    fn test_insufficient_tx_data() {
        let mut buffer = vec![0u8; 32]; // header only
        buffer.extend_from_slice(&[1, 2, 3]); // only 3 bytes of tx

        assert!(read_transaction_from_buffer(&buffer, 10).is_err());
    }
}
