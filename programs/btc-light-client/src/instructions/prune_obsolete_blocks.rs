use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

use crate::constants::{
    BLOCK_HEADER_DISCRIMINATOR, BLOCK_HEADER_SEED, HEIGHT_INDEX_DISCRIMINATOR, HEIGHT_INDEX_SEED,
};
use crate::state::{BitcoinLightClient, BlockHeader, HeightIndex};

/// Close a non-canonical (orphaned) BlockHeader PDA, recovering rent.
/// Permissionless — anyone can prune obsolete blocks.
///
/// Instruction data (after discriminator):
///   [0-31]  block_hash (32 bytes)
///
/// Accounts:
///   0. []              BitcoinLightClient (read-only)
///   1. [writable]      BlockHeader PDA to close (["block", block_hash])
///   2. []              HeightIndex PDA at same height (proves non-canonical)
///   3. [writable]      Rent receiver
pub fn process_prune_obsolete_blocks(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 32 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if accounts.len() < 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let light_client_info = &accounts[0];
    let block_header_info = &accounts[1];
    let height_index_info = &accounts[2];
    let rent_receiver = &accounts[3];

    // Validate ownership
    if light_client_info.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if block_header_info.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }
    if height_index_info.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&data[0..32]);

    // Verify BlockHeader PDA address
    let (expected_header_pda, _) =
        pinocchio::pubkey::find_program_address(&[BLOCK_HEADER_SEED, &block_hash], program_id);
    if block_header_info.key() != &expected_header_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Read block header to get height and verify hash
    let block_height = {
        let header_data = block_header_info.try_borrow_data()?;
        if header_data.len() < BlockHeader::LEN || header_data[0] != BLOCK_HEADER_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let header = unsafe { &*(header_data.as_ptr() as *const BlockHeader) };
        if header.block_hash != block_hash {
            return Err(ProgramError::InvalidArgument);
        }
        header.height()
    };

    // Verify HeightIndex PDA at this height
    let height_le = block_height.to_le_bytes();
    let (expected_hi_pda, _) =
        pinocchio::pubkey::find_program_address(&[HEIGHT_INDEX_SEED, &height_le], program_id);
    if height_index_info.key() != &expected_hi_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Read HeightIndex — the canonical hash at this height must differ
    {
        let hi_data = height_index_info.try_borrow_data()?;
        if hi_data.len() < HeightIndex::LEN || hi_data[0] != HEIGHT_INDEX_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let hi = unsafe { &*(hi_data.as_ptr() as *const HeightIndex) };
        // If the canonical hash matches this block, it's NOT orphaned — can't prune
        if hi.block_hash == block_hash {
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Verify block is below finalized_height (deep enough to be certain)
    {
        let lc_data = light_client_info.try_borrow_data()?;
        let lc = BitcoinLightClient::from_bytes(&lc_data)?;
        let finalized = u64::from_le_bytes(lc.finalized_height);
        if block_height > finalized {
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Close BlockHeader account: zero data, transfer lamports to receiver
    {
        let mut header_data = block_header_info.try_borrow_mut_data()?;
        header_data.fill(0);
    }

    // Transfer lamports
    let header_lamports = block_header_info.lamports();
    // Subtract from block header
    unsafe {
        *block_header_info.borrow_mut_lamports_unchecked() = 0;
    }
    // Add to rent receiver
    unsafe {
        *rent_receiver.borrow_mut_lamports_unchecked() = rent_receiver
            .lamports()
            .checked_add(header_lamports)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }

    // Reassign to system program (all zeros = system program)
    unsafe { block_header_info.assign(&[0u8; 32]) };

    Ok(())
}
