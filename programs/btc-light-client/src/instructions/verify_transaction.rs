use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::CreateAccount;

use crate::constants::{
    BLOCK_HEADER_DISCRIMINATOR, BLOCK_HEADER_SEED, HEIGHT_INDEX_DISCRIMINATOR, HEIGHT_INDEX_SEED,
    REQUIRED_CONFIRMATIONS, VERIFIED_TX_DISCRIMINATOR, VERIFIED_TX_SEED,
};
use crate::state::{BitcoinLightClient, BlockHeader, HeightIndex, VerifiedTransaction};
use crate::utils::{double_sha256, double_sha256_pair};

/// Verify a Bitcoin transaction's inclusion in a confirmed block, creating a VerifiedTransaction PDA.
///
/// Instruction data (after discriminator):
///   [0-31]   txid         ([u8; 32])
///   [32-63]  block_hash   ([u8; 32])    ← was block_height(8)
///   [64-67]  tx_size      (u32 LE)
///   [68+]    merkle_proof: [txid(32)][path_bits(4)][path_len(1)][tx_index(4)][siblings...]
///
/// Accounts:
///   0. [writable, PDA] VerifiedTransaction (to create)
///   1. []              BitcoinLightClient
///   2. []              BlockHeader (["block", block_hash])
///   3. []              HeightIndex (["height_index", block_height])
///   4. []              ChadBuffer (raw tx)
///   5. [signer, writable] Payer
///   6. []              System program
pub fn process_verify_transaction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 68 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if accounts.len() < 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let verified_tx_info = &accounts[0];
    let light_client_info = &accounts[1];
    let block_header_info = &accounts[2];
    let height_index_info = &accounts[3];
    let tx_buffer_info = &accounts[4];
    let payer = &accounts[5];
    let _system_program = &accounts[6];

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

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

    // Parse instruction data
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&data[0..32]);
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&data[32..64]);
    let tx_size = u32::from_le_bytes(data[64..68].try_into().unwrap());

    // Verify BlockHeader PDA address: ["block", block_hash]
    let (expected_header_pda, _) =
        pinocchio::pubkey::find_program_address(&[BLOCK_HEADER_SEED, &block_hash], program_id);
    if block_header_info.key() != &expected_header_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Parse merkle proof from remaining data
    let proof_data = &data[68..];
    if proof_data.len() < 41 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut proof_txid = [0u8; 32];
    proof_txid.copy_from_slice(&proof_data[0..32]);
    let path_bits = u32::from_le_bytes(proof_data[32..36].try_into().unwrap());
    let path_len = proof_data[36];
    let tx_index = u32::from_le_bytes(proof_data[37..41].try_into().unwrap());

    if path_len as usize > 20 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let siblings_start = 41;
    let expected_proof_len = siblings_start + path_len as usize * 32;
    if proof_data.len() < expected_proof_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Verify block header and get merkle_root + height
    let (block_merkle_root, block_height) = {
        let header_data = block_header_info.try_borrow_data()?;
        if header_data.len() < BlockHeader::LEN || header_data[0] != BLOCK_HEADER_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let header = unsafe { &*(header_data.as_ptr() as *const BlockHeader) };

        // Verify the stored block_hash matches the one in instruction data
        if header.block_hash != block_hash {
            return Err(ProgramError::InvalidArgument);
        }

        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(&header.merkle_root);
        (merkle_root, header.height())
    };

    let height_le = block_height.to_le_bytes();
    let (expected_hi_pda, _) =
        pinocchio::pubkey::find_program_address(&[HEIGHT_INDEX_SEED, &height_le], program_id);
    if height_index_info.key() != &expected_hi_pda {
        return Err(ProgramError::InvalidSeeds);
    }
    {
        let hi_data = height_index_info.try_borrow_data()?;
        if hi_data.len() < HeightIndex::LEN || hi_data[0] != HEIGHT_INDEX_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let hi = unsafe { &*(hi_data.as_ptr() as *const HeightIndex) };
        if hi.height != height_le || hi.block_hash != block_hash {
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Verify sufficient confirmations
    {
        let lc_data = light_client_info.try_borrow_data()?;
        let lc = BitcoinLightClient::from_bytes(&lc_data)?;
        let tip = lc.tip_height();
        let confirmations = if block_height > tip {
            0
        } else {
            tip - block_height + 1
        };
        if confirmations < REQUIRED_CONFIRMATIONS {
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Read raw tx from ChadBuffer and verify hash
    {
        let buffer_data = tx_buffer_info
            .try_borrow_data()
            .map_err(|_| ProgramError::InvalidAccountData)?;
        // ChadBuffer format: 32-byte authority pubkey header, then data
        if buffer_data.len() < 32 + tx_size as usize {
            return Err(ProgramError::InvalidAccountData);
        }
        let raw_tx = &buffer_data[32..32 + tx_size as usize];
        let computed_hash = double_sha256(raw_tx);
        if computed_hash != txid {
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Verify merkle proof
    if proof_txid != txid {
        return Err(ProgramError::InvalidArgument);
    }
    {
        let mut current = txid;
        for i in 0..path_len as usize {
            let sibling_offset = siblings_start + i * 32;
            let mut sibling = [0u8; 32];
            sibling.copy_from_slice(&proof_data[sibling_offset..sibling_offset + 32]);
            let is_right = (path_bits >> i) & 1 == 1;
            current = if is_right {
                double_sha256_pair(&sibling, &current)
            } else {
                double_sha256_pair(&current, &sibling)
            };
        }
        if current != block_merkle_root {
            return Err(ProgramError::InvalidArgument);
        }
    }

    // Derive VerifiedTransaction PDA: ["verified_tx", block_hash, txid]
    let (expected_pda, bump) = pinocchio::pubkey::find_program_address(
        &[VERIFIED_TX_SEED, &block_hash, &txid],
        program_id,
    );
    if verified_tx_info.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Idempotent: if already exists, return Ok
    if verified_tx_info.data_len() != 0 {
        if verified_tx_info.owner() != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let existing_data = verified_tx_info.try_borrow_data()?;
        if existing_data[0] == VERIFIED_TX_DISCRIMINATOR {
            return Ok(());
        }
    }

    // Create the VerifiedTransaction account
    let bump_bytes = [bump];
    let signer_seeds: [Seed; 4] = [
        Seed::from(VERIFIED_TX_SEED),
        Seed::from(block_hash.as_slice()),
        Seed::from(txid.as_slice()),
        Seed::from(&bump_bytes),
    ];
    let signer = [Signer::from(&signer_seeds)];

    let rent = pinocchio::sysvars::rent::Rent::get()?;
    let lamports = rent.minimum_balance(VerifiedTransaction::LEN);

    CreateAccount {
        from: payer,
        to: verified_tx_info,
        lamports,
        space: VerifiedTransaction::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&signer)?;

    // Initialize
    {
        let mut vt_data = verified_tx_info.try_borrow_mut_data()?;
        vt_data[..VerifiedTransaction::LEN].fill(0);
        vt_data[0] = VERIFIED_TX_DISCRIMINATOR;

        let vt = unsafe { &mut *(vt_data.as_mut_ptr() as *mut VerifiedTransaction) };
        vt.bump = bump;
        vt.block_height = (block_height as u32).to_le_bytes();
        vt.block_hash = block_hash;
        vt.txid = txid;
        vt.tx_index = tx_index.to_le_bytes();

        let clock = Clock::get()?;
        vt.verified_at = clock.unix_timestamp.to_le_bytes();
    }

    Ok(())
}
