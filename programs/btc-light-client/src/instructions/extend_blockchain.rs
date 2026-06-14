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
    BLOCKS_PER_EPOCH, BLOCK_HEADER_DISCRIMINATOR, BLOCK_HEADER_SEED, HEIGHT_INDEX_DISCRIMINATOR,
    HEIGHT_INDEX_SEED, MAX_BATCH_SIZE, REQUIRED_CONFIRMATIONS,
};
use crate::state::{BitcoinLightClient, BlockHeader, HeightIndex};
use crate::utils::{
    add_chainwork, calculate_chainwork, double_sha256, hash_meets_target,
    required_bits_for_next_block, target_from_bits, u256_from_le_bytes, u256_gt_limbs,
};

/// Submit a batch of Bitcoin block headers, extending the blockchain.
/// Permissionless — anyone can submit. Supports forking from any existing block.
///
/// Instruction data (after discriminator):
///   [0]             num_headers: u8 (1..=10)
///   [1..1+N*80]     raw_headers: N × 80 bytes
///
/// Accounts:
///   0. [writable]           BitcoinLightClient PDA
///   1. [signer, writable]   Submitter (payer for new PDAs)
///   2. []                   System program
///   3. []                   Parent BlockHeader PDA (["block", first_header.prev_hash])
///      4..4+N-1   [writable]   BlockHeader PDAs (["block", hash_i])
///      4+N..4+2N-1 [writable]  HeightIndex PDAs (["height_index", height_i])
pub fn process_extend_blockchain(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let num_headers = data[0];
    if num_headers == 0 || num_headers > MAX_BATCH_SIZE {
        return Err(ProgramError::InvalidInstructionData);
    }

    let n = num_headers as usize;
    let expected_data_len = 1 + n * 80;
    if data.len() < expected_data_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Need: lc(1) + submitter(1) + system(1) + parent(1) + N block_headers + N height_indices
    let expected_accounts = 4 + 2 * n;
    if accounts.len() < expected_accounts {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let light_client_info = &accounts[0];
    let submitter = &accounts[1];
    let _system_program = &accounts[2];
    let parent_header_info = &accounts[3];

    if !submitter.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if light_client_info.owner() != program_id {
        return Err(ProgramError::IllegalOwner);
    }

    // Read parent block header to get starting height and chainwork
    let (
        parent_height,
        parent_chainwork,
        parent_hash,
        parent_timestamp,
        parent_epoch_bits,
        parent_epoch_start,
    ) = {
        if parent_header_info.owner() != program_id {
            return Err(ProgramError::IllegalOwner);
        }
        let parent_data = parent_header_info.try_borrow_data()?;
        if parent_data.len() < BlockHeader::LEN || parent_data[0] != BLOCK_HEADER_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        let parent = unsafe { &*(parent_data.as_ptr() as *const BlockHeader) };
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&parent.block_hash);
        let mut cw = [0u8; 32];
        cw.copy_from_slice(&parent.chainwork);
        let h = parent.height();
        let ts = u32::from_le_bytes(parent.timestamp);
        (
            h,
            cw,
            hash,
            ts,
            parent.epoch_bits(),
            parent.epoch_start_time(),
        )
    };

    // Read light client state
    let (network, _lc_tip_height, lc_chainwork, lc_expected_bits, lc_epoch_start_time) = {
        let lc_data = light_client_info.try_borrow_data()?;
        let lc = BitcoinLightClient::from_bytes(&lc_data)?;
        let mut cw = [0u8; 32];
        cw.copy_from_slice(&lc.total_chainwork);
        (
            lc.network,
            lc.tip_height(),
            cw,
            lc.expected_bits(),
            lc.epoch_start_time(),
        )
    };

    // Verify parent BlockHeader PDA address: seeds = ["block", parent_hash]
    let (expected_parent_pda, _) =
        pinocchio::pubkey::find_program_address(&[BLOCK_HEADER_SEED, &parent_hash], program_id);
    if parent_header_info.key() != &expected_parent_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    // Validate first header links to parent
    let first_prev_hash: &[u8; 32] = data[1 + 4..1 + 36].try_into().unwrap();
    if *first_prev_hash != parent_hash {
        return Err(ProgramError::InvalidArgument);
    }

    let clock = Clock::get()?;
    let rent = pinocchio::sysvars::rent::Rent::get()?;

    let mut prev_hash = parent_hash;
    let mut running_chainwork = parent_chainwork;
    let mut running_height = parent_height;
    // Track difficulty params for epoch boundary retarget
    let mut running_expected_bits = if parent_epoch_bits != 0 {
        parent_epoch_bits
    } else {
        lc_expected_bits
    };
    let mut running_epoch_start = if parent_epoch_start != 0 {
        parent_epoch_start
    } else {
        lc_epoch_start_time
    };
    let mut running_parent_timestamp = parent_timestamp;

    // Process each header in the batch
    for i in 0..n {
        let header_offset = 1 + i * 80;
        let raw_header: &[u8; 80] = data[header_offset..header_offset + 80].try_into().unwrap();

        let header_prev_hash: &[u8; 32] = raw_header[4..36].try_into().unwrap();
        let timestamp = u32::from_le_bytes(raw_header[68..72].try_into().unwrap());
        let bits = u32::from_le_bytes(raw_header[72..76].try_into().unwrap());

        // Validate chain continuity
        if *header_prev_hash != prev_hash {
            return Err(ProgramError::InvalidArgument);
        }

        let block_hash = double_sha256(raw_header);
        let block_height = running_height
            .checked_add(1)
            .ok_or(ProgramError::ArithmeticOverflow)?;

        // PoW and difficulty checks for production Bitcoin networks.
        if network == crate::constants::NETWORK_MAINNET
            || network == crate::constants::NETWORK_TESTNET4
        {
            let target = target_from_bits(bits);
            if !hash_meets_target(&block_hash, &target) {
                return Err(ProgramError::InvalidArgument);
            }

            // Difficulty params MUST be seeded for production networks. An unseeded (0)
            // value previously made required_bits_for_next_block return 0, which disabled
            // the bits check entirely and let an attacker grind a low-difficulty chain.
            if running_expected_bits == 0 {
                return Err(ProgramError::InvalidArgument);
            }

            let required_bits = required_bits_for_next_block(
                network == crate::constants::NETWORK_TESTNET4,
                block_height,
                timestamp,
                running_parent_timestamp,
                running_expected_bits,
                running_epoch_start,
            );
            // Always enforce the consensus difficulty — chainwork is derived from `bits`,
            // so an unconstrained `bits` would let a fork claim arbitrary work.
            if bits != required_bits {
                return Err(ProgramError::InvalidArgument);
            }
        }

        // Compute chainwork
        let block_work = calculate_chainwork(bits);
        let new_chainwork = add_chainwork(&running_chainwork, &block_work);

        let mut header_epoch_bits = running_expected_bits;
        let mut header_epoch_start = running_epoch_start;
        if (network == crate::constants::NETWORK_MAINNET
            || network == crate::constants::NETWORK_TESTNET4)
            && block_height % BLOCKS_PER_EPOCH == 0
        {
            header_epoch_bits = bits;
            header_epoch_start = timestamp;
        }

        // Derive and verify BlockHeader PDA: ["block", block_hash]
        let block_header_info = &accounts[4 + i];
        let (expected_pda, header_bump) =
            pinocchio::pubkey::find_program_address(&[BLOCK_HEADER_SEED, &block_hash], program_id);
        if block_header_info.key() != &expected_pda {
            return Err(ProgramError::InvalidSeeds);
        }
        if block_header_info.data_len() != 0 && block_header_info.owner() != program_id {
            return Err(ProgramError::IllegalOwner);
        }

        // Create BlockHeader PDA if it doesn't exist (idempotent — skip if already created)
        let account_exists = {
            let existing_data = block_header_info.try_borrow_data()?;
            !existing_data.is_empty()
                && existing_data.len() >= BlockHeader::LEN
                && existing_data[0] == BLOCK_HEADER_DISCRIMINATOR
        };

        if !account_exists {
            let header_bump_bytes = [header_bump];
            let header_signer_seeds: [Seed; 3] = [
                Seed::from(BLOCK_HEADER_SEED),
                Seed::from(block_hash.as_slice()),
                Seed::from(&header_bump_bytes),
            ];
            let header_signer = [Signer::from(&header_signer_seeds)];

            let lamports = rent.minimum_balance(BlockHeader::LEN);
            CreateAccount {
                from: submitter,
                to: block_header_info,
                lamports,
                space: BlockHeader::LEN as u64,
                owner: program_id,
            }
            .invoke_signed(&header_signer)?;
        }

        // Write block header data
        {
            let mut header_data = block_header_info.try_borrow_mut_data()?;
            header_data[..BlockHeader::LEN].fill(0);
            header_data[0] = BLOCK_HEADER_DISCRIMINATOR;

            let header = unsafe { &mut *(header_data.as_mut_ptr() as *mut BlockHeader) };
            header.version.copy_from_slice(&raw_header[0..4]);
            header.prev_block_hash.copy_from_slice(&raw_header[4..36]);
            header.merkle_root.copy_from_slice(&raw_header[36..68]);
            header.timestamp.copy_from_slice(&raw_header[68..72]);
            header.bits.copy_from_slice(&raw_header[72..76]);
            header.nonce.copy_from_slice(&raw_header[76..80]);
            header.block_hash = block_hash;
            header.height = block_height.to_le_bytes();
            header.chainwork = new_chainwork;
            header.set_epoch_bits(header_epoch_bits);
            header.set_epoch_start_time(header_epoch_start);
            header.submitted_at = clock.unix_timestamp.to_le_bytes();
        }

        prev_hash = block_hash;
        running_chainwork = new_chainwork;
        running_height = block_height;
        running_expected_bits = header_epoch_bits;
        running_epoch_start = header_epoch_start;
        running_parent_timestamp = timestamp;
    }

    // Determine if this new fork becomes canonical (has more chainwork than current tip)
    let is_new_canonical = {
        let new_cw = u256_from_le_bytes(&running_chainwork);
        let old_cw = u256_from_le_bytes(&lc_chainwork);
        u256_gt_limbs(new_cw, old_cw)
    };

    if is_new_canonical {
        // Create/update HeightIndex PDAs for each new block
        for i in 0..n {
            let header_offset = 1 + i * 80;
            let raw_header: &[u8; 80] = data[header_offset..header_offset + 80].try_into().unwrap();
            let block_hash = double_sha256(raw_header);
            let block_height = parent_height
                .checked_add(1)
                .and_then(|height| height.checked_add(i as u64))
                .ok_or(ProgramError::ArithmeticOverflow)?;
            let height_le = block_height.to_le_bytes();

            let height_index_info = &accounts[4 + n + i];
            let (expected_hi_pda, hi_bump) = pinocchio::pubkey::find_program_address(
                &[HEIGHT_INDEX_SEED, &height_le],
                program_id,
            );
            if height_index_info.key() != &expected_hi_pda {
                return Err(ProgramError::InvalidSeeds);
            }
            if height_index_info.data_len() != 0 && height_index_info.owner() != program_id {
                return Err(ProgramError::IllegalOwner);
            }

            // Check if HeightIndex already exists
            let hi_exists = {
                let existing_data = height_index_info.try_borrow_data()?;
                !existing_data.is_empty()
                    && existing_data.len() >= HeightIndex::LEN
                    && existing_data[0] == HEIGHT_INDEX_DISCRIMINATOR
            };

            if !hi_exists {
                // Create HeightIndex PDA
                let hi_bump_bytes = [hi_bump];
                let hi_signer_seeds: [Seed; 3] = [
                    Seed::from(HEIGHT_INDEX_SEED),
                    Seed::from(height_le.as_slice()),
                    Seed::from(&hi_bump_bytes),
                ];
                let hi_signer = [Signer::from(&hi_signer_seeds)];

                let lamports = rent.minimum_balance(HeightIndex::LEN);
                CreateAccount {
                    from: submitter,
                    to: height_index_info,
                    lamports,
                    space: HeightIndex::LEN as u64,
                    owner: program_id,
                }
                .invoke_signed(&hi_signer)?;
            }

            // Write HeightIndex data (overwrite if reorg makes this fork canonical)
            {
                let mut hi_data = height_index_info.try_borrow_mut_data()?;
                hi_data[0] = HEIGHT_INDEX_DISCRIMINATOR;

                let hi = unsafe { &mut *(hi_data.as_mut_ptr() as *mut HeightIndex) };
                hi.bump = hi_bump;
                hi._padding = [0u8; 6];
                hi.block_hash = block_hash;
                hi.height = height_le;
            }
        }

        // Update light client state
        {
            let mut lc_data = light_client_info.try_borrow_mut_data()?;
            let lc = BitcoinLightClient::from_bytes_mut(&mut lc_data)?;

            lc.tip_hash = prev_hash; // last block hash in batch
            lc.set_tip_height(running_height);
            let header_count = lc
                .header_count()
                .checked_add(n as u64)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            lc.set_header_count(header_count);
            lc.total_chainwork = running_chainwork;

            if running_height > REQUIRED_CONFIRMATIONS {
                lc.set_finalized_height(running_height - REQUIRED_CONFIRMATIONS);
            }

            // Update difficulty params
            if network == crate::constants::NETWORK_MAINNET
                || network == crate::constants::NETWORK_TESTNET4
            {
                lc.set_expected_bits(running_expected_bits);
                lc.set_epoch_start_time(running_epoch_start);
            }

            lc.set_last_update(clock.unix_timestamp);
        }
    } else {
        // Non-canonical fork: blocks are stored but tip is NOT updated.
        // HeightIndex PDAs are NOT created/updated for non-canonical forks.
        // Still count the headers.
        let mut lc_data = light_client_info.try_borrow_mut_data()?;
        let lc = BitcoinLightClient::from_bytes_mut(&mut lc_data)?;
        let header_count = lc
            .header_count()
            .checked_add(n as u64)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        lc.set_header_count(header_count);
        lc.set_last_update(clock.unix_timestamp);
    }

    Ok(())
}
