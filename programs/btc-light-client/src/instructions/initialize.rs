use pinocchio::{
    account_info::AccountInfo,
    instruction::{Seed, Signer},
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvars::{clock::Clock, Sysvar},
    ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

use crate::constants::{
    BLOCK_HEADER_DISCRIMINATOR, BLOCK_HEADER_SEED, BTC_LIGHT_CLIENT_DISCRIMINATOR,
    HEIGHT_INDEX_DISCRIMINATOR, HEIGHT_INDEX_SEED, LIGHT_CLIENT_SEED, NETWORK_MAINNET,
    NETWORK_REGTEST, NETWORK_TESTNET4, REQUIRED_CONFIRMATIONS,
};
use crate::state::{BitcoinLightClient, BlockHeader, HeightIndex};

/// Initialize the Bitcoin Light Client PDA + genesis HeightIndex + genesis BlockHeader.
///
/// Instruction data (after discriminator):
///   [0-7]   start_height       (u64 LE)
///   [8-39]  start_block_hash   ([u8; 32])
///   [40]    network            (u8: 0=mainnet, 2=testnet4, 3=regtest)
///   [41-44] initial_bits       (u32 LE, optional — 0 to skip)
///   [45-48] epoch_start_time   (u32 LE, optional — 0 to skip)
///   [49-52] start_timestamp    (u32 LE, optional — 0 to skip)
///   [53-56] start_bits         (u32 LE, optional — 0 to skip)
///
/// Accounts:
///   0. [writable] BitcoinLightClient PDA (["btc_light_client"])
///   1. [signer, writable] Payer (becomes authority)
///   2. [] System program
///   3. [writable] HeightIndex PDA (["height_index", start_height])
///   4. [writable] BlockHeader PDA (["block", start_block_hash])
pub fn process_initialize(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if data.len() < 41 {
        return Err(ProgramError::InvalidInstructionData);
    }
    if accounts.len() < 5 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let light_client_info = &accounts[0];
    let payer = &accounts[1];
    let _system_program = &accounts[2];
    let height_index_info = &accounts[3];
    let block_header_info = &accounts[4];

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Parse instruction data
    let start_height = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let mut start_block_hash = [0u8; 32];
    start_block_hash.copy_from_slice(&data[8..40]);
    let network = data[40];
    if network != NETWORK_MAINNET && network != NETWORK_TESTNET4 && network != NETWORK_REGTEST {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Derive and create LightClient PDA
    let (expected_pda, bump) =
        pinocchio::pubkey::find_program_address(&[LIGHT_CLIENT_SEED], program_id);
    if light_client_info.key() != &expected_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let bump_bytes = [bump];
    let signer_seeds: [Seed; 2] = [Seed::from(LIGHT_CLIENT_SEED), Seed::from(&bump_bytes)];
    let signer = [Signer::from(&signer_seeds)];

    let rent = pinocchio::sysvars::rent::Rent::get()?;
    let lamports = rent.minimum_balance(BitcoinLightClient::LEN);

    // Reject re-initialization of an already-initialized client.
    if light_client_info.data_len() >= 1
        && light_client_info.try_borrow_data()?[0] == BTC_LIGHT_CLIENT_DISCRIMINATOR
    {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    if light_client_info.lamports() == 0 {
        CreateAccount {
            from: payer,
            to: light_client_info,
            lamports,
            space: BitcoinLightClient::LEN as u64,
            owner: program_id,
        }
        .invoke_signed(&signer)?;
    } else {
        // Pre-funded PDA (a griefer can transfer lamports to the known address to make a
        // bare CreateAccount fail): top up rent, then allocate + assign so init still succeeds.
        let current = light_client_info.lamports();
        if lamports > current {
            Transfer {
                from: payer,
                to: light_client_info,
                lamports: lamports - current,
            }
            .invoke()?;
        }
        if light_client_info.data_len() < BitcoinLightClient::LEN {
            Allocate {
                account: light_client_info,
                space: BitcoinLightClient::LEN as u64,
            }
            .invoke_signed(&signer)?;
        }
        if light_client_info.owner() != program_id {
            Assign {
                account: light_client_info,
                owner: program_id,
            }
            .invoke_signed(&signer)?;
        }
    }

    // Initialize light client fields
    let mut lc_data = light_client_info.try_borrow_mut_data()?;
    lc_data[..BitcoinLightClient::LEN].fill(0);
    lc_data[0] = BTC_LIGHT_CLIENT_DISCRIMINATOR;

    let lc = unsafe { &mut *(lc_data.as_mut_ptr() as *mut BitcoinLightClient) };
    lc.bump = bump;
    lc.network = network;
    lc.authority.copy_from_slice(payer.key());
    lc.genesis_hash = start_block_hash;
    lc.tip_hash = start_block_hash;
    lc.set_tip_height(start_height);
    lc.set_finalized_height(start_height.saturating_sub(REQUIRED_CONFIRMATIONS));
    lc.set_header_count(0);

    let clock = Clock::get()?;
    lc.set_last_update(clock.unix_timestamp);

    lc.total_chainwork = [0u8; 32];

    // Set initial difficulty params if provided
    let mut initial_bits = 0u32;
    let mut epoch_start = 0u32;
    let mut start_timestamp = 0u32;
    let mut start_bits = 0u32;
    if data.len() >= 49 {
        initial_bits = u32::from_le_bytes(data[41..45].try_into().unwrap());
        epoch_start = u32::from_le_bytes(data[45..49].try_into().unwrap());
        if initial_bits != 0 {
            lc.set_expected_bits(initial_bits);
        }
        if epoch_start != 0 {
            lc.set_epoch_start_time(epoch_start);
        }
    }
    if data.len() >= 53 {
        start_timestamp = u32::from_le_bytes(data[49..53].try_into().unwrap());
    }
    if data.len() >= 57 {
        start_bits = u32::from_le_bytes(data[53..57].try_into().unwrap());
    }
    if start_bits == 0 {
        start_bits = initial_bits;
    }

    // Production networks MUST be seeded with difficulty params, otherwise extend_blockchain
    // cannot enforce PoW difficulty (required_bits would be 0). Checkpoint at a known epoch
    // so `epoch_start_time` is the timestamp of the first block of the current epoch.
    if (network == NETWORK_MAINNET || network == NETWORK_TESTNET4)
        && (initial_bits == 0 || epoch_start == 0)
    {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Drop the borrow before creating more accounts
    drop(lc_data);

    // Create genesis BlockHeader PDA: ["block", start_block_hash]
    let (expected_bh_pda, bh_bump) = pinocchio::pubkey::find_program_address(
        &[BLOCK_HEADER_SEED, &start_block_hash],
        program_id,
    );
    if block_header_info.key() != &expected_bh_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let bh_bump_bytes = [bh_bump];
    let bh_signer_seeds: [Seed; 3] = [
        Seed::from(BLOCK_HEADER_SEED),
        Seed::from(start_block_hash.as_slice()),
        Seed::from(&bh_bump_bytes),
    ];
    let bh_signer = [Signer::from(&bh_signer_seeds)];

    let bh_lamports = rent.minimum_balance(BlockHeader::LEN);
    CreateAccount {
        from: payer,
        to: block_header_info,
        lamports: bh_lamports,
        space: BlockHeader::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&bh_signer)?;

    // Initialize genesis BlockHeader (minimal — we only know hash and height)
    {
        let mut bh_data = block_header_info.try_borrow_mut_data()?;
        bh_data[..BlockHeader::LEN].fill(0);
        bh_data[0] = BLOCK_HEADER_DISCRIMINATOR;

        let bh = unsafe { &mut *(bh_data.as_mut_ptr() as *mut BlockHeader) };
        bh.block_hash = start_block_hash;
        bh.height = start_height.to_le_bytes();
        bh.timestamp = start_timestamp.to_le_bytes();
        bh.bits = start_bits.to_le_bytes();
        bh.set_epoch_bits(initial_bits);
        bh.set_epoch_start_time(epoch_start);
        bh.submitted_at = clock.unix_timestamp.to_le_bytes();
    }

    // Create genesis HeightIndex PDA: ["height_index", start_height]
    let height_le = start_height.to_le_bytes();
    let (expected_hi_pda, hi_bump) =
        pinocchio::pubkey::find_program_address(&[HEIGHT_INDEX_SEED, &height_le], program_id);
    if height_index_info.key() != &expected_hi_pda {
        return Err(ProgramError::InvalidSeeds);
    }

    let hi_bump_bytes = [hi_bump];
    let hi_signer_seeds: [Seed; 3] = [
        Seed::from(HEIGHT_INDEX_SEED),
        Seed::from(height_le.as_slice()),
        Seed::from(&hi_bump_bytes),
    ];
    let hi_signer = [Signer::from(&hi_signer_seeds)];

    let hi_lamports = rent.minimum_balance(HeightIndex::LEN);
    CreateAccount {
        from: payer,
        to: height_index_info,
        lamports: hi_lamports,
        space: HeightIndex::LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&hi_signer)?;

    // Initialize HeightIndex
    {
        let mut hi_data = height_index_info.try_borrow_mut_data()?;
        hi_data[0] = HEIGHT_INDEX_DISCRIMINATOR;

        let hi = unsafe { &mut *(hi_data.as_mut_ptr() as *mut HeightIndex) };
        hi.bump = hi_bump;
        hi._padding = [0u8; 6];
        hi.block_hash = start_block_hash;
        hi.height = height_le;
    }

    Ok(())
}
