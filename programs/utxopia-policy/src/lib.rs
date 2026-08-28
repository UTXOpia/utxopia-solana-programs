#![cfg_attr(not(test), no_std)]

use ephemeral_rollups_pinocchio::{
    acl::{
        data_buffer_size, permission_pda_from_permissioned_account, CloseEphemeralPermission,
        CreateEphemeralPermission, EphemeralMembersArgs, Member, MemberFlags,
        PERMISSION_PROGRAM_ID,
    },
    consts::{
        DELEGATION_PROGRAM_ID, EPHEMERAL_VAULT_ID, EXTERNAL_UNDELEGATE_DISCRIMINATOR,
        MAGIC_CONTEXT_ID, MAGIC_PROGRAM_ID,
    },
    instruction::delegate_account,
    intent_bundle::MagicIntentBundleBuilder,
    pda::{
        delegate_buffer_pda_from_delegated_account_and_owner_program,
        delegation_metadata_pda_from_delegated_account,
        delegation_record_pda_from_delegated_account,
    },
    types::DelegateConfig,
};
use pinocchio::{
    cpi::{Seed, Signer},
    entrypoint,
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use solana_address::Address as SolanaAddress;

// No panic handler of our own: solana_address pulls in std, which already
// defines one, and a second definition fails the SBF link.

pub const ID: Address = Address::new_from_array([
    127, 138, 197, 238, 106, 229, 114, 241, 179, 216, 130, 79, 100, 240, 58, 143, 160, 74, 31,
    7, 220, 81, 204, 120, 6, 48, 208, 221, 123, 198, 3, 214,
]);
const ASSET_PROGRAM_ID: Address = Address::new_from_array([
    177, 47, 207, 226, 231, 90, 174, 9, 81, 157, 213, 140, 10, 174, 82, 49, 241, 201, 245,
    199, 35, 77, 222, 44, 97, 82, 155, 76, 251, 198, 64, 233,
]);
const TEE_VALIDATOR_ID: Address = Address::new_from_array([
    5, 61, 71, 26, 133, 158, 115, 46, 104, 11, 201, 88, 248, 65, 7, 43, 143, 63, 188, 25,
    115, 155, 230, 151, 196, 198, 129, 18, 111, 140, 31, 116,
]);
const POLICY_SEED: &[u8] = b"policy_approval";
const POOL_SEED: &[u8] = b"pool_state";
const POLICY_LEN: usize = 176;
const POOL_MIN_LEN: usize = 332;
const MAX_MEMBERS: usize = 8;
const PER_BUFFER_SIZE: usize = data_buffer_size(MAX_MEMBERS);
const INTENT_BUFFER_SIZE: usize = 1280;
const STATUS_PENDING: u8 = 0;
const STATUS_APPROVED: u8 = 1;
const STATUS_REJECTED: u8 = 2;
const STATUS_CONSUMED: u8 = 3;
const TARGET_POLICY: u8 = 2;

/// Mirrors `spend_is_allowed` in the asset program. This program holds the
/// account, so it re-decides rather than trusting the pool signature; a rule
/// that drifts from the asset program's stalls every approved spend in the CPI.
///
/// An unapproved exit never comes through here at all — it takes the asset
/// program's ragequit path, which consumes no approval.
fn spend_is_allowed(status: u8, slot: u64, expires_at: u64) -> bool {
    status == STATUS_APPROVED && slot <= expires_at
}

entrypoint!(process_instruction);

fn find(seeds: &[&[u8]], program: &Address) -> (Address, u8) {
    SolanaAddress::find_program_address(seeds, program)
}

fn owner(account: &AccountView) -> &Address {
    unsafe { account.owner() }
}

#[inline(never)]
fn process_instruction(
    program_id: &Address,
    accounts: &[AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    if instruction_data.len() >= 8 && instruction_data[..8] == EXTERNAL_UNDELEGATE_DISCRIMINATOR {
        if accounts.len() < 3 {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        return ephemeral_rollups_pinocchio::instruction::undelegate(
            &accounts[0],
            program_id,
            &accounts[1],
            &accounts[2],
            &instruction_data[8..],
        );
    }
    let (disc, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;
    match *disc {
        32 => delegate(program_id, accounts, data),
        34 => permission(program_id, accounts, data),
        36 => initialize(program_id, accounts, data),
        37 => decision(program_id, accounts, data),
        38 => commit(program_id, accounts, data),
        39 => consume(program_id, accounts, data),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

#[inline(never)]
fn validate_pool(pool: &AccountView) -> Result<([u8; 32], [u8; 32]), ProgramError> {
    if owner(pool) != &ASSET_PROGRAM_ID {
        return Err(ProgramError::InvalidAccountOwner);
    }
    let data = pool.try_borrow()?;
    if data.len() < POOL_MIN_LEN || data[0] != 1 || data[2] & 0x02 == 0 || data[2] & 0x04 != 0 {
        return Err(ProgramError::InvalidAccountData);
    }
    let mint: [u8; 32] = data[36..68].try_into().unwrap();
    let (expected, bump) = find(&[POOL_SEED, &mint], &ASSET_PROGRAM_ID);
    if pool.address() != &expected || data[1] != bump {
        return Err(ProgramError::InvalidSeeds);
    }
    let authority = data[4..36].try_into().unwrap();
    let auditor = data[264..296].try_into().unwrap();
    Ok((authority, auditor))
}

#[inline(never)]
fn approval_seeds<'a>(
    approval: &'a AccountView,
    pool: &'a AccountView,
    hash: &'a mut [u8; 32],
    nonce: &'a mut [u8; 32],
    refs: &'a mut [&'a [u8]; 4],
    program_id: &Address,
) -> Result<(&'a [&'a [u8]], u8), ProgramError> {
    let data = approval.try_borrow()?;
    if data.len() != POLICY_LEN || data[0] != 0x0c || data[1] != 1 || &data[16..48] != pool.address().as_ref() {
        return Err(ProgramError::InvalidAccountData);
    }
    hash.copy_from_slice(&data[112..144]);
    nonce.copy_from_slice(&data[144..176]);
    let (expected, bump) = find(&[POLICY_SEED, pool.address().as_ref(), hash, nonce], program_id);
    if approval.address() != &expected || data[3] != bump {
        return Err(ProgramError::InvalidSeeds);
    }
    refs[0] = POLICY_SEED;
    refs[1] = pool.address().as_ref();
    refs[2] = hash;
    refs[3] = nonce;
    Ok((&refs[..], bump))
}

#[inline(never)]
fn initialize(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() != 4 || data.len() != 105 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let payer = &accounts[0];
    let pool = &accounts[1];
    let approval = &accounts[2];
    let system = &accounts[3];
    if !payer.is_signer() || !approval.is_writable() || system.address() != &pinocchio_system::ID {
        return Err(ProgramError::InvalidAccountData);
    }
    let (_, auditor) = validate_pool(pool)?;
    // Keep in lockstep with utxopia's `is_permissioned_action`; the two lists are a
    // cross-program duplicate and `policy-allowlist-parity.test.ts` fails if they drift.
    // 13 transact · 14 unshield · 15 redeem · 22 complete_deposit_permissioned
    // · 23 shield_permissioned · 26 verify_deposit_permissioned
    if !matches!(data[0], 13 | 14 | 15 | 22 | 23 | 26) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let expires = u64::from_le_bytes(data[1..9].try_into().unwrap());
    if expires <= Clock::get()?.slot {
        return Err(ProgramError::InvalidArgument);
    }
    let hash: &[u8; 32] = data[41..73].try_into().unwrap();
    let nonce: &[u8; 32] = data[73..105].try_into().unwrap();
    let (expected, bump) = find(&[POLICY_SEED, pool.address().as_ref(), hash, nonce], program_id);
    if approval.address() != &expected || approval.lamports() != 0 {
        return Err(ProgramError::InvalidSeeds);
    }
    let bump_bytes = [bump];
    let raw = [POLICY_SEED, pool.address().as_ref(), hash, nonce, &bump_bytes];
    let seeds = [
        Seed::from(raw[0]), Seed::from(raw[1]), Seed::from(raw[2]),
        Seed::from(raw[3]), Seed::from(raw[4]),
    ];
    let rent = Rent::get()?.try_minimum_balance(POLICY_LEN)?
        .checked_add(ephemeral_rollups_pinocchio::ephemeral_accounts::rent(
            ephemeral_rollups_pinocchio::acl::EphemeralPermission::size_of(MAX_MEMBERS) as u32,
        ))
        .ok_or(ProgramError::ArithmeticOverflow)?;
    pinocchio_system::instructions::CreateAccount {
        from: payer,
        to: approval,
        lamports: rent,
        space: POLICY_LEN as u64,
        owner: program_id,
    }
    .invoke_signed(&[Signer::from(&seeds)])?;
    let mut state = approval.try_borrow_mut()?;
    state.fill(0);
    state[0] = 0x0c;
    state[1] = 1;
    state[2] = STATUS_PENDING;
    state[3] = bump;
    state[4] = data[0];
    state[8..16].copy_from_slice(&expires.to_le_bytes());
    state[16..48].copy_from_slice(pool.address().as_ref());
    state[48..80].copy_from_slice(&data[9..41]);
    state[80..112].copy_from_slice(&auditor);
    state[112..144].copy_from_slice(hash);
    state[144..176].copy_from_slice(nonce);
    Ok(())
}

#[inline(never)]
fn delegate(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() != 10 || data.len() != 37 || data[0] != TARGET_POLICY {
        return Err(ProgramError::InvalidInstructionData);
    }
    let payer = &accounts[0];
    let authority = &accounts[1];
    let pool = &accounts[2];
    let approval = &accounts[3];
    if !payer.is_signer() || !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (pool_authority, _) = validate_pool(pool)?;
    if authority.address().as_ref() != pool_authority {
        return Err(ProgramError::InvalidArgument);
    }
    if accounts[4].address() != program_id
        || accounts[8].address() != &pinocchio_system::ID
        || accounts[9].address() != &DELEGATION_PROGRAM_ID
        || !accounts[9].executable()
    {
        return Err(ProgramError::IncorrectProgramId);
    }
    if accounts[5].address() != &delegate_buffer_pda_from_delegated_account_and_owner_program(approval.address(), program_id)
        || accounts[6].address() != &delegation_record_pda_from_delegated_account(approval.address())
        || accounts[7].address() != &delegation_metadata_pda_from_delegated_account(approval.address())
    {
        return Err(ProgramError::InvalidSeeds);
    }
    let mut hash = [0; 32];
    let mut nonce = [0; 32];
    let mut refs = [&[][..]; 4];
    let (seeds, bump) = approval_seeds(approval, pool, &mut hash, &mut nonce, &mut refs, program_id)?;
    let mut validator = [0; 32];
    validator.copy_from_slice(&data[5..37]);
    if validator != *TEE_VALIDATOR_ID.as_array() {
        return Err(ProgramError::InvalidArgument);
    }
    delegate_account(
        &[payer, approval, &accounts[4], &accounts[5], &accounts[6], &accounts[7], &accounts[8]],
        seeds,
        bump,
        DelegateConfig {
            commit_frequency_ms: u32::from_le_bytes(data[1..5].try_into().unwrap()),
            validator: Some(Address::new_from_array(validator)),
        },
    )
}

#[inline(never)]
fn permission(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() != 7 || data.len() < 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let authority = &accounts[0];
    let pool = &accounts[1];
    let approval = &accounts[2];
    let permission = &accounts[3];
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let (pool_authority, _) = validate_pool(pool)?;
    if authority.address().as_ref() != pool_authority
        || permission.address() != &permission_pda_from_permissioned_account(approval.address())
        || accounts[4].address() != &EPHEMERAL_VAULT_ID
        || accounts[5].address() != &MAGIC_PROGRAM_ID
        || accounts[6].address() != &PERMISSION_PROGRAM_ID
    {
        return Err(ProgramError::InvalidArgument);
    }
    let operation = data[0];
    if data[1] != TARGET_POLICY {
        return Err(ProgramError::InvalidInstructionData);
    }
    let count = data[2] as usize;
    if operation == 2 {
        if count != 0 || data.len() != 3 {
            return Err(ProgramError::InvalidInstructionData);
        }
    } else if operation != 0 || count == 0 || count > MAX_MEMBERS || data.len() != 3 + count * 33 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut hash = [0; 32];
    let mut nonce = [0; 32];
    let mut refs = [&[][..]; 4];
    let (raw_seeds, bump) = approval_seeds(approval, pool, &mut hash, &mut nonce, &mut refs, program_id)?;
    let bump_bytes = [bump];
    let signer_seeds = [
        Seed::from(raw_seeds[0]), Seed::from(raw_seeds[1]), Seed::from(raw_seeds[2]),
        Seed::from(raw_seeds[3]), Seed::from(&bump_bytes),
    ];
    let signers = [Signer::from(&signer_seeds)];
    if operation == 2 {
        return CloseEphemeralPermission {
            permissioned_account: approval,
            permission,
            payer: approval,
            authority,
            vault: &accounts[4],
            magic_program: &accounts[5],
            permission_program: &accounts[6],
            authority_is_signer: true,
        }.invoke_signed(&signers);
    }
    let mut members = core::array::from_fn::<_, MAX_MEMBERS, _>(|_| Member {
        flags: MemberFlags::new(),
        pubkey: Address::new_from_array([0; 32]),
    });
    let mut has_authority = false;
    for (i, raw) in data[3..].chunks_exact(33).enumerate() {
        if raw[0] & !0x1f != 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
        if raw[0] & MemberFlags::AUTHORITY != 0 {
            has_authority = true;
        }
        let mut key = [0; 32];
        key.copy_from_slice(&raw[1..]);
        members[i] = Member {
            flags: MemberFlags::from_acl_flag_byte(raw[0]),
            pubkey: Address::new_from_array(key),
        };
    }
    if !has_authority {
        return Err(ProgramError::InvalidInstructionData);
    }
    CreateEphemeralPermission {
        permissioned_account: approval,
        permission,
        payer: approval,
        vault: &accounts[4],
        magic_program: &accounts[5],
        permission_program: &accounts[6],
        args: EphemeralMembersArgs { is_private: true, members: &members[..count] },
    }.invoke_signed::<PER_BUFFER_SIZE>(&signers)
}

#[inline(never)]
fn decision(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() != 2 || data.len() != 1 || !matches!(data[0], 1 | 2) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let authority = &accounts[0];
    let approval = &accounts[1];
    if !authority.is_signer() || owner(approval) != program_id || !approval.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    let mut state = approval.try_borrow_mut()?;
    if state.len() != POLICY_LEN || state[0] != 0x0c || state[2] != STATUS_PENDING
        || authority.address().as_ref() != &state[80..112]
        || Clock::get()?.slot > u64::from_le_bytes(state[8..16].try_into().unwrap())
    {
        return Err(ProgramError::InvalidAccountData);
    }
    state[2] = if data[0] == 1 { STATUS_APPROVED } else { STATUS_REJECTED };
    Ok(())
}

/// Atomically consume a base-layer approval from the asset program.
///
/// The pool PDA must sign this CPI. Only the UTXOpia asset program can sign for
/// that PDA, so a user cannot consume an approval directly. The asset program
/// validates the actor and full instruction payload before invoking this
/// instruction with the resulting action and request hash.
#[inline(never)]
fn consume(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() != 2 || data.len() != 33 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let pool = &accounts[0];
    let approval = &accounts[1];
    if !pool.is_signer() || owner(approval) != program_id || !approval.is_writable() {
        return Err(ProgramError::InvalidAccountData);
    }
    let (_, auditor) = validate_pool(pool)?;

    let mut hash = [0; 32];
    let mut nonce = [0; 32];
    let mut refs = [&[][..]; 4];
    approval_seeds(
        approval,
        pool,
        &mut hash,
        &mut nonce,
        &mut refs,
        program_id,
    )?;

    let mut state = approval.try_borrow_mut()?;
    let expires_at = u64::from_le_bytes(state[8..16].try_into().unwrap());
    if !spend_is_allowed(state[2], Clock::get()?.slot, expires_at)
        || state[4] != data[0]
        || state[80..112] != auditor
        || state[112..144] != data[1..33]
    {
        return Err(ProgramError::InvalidAccountData);
    }
    state[2] = STATUS_CONSUMED;
    Ok(())
}

#[inline(never)]
fn commit(program_id: &Address, accounts: &[AccountView], data: &[u8]) -> ProgramResult {
    if accounts.len() != 4 || !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !accounts[0].is_signer()
        || accounts[1].address() != &MAGIC_CONTEXT_ID
        || accounts[2].address() != &MAGIC_PROGRAM_ID
        || owner(&accounts[3]) != program_id
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let state = accounts[3].try_borrow()?;
    if state.len() != POLICY_LEN || !matches!(state[2], STATUS_APPROVED | STATUS_REJECTED) {
        return Err(ProgramError::InvalidAccountData);
    }
    drop(state);
    let mut buffer = [0; INTENT_BUFFER_SIZE];
    MagicIntentBundleBuilder::new(accounts[0].clone(), accounts[1].clone(), accounts[2].clone())
        .commit_and_undelegate(core::slice::from_ref(&accounts[3]))
        .build_and_invoke(&mut buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXPIRES_AT: u64 = 10;

    /// This program owns the account, so it re-decides what the asset program
    /// already decided. Any drift between the two stalls an approved spend in
    /// the CPI.
    #[test]
    fn consume_matches_the_asset_program_rule() {
        assert!(spend_is_allowed(STATUS_APPROVED, EXPIRES_AT, EXPIRES_AT));
        assert!(!spend_is_allowed(STATUS_APPROVED, EXPIRES_AT + 1, EXPIRES_AT));

        // Nothing ripens by waiting. An unapproved exit never reaches this
        // program at all; it takes the asset program's ragequit path.
        for status in [STATUS_PENDING, STATUS_REJECTED, STATUS_CONSUMED] {
            assert!(!spend_is_allowed(status, EXPIRES_AT, EXPIRES_AT));
            assert!(!spend_is_allowed(status, u64::MAX, EXPIRES_AT));
        }
    }
}
