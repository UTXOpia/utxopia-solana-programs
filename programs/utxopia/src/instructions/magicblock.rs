//! MagicBlock ER/PER account lifecycle helpers.

use crate::error::UTXOpiaError;
use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError, Pubkey};
use crate::state::{
    CommitmentTree, NullifierRecord, PolicyApproval, PoolState, NULLIFIER_RECORD_DISCRIMINATOR,
    POLICY_STATUS_APPROVED, POLICY_STATUS_REJECTED,
};
use crate::utils::{validate_account_writable, validate_program_owner, validate_system_program};
use ephemeral_rollups_pinocchio::{
    acl::{
        data_buffer_size, permission_pda_from_permissioned_account, CloseEphemeralPermission,
        CreateEphemeralPermission, EphemeralMembersArgs, Member, MemberFlags,
        UpdateEphemeralPermission, PERMISSION_PROGRAM_ID,
    },
    consts::{
        DELEGATION_PROGRAM_ID, EPHEMERAL_VAULT_ID, EXTERNAL_UNDELEGATE_DISCRIMINATOR,
        MAGIC_CONTEXT_ID, MAGIC_PROGRAM_ID,
    },
    instruction::{delegate_account, delegate_account_with_any_validator, undelegate},
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
    ProgramResult,
};

const TARGET_POOL_STATE: u8 = 0;
const TARGET_POLICY_APPROVAL: u8 = 2;
const NO_VALIDATOR_SENTINEL: [u8; 32] = [0; 32];

const COMMIT_ABI_VERSION: u8 = 1;
const COMMIT_FLAG_UNDELEGATE: u8 = 1 << 0;
const COMMIT_ALLOWED_FLAGS: u8 = COMMIT_FLAG_UNDELEGATE;
const INTENT_DATA_BUFFER_SIZE: usize = 1280;

const PER_OPERATION_CREATE: u8 = 0;
const PER_OPERATION_UPDATE: u8 = 1;
const PER_OPERATION_CLOSE: u8 = 2;
const PER_ALLOWED_MEMBER_FLAGS: u8 = MemberFlags::AUTHORITY
    | MemberFlags::TX_LOGS
    | MemberFlags::TX_BALANCES
    | MemberFlags::TX_MESSAGE
    | MemberFlags::ACCOUNT_SIGNATURES;
pub const MAX_PER_PERMISSION_MEMBERS: usize = crate::constants::MAGICBLOCK_MAX_PER_MEMBERS;
const PER_CPI_DATA_BUFFER_SIZE: usize = data_buffer_size(MAX_PER_PERMISSION_MEMBERS);

/// Delegate a one-time PolicyApproval PDA on the base layer.
///
/// Data after the UTXOpia discriminator:
/// - target: u8, must be 2 = PolicyApproval
/// - commit_frequency_ms: u32 LE
/// - validator: optional [u8; 32]; omitted or all-zero allows any validator
///
/// Accounts:
/// 0. payer signer writable
/// 1. pool authority signer
/// 2. pool state
/// 3. delegated UTXOpia PDA writable
/// 4. owner program account (this program, executable)
/// 5. MagicBlock buffer PDA writable
/// 6. MagicBlock delegation record PDA writable
/// 7. MagicBlock delegation metadata PDA writable
/// 8. system program
/// 9. MagicBlock delegation program (executable, required by the CPI runtime)
pub fn process_magicblock_delegate(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 10 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() != 5 && data.len() != 37 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let payer = &accounts[0];
    let authority = &accounts[1];
    let pool_state = &accounts[2];
    let delegated = &accounts[3];
    let owner_program = &accounts[4];
    let buffer = &accounts[5];
    let delegation_record = &accounts[6];
    let delegation_metadata = &accounts[7];
    let system_program = &accounts[8];
    let delegation_program = &accounts[9];

    if !payer.is_signer() || !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_pool_authority(pool_state, authority, program_id)?;
    if owner_program.address() != program_id || !owner_program.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    validate_program_owner(delegated, program_id)?;
    validate_account_writable(delegated)?;
    validate_account_writable(buffer)?;
    validate_account_writable(delegation_record)?;
    validate_account_writable(delegation_metadata)?;
    validate_system_program(system_program)?;
    if delegation_program.address() != &DELEGATION_PROGRAM_ID || !delegation_program.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }

    let target = data[0];
    if target != TARGET_POLICY_APPROVAL {
        return Err(ProgramError::InvalidInstructionData);
    }
    let commit_frequency_ms = u32::from_le_bytes(data[1..5].try_into().unwrap());
    let validator = if data.len() == 37 {
        let mut validator = [0u8; 32];
        validator.copy_from_slice(&data[5..37]);
        if validator == NO_VALIDATOR_SENTINEL {
            None
        } else {
            Some(Pubkey::new_from_array(validator))
        }
    } else {
        None
    };

    let mut tree_index_bytes = [0u8; 4];
    let mut approval_request_hash = [0u8; 32];
    let mut approval_nonce = [0u8; 32];
    let mut seed_refs: [&[u8]; 4] = [&[]; 4];
    let (seeds, bump) = delegated_seeds(
        target,
        delegated,
        pool_state,
        program_id,
        &mut tree_index_bytes,
        &mut approval_request_hash,
        &mut approval_nonce,
        &mut seed_refs,
    )?;

    validate_magicblock_delegate_accounts(
        delegated,
        owner_program,
        buffer,
        delegation_record,
        delegation_metadata,
    )?;

    let config = DelegateConfig {
        commit_frequency_ms,
        validator,
    };
    let cpi_accounts = [
        payer,
        delegated,
        owner_program,
        buffer,
        delegation_record,
        delegation_metadata,
        system_program,
    ];

    if config.validator.is_some() {
        delegate_account(&cpi_accounts, seeds, bump, config)
    } else {
        delegate_account_with_any_validator(&cpi_accounts, seeds, bump, config)
    }
}

/// Atomically commit the pool, active tree, and every nullifier created by a
/// private transfer. Undelegation uses the same complete account cluster.
///
/// Data after the UTXOpia discriminator:
/// - version: u8, currently 1
/// - flags: u8, bit 0 = commit and undelegate
/// - nullifier_count: u8
/// - nullifier_hashes: nullifier_count * [u8; 32]
///
/// Accounts:
/// 0. payer signer
/// 1. pool authority signer for undelegation; ignored for commit-only
/// 2. Magic context writable
/// 3. Magic program
/// 4. pool state writable
/// 5. active commitment tree writable
/// 6..N. nullifier record PDAs writable, in hash order
pub fn process_magicblock_commit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    let parsed = parse_commit_data(data)?;
    let expected_accounts = 6usize
        .checked_add(parsed.nullifier_count)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if accounts.len() != expected_accounts {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let payer = &accounts[0];
    let authority = &accounts[1];
    let magic_context = &accounts[2];
    let magic_program = &accounts[3];
    let pool_state = &accounts[4];
    let commitment_tree = &accounts[5];

    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_magic_accounts(magic_context, magic_program)?;
    validate_account_writable(magic_context)?;
    validate_program_owner(pool_state, program_id)?;
    crate::utils::validate_pool_state_pda(pool_state, program_id)?;
    if parsed.allow_undelegation {
        if !authority.is_signer() {
            return Err(ProgramError::MissingRequiredSignature);
        }
        validate_pool_authority(pool_state, authority, program_id)?;
    }
    validate_account_writable(pool_state)?;
    validate_active_tree(pool_state, commitment_tree, program_id)?;

    for (i, nullifier_hash) in parsed.nullifier_hashes.chunks_exact(32).enumerate() {
        let nullifier = &accounts[6 + i];
        validate_program_owner(nullifier, program_id)?;
        validate_account_writable(nullifier)?;
        let expected = find_program_address(&[NullifierRecord::SEED, nullifier_hash], program_id).0;
        if nullifier.address() != &expected {
            return Err(ProgramError::InvalidSeeds);
        }
        let nullifier_data = nullifier.try_borrow()?;
        if nullifier_data.first() != Some(&NULLIFIER_RECORD_DISCRIMINATOR) {
            return Err(ProgramError::InvalidAccountData);
        }
    }

    let committed_accounts = &accounts[4..];
    let mut intent_data = [0u8; INTENT_DATA_BUFFER_SIZE];
    let builder =
        MagicIntentBundleBuilder::new(payer.clone(), magic_context.clone(), magic_program.clone());

    if parsed.allow_undelegation {
        builder
            .commit_and_undelegate(committed_accounts)
            .build_and_invoke(&mut intent_data)
    } else {
        builder
            .commit(committed_accounts)
            .build_and_invoke(&mut intent_data)
    }
}

/// Create, update, or close an ER-local PER permission for a delegated
/// PolicyApproval.
///
/// Data after the UTXOpia discriminator:
/// - operation: u8, 0=create, 1=update, 2=close
/// - target: u8, must be 2=PolicyApproval
/// - member_count: u8
/// - members: member_count * (flags: u8 + pubkey: [u8; 32])
///
/// Accounts:
/// 0. pool authority signer
/// 1. pool state
/// 2. PolicyApproval PDA writable
/// 3. canonical ER-local permission PDA writable
/// 4. ephemeral vault writable
/// 5. Magic program
/// 6. permission program
pub fn process_magicblock_per_permission(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let authority = &accounts[0];
    let pool_state = &accounts[1];
    let permissioned_account = &accounts[2];
    let permission = &accounts[3];
    let ephemeral_vault = &accounts[4];
    let magic_program = &accounts[5];
    let permission_program = &accounts[6];

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_pool_authority(pool_state, authority, program_id)?;
    {
        let pool_data = pool_state.try_borrow()?;
        if !PoolState::from_bytes(&pool_data)?.permissioned() {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }
    validate_account_writable(permissioned_account)?;
    validate_account_writable(permission)?;
    validate_account_writable(ephemeral_vault)?;
    if ephemeral_vault.address() != &EPHEMERAL_VAULT_ID
        || magic_program.address() != &MAGIC_PROGRAM_ID
        || permission_program.address() != &PERMISSION_PROGRAM_ID
        || !magic_program.executable()
        || !permission_program.executable()
    {
        return Err(ProgramError::IncorrectProgramId);
    }
    if permission.address()
        != &permission_pda_from_permissioned_account(permissioned_account.address())
    {
        return Err(ProgramError::InvalidSeeds);
    }

    let parsed = parse_per_permission_data(data)?;
    let mut tree_index_bytes = [0u8; 4];
    let mut approval_request_hash = [0u8; 32];
    let mut approval_nonce = [0u8; 32];
    let mut seed_refs: [&[u8]; 4] = [&[]; 4];
    let (seeds, bump) = delegated_seeds(
        parsed.target,
        permissioned_account,
        pool_state,
        program_id,
        &mut tree_index_bytes,
        &mut approval_request_hash,
        &mut approval_nonce,
        &mut seed_refs,
    )?;
    let bump_bytes = [bump];
    let mut signer_seeds = [
        Seed::from(&[][..]),
        Seed::from(&[][..]),
        Seed::from(&[][..]),
        Seed::from(&[][..]),
        Seed::from(&[][..]),
    ];
    for (i, seed) in seeds.iter().enumerate() {
        signer_seeds[i] = Seed::from(*seed);
    }
    signer_seeds[seeds.len()] = Seed::from(&bump_bytes);
    let signer = Signer::from(&signer_seeds[..=seeds.len()]);
    let signers = [signer];

    let mut members = core::array::from_fn::<_, MAX_PER_PERMISSION_MEMBERS, _>(|_| Member {
        flags: MemberFlags::new(),
        pubkey: Pubkey::new_from_array([0; 32]),
    });
    for (i, raw) in parsed.members.chunks_exact(33).enumerate() {
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&raw[1..33]);
        members[i] = Member {
            flags: MemberFlags::from_acl_flag_byte(raw[0]),
            pubkey: Pubkey::new_from_array(pubkey),
        };
    }
    let args = EphemeralMembersArgs {
        is_private: true,
        members: &members[..parsed.member_count],
    };
    let permission_initialized =
        permission.owned_by(&PERMISSION_PROGRAM_ID) && permission.data_len() > 0;
    if permission.data_len() > 0 && !permission_initialized {
        return Err(ProgramError::IllegalOwner);
    }

    match parsed.operation {
        PER_OPERATION_CREATE if permission_initialized => UpdateEphemeralPermission {
            permissioned_account,
            permission,
            payer: permissioned_account,
            authority,
            vault: ephemeral_vault,
            magic_program,
            permission_program,
            authority_is_signer: true,
            args,
        }
        .invoke_signed::<PER_CPI_DATA_BUFFER_SIZE>(&signers),
        PER_OPERATION_CREATE => CreateEphemeralPermission {
            permissioned_account,
            permission,
            payer: permissioned_account,
            vault: ephemeral_vault,
            magic_program,
            permission_program,
            args,
        }
        .invoke_signed::<PER_CPI_DATA_BUFFER_SIZE>(&signers),
        PER_OPERATION_UPDATE => UpdateEphemeralPermission {
            permissioned_account,
            permission,
            payer: permissioned_account,
            authority,
            vault: ephemeral_vault,
            magic_program,
            permission_program,
            authority_is_signer: true,
            args,
        }
        .invoke_signed::<PER_CPI_DATA_BUFFER_SIZE>(&signers),
        PER_OPERATION_CLOSE => CloseEphemeralPermission {
            permissioned_account,
            permission,
            payer: permissioned_account,
            authority,
            vault: ephemeral_vault,
            magic_program,
            permission_program,
            authority_is_signer: true,
        }
        .invoke_signed(&signers),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// MagicBlock external undelegate callback. The SDK helper authenticates the
/// canonical undelegate-buffer signer before returning account ownership.
pub fn process_magicblock_undelegate_callback(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    if accounts.len() < 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if instruction_data.len() < EXTERNAL_UNDELEGATE_DISCRIMINATOR.len()
        || instruction_data[..8] != EXTERNAL_UNDELEGATE_DISCRIMINATOR
    {
        return Err(ProgramError::InvalidInstructionData);
    }

    undelegate(
        &accounts[0],
        program_id,
        &accounts[1],
        &accounts[2],
        &instruction_data[8..],
    )
}

struct ParsedCommitData<'a> {
    allow_undelegation: bool,
    nullifier_count: usize,
    nullifier_hashes: &'a [u8],
}

fn parse_commit_data(data: &[u8]) -> Result<ParsedCommitData<'_>, ProgramError> {
    if data.len() < 3 || data[0] != COMMIT_ABI_VERSION {
        return Err(ProgramError::InvalidInstructionData);
    }
    let flags = data[1];
    if flags & !COMMIT_ALLOWED_FLAGS != 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let nullifier_count = data[2] as usize;
    if nullifier_count == 0 || nullifier_count > crate::constants::MAX_SAFE_JOINSPLIT_SIZE {
        return Err(ProgramError::InvalidInstructionData);
    }
    let hashes_len = nullifier_count
        .checked_mul(32)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() != 3 + hashes_len {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(ParsedCommitData {
        allow_undelegation: flags & COMMIT_FLAG_UNDELEGATE != 0,
        nullifier_count,
        nullifier_hashes: &data[3..],
    })
}

struct ParsedPerPermissionData<'a> {
    operation: u8,
    target: u8,
    member_count: usize,
    members: &'a [u8],
}

fn parse_per_permission_data(data: &[u8]) -> Result<ParsedPerPermissionData<'_>, ProgramError> {
    if data.len() < 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let operation = data[0];
    let target = data[1];
    if target != TARGET_POLICY_APPROVAL {
        return Err(ProgramError::InvalidInstructionData);
    }

    let member_count = data[2] as usize;
    if operation == PER_OPERATION_CLOSE {
        if member_count != 0 || data.len() != 3 {
            return Err(ProgramError::InvalidInstructionData);
        }
        return Ok(ParsedPerPermissionData {
            operation,
            target,
            member_count,
            members: &[],
        });
    }
    if operation != PER_OPERATION_CREATE && operation != PER_OPERATION_UPDATE {
        return Err(ProgramError::InvalidInstructionData);
    }
    if member_count == 0 || member_count > MAX_PER_PERMISSION_MEMBERS {
        return Err(ProgramError::InvalidInstructionData);
    }
    let members_len = member_count
        .checked_mul(33)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if data.len() != 3 + members_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    let members = &data[3..];
    let mut authority_members = 0usize;
    for member in members.chunks_exact(33) {
        let flags = member[0];
        if flags & !PER_ALLOWED_MEMBER_FLAGS != 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
        if flags & MemberFlags::AUTHORITY != 0 {
            authority_members += 1;
        }
    }
    if authority_members == 0 {
        return Err(UTXOpiaError::Unauthorized.into());
    }

    Ok(ParsedPerPermissionData {
        operation,
        target,
        member_count,
        members,
    })
}

fn validate_pool_authority(
    pool_state: &AccountInfo,
    authority: &AccountInfo,
    program_id: &Pubkey,
) -> ProgramResult {
    validate_program_owner(pool_state, program_id)?;
    crate::utils::validate_pool_state_pda(pool_state, program_id)?;
    let pool_data = pool_state.try_borrow()?;
    let pool = PoolState::from_bytes(&pool_data)?;
    if authority.address().as_ref() != pool.authority {
        return Err(UTXOpiaError::Unauthorized.into());
    }
    Ok(())
}

fn validate_active_tree(
    pool_state: &AccountInfo,
    commitment_tree: &AccountInfo,
    program_id: &Pubkey,
) -> ProgramResult {
    validate_program_owner(commitment_tree, program_id)?;
    validate_account_writable(commitment_tree)?;
    let pool_data = pool_state.try_borrow()?;
    let pool = PoolState::from_bytes(&pool_data)?;
    crate::utils::validate_active_tree_pda(
        commitment_tree,
        pool_state,
        program_id,
        pool.active_tree_index(),
    )?;
    let tree_data = commitment_tree.try_borrow()?;
    let tree = CommitmentTree::from_bytes(&tree_data)?;
    if tree.tree_index() != pool.active_tree_index() {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

fn delegated_seeds<'a>(
    target: u8,
    delegated: &'a AccountInfo,
    pool_state: &'a AccountInfo,
    program_id: &Pubkey,
    _tree_index_bytes: &'a mut [u8; 4],
    approval_request_hash: &'a mut [u8; 32],
    approval_nonce: &'a mut [u8; 32],
    seed_refs: &'a mut [&'a [u8]; 4],
) -> Result<(&'a [&'a [u8]], u8), ProgramError> {
    match target {
        TARGET_POLICY_APPROVAL => {
            let pool_data = pool_state.try_borrow()?;
            let pool = PoolState::from_bytes(&pool_data)?;
            if !pool.permissioned() {
                return Err(UTXOpiaError::NotPermissioned.into());
            }
            let data = delegated.try_borrow()?;
            PolicyApproval::validate(&data)?;
            if PolicyApproval::pool(&data) != pool_state.address().as_ref() {
                return Err(ProgramError::InvalidSeeds);
            }
            approval_request_hash.copy_from_slice(PolicyApproval::request_hash(&data));
            approval_nonce.copy_from_slice(PolicyApproval::nonce(&data));
            let (expected, bump) = find_program_address(
                &[
                    PolicyApproval::SEED,
                    pool_state.address().as_ref(),
                    approval_request_hash,
                    approval_nonce,
                ],
                program_id,
            );
            if delegated.address() != &expected || PolicyApproval::bump(&data) != bump {
                return Err(ProgramError::InvalidSeeds);
            }
            seed_refs[0] = PolicyApproval::SEED;
            seed_refs[1] = pool_state.address().as_ref();
            seed_refs[2] = approval_request_hash;
            seed_refs[3] = approval_nonce;
            Ok((&seed_refs[..4], bump))
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Commit and undelegate one approved/rejected PolicyApproval back to Solana.
///
/// Accounts: payer signer, Magic context writable, Magic program, approval writable.
pub fn process_policy_approval_commit(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if !data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let payer = &accounts[0];
    let magic_context = &accounts[1];
    let magic_program = &accounts[2];
    let approval = &accounts[3];
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_magic_accounts(magic_context, magic_program)?;
    validate_account_writable(magic_context)?;
    validate_program_owner(approval, program_id)?;
    validate_account_writable(approval)?;
    {
        let approval_data = approval.try_borrow()?;
        PolicyApproval::validate(&approval_data)?;
        if !matches!(
            PolicyApproval::status(&approval_data),
            POLICY_STATUS_APPROVED | POLICY_STATUS_REJECTED
        ) {
            return Err(UTXOpiaError::PolicyApprovalRequired.into());
        }
    }
    let mut intent_data = [0u8; INTENT_DATA_BUFFER_SIZE];
    MagicIntentBundleBuilder::new(payer.clone(), magic_context.clone(), magic_program.clone())
        .commit_and_undelegate(core::slice::from_ref(approval))
        .build_and_invoke(&mut intent_data)
}

fn validate_magicblock_delegate_accounts(
    delegated: &AccountInfo,
    owner_program: &AccountInfo,
    buffer: &AccountInfo,
    delegation_record: &AccountInfo,
    delegation_metadata: &AccountInfo,
) -> ProgramResult {
    if buffer.address()
        != &delegate_buffer_pda_from_delegated_account_and_owner_program(
            delegated.address(),
            owner_program.address(),
        )
        || delegation_record.address()
            != &delegation_record_pda_from_delegated_account(delegated.address())
        || delegation_metadata.address()
            != &delegation_metadata_pda_from_delegated_account(delegated.address())
    {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

fn validate_magic_accounts(
    magic_context: &AccountInfo,
    magic_program: &AccountInfo,
) -> ProgramResult {
    if magic_context.address() != &MAGIC_CONTEXT_ID
        || magic_program.address() != &MAGIC_PROGRAM_ID
        || !magic_program.executable()
    {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commit_parser_requires_complete_versioned_nullifier_list() {
        let mut data = vec![COMMIT_ABI_VERSION, COMMIT_FLAG_UNDELEGATE, 2];
        data.extend_from_slice(&[1u8; 32]);
        data.extend_from_slice(&[2u8; 32]);
        let parsed = parse_commit_data(&data).unwrap();
        assert!(parsed.allow_undelegation);
        assert_eq!(parsed.nullifier_count, 2);
        assert_eq!(parsed.nullifier_hashes.len(), 64);
    }

    #[test]
    fn commit_parser_rejects_empty_or_truncated_clusters() {
        assert!(parse_commit_data(&[COMMIT_ABI_VERSION, 0, 0]).is_err());
        assert!(parse_commit_data(&[COMMIT_ABI_VERSION, 0, 1, 7]).is_err());
        assert!(parse_commit_data(&[0, 0, 1]).is_err());
        assert!(parse_commit_data(&[COMMIT_ABI_VERSION, 0x80, 1]).is_err());
    }

    #[test]
    fn per_parser_requires_a_retained_authority() {
        let mut valid = vec![
            PER_OPERATION_CREATE,
            TARGET_POLICY_APPROVAL,
            1,
            MemberFlags::AUTHORITY,
        ];
        valid.extend_from_slice(&[9u8; 32]);
        assert!(parse_per_permission_data(&valid).is_ok());

        let mut no_authority = vec![
            PER_OPERATION_UPDATE,
            TARGET_POLICY_APPROVAL,
            1,
            MemberFlags::TX_LOGS,
        ];
        no_authority.extend_from_slice(&[9u8; 32]);
        assert!(parse_per_permission_data(&no_authority).is_err());
    }

    #[test]
    fn per_parser_rejects_public_or_oversized_permissions() {
        assert!(
            parse_per_permission_data(&[PER_OPERATION_CREATE, TARGET_POLICY_APPROVAL, 0]).is_err()
        );
        assert!(parse_per_permission_data(&[
            PER_OPERATION_CREATE,
            TARGET_POLICY_APPROVAL,
            (MAX_PER_PERMISSION_MEMBERS + 1) as u8,
        ])
        .is_err());
        assert!(
            parse_per_permission_data(&[
                PER_OPERATION_CREATE,
                TARGET_POLICY_APPROVAL,
                1,
                0x80,
            ])
                .is_err()
        );
        assert!(parse_per_permission_data(&[PER_OPERATION_CLOSE, TARGET_POOL_STATE, 0]).is_err());
    }

    #[test]
    fn per_close_has_no_member_payload() {
        let close = parse_per_permission_data(&[
            PER_OPERATION_CLOSE,
            TARGET_POLICY_APPROVAL,
            0,
        ])
        .unwrap();
        assert_eq!(close.operation, PER_OPERATION_CLOSE);
        assert_eq!(close.member_count, 0);
        assert!(close.members.is_empty());
    }
}
