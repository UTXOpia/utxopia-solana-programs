//! Permissioned-pool PolicyApproval lifecycle and consumption.

use crate::error::UTXOpiaError;
use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError, Pubkey};
use crate::state::{
    PolicyApproval, PoolState, POLICY_STATUS_APPROVED, POLICY_STATUS_PENDING,
    POLICY_STATUS_REJECTED,
};
use crate::utils::{
    create_pda_account, validate_account_writable, validate_pool_state_pda,
    validate_program_owner, validate_system_program,
};
use pinocchio::{
    cpi::{invoke_signed, Seed, Signer},
    instruction::{InstructionAccount as AccountMeta, InstructionView as Instruction},
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    ProgramResult,
};

const INIT_DATA_LEN: usize = 1 + 8 + 32 + 32 + 32;
const DECISION_APPROVE: u8 = 1;
const DECISION_REJECT: u8 = 2;
const REQUEST_DOMAIN: &[u8] = b"UTXOPIA_POLICY_APPROVAL_V1";

/// Initialize a pending approval on Solana.
///
/// Data: action:u8 || expires_at_slot:u64 || actor:[32] ||
/// request_hash:[32] || nonce:[32]
///
/// Accounts: payer signer writable, pool_state, approval writable, system program.
pub fn process_initialize_policy_approval(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() != INIT_DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let payer = &accounts[0];
    let pool_info = &accounts[1];
    let approval_info = &accounts[2];
    let system_program = &accounts[3];
    if !payer.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_program_owner(pool_info, program_id)?;
    validate_pool_state_pda(pool_info, program_id)?;
    validate_account_writable(approval_info)?;
    validate_system_program(system_program)?;

    let action = data[0];
    if !is_permissioned_action(action) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let expires_at_slot = u64::from_le_bytes(data[1..9].try_into().unwrap());
    let actor: &[u8; 32] = data[9..41].try_into().unwrap();
    let request_hash: &[u8; 32] = data[41..73].try_into().unwrap();
    let nonce: &[u8; 32] = data[73..105].try_into().unwrap();
    let clock = Clock::get()?;
    if expires_at_slot <= clock.slot {
        return Err(UTXOpiaError::PolicyApprovalExpired.into());
    }

    let policy_authority = {
        let pool_data = pool_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if !pool.permissioned() || pool.auditor_is_frozen() {
            return Err(UTXOpiaError::Unauthorized.into());
        }
        *pool.auditor()
    };
    let (expected, bump) = find_program_address(
        &[
            PolicyApproval::SEED,
            pool_info.address().as_ref(),
            request_hash,
            nonce,
        ],
        program_id,
    );
    if approval_info.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    if approval_info.owned_by(program_id) && approval_info.data_len() > 0 {
        return Err(UTXOpiaError::PolicyApprovalAlreadyUsed.into());
    }
    let bump_bytes = [bump];
    let signer_seeds: &[&[u8]] = &[
        PolicyApproval::SEED,
        pool_info.address().as_ref(),
        request_hash,
        nonce,
        &bump_bytes,
    ];
    let approval_lamports = Rent::get()?
        .try_minimum_balance(PolicyApproval::LEN)?
        .checked_add(crate::constants::MAGICBLOCK_PER_PERMISSION_RENT)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    create_pda_account(
        payer,
        approval_info,
        program_id,
        approval_lamports,
        PolicyApproval::LEN as u64,
        signer_seeds,
    )?;
    let mut approval_data = approval_info.try_borrow_mut()?;
    PolicyApproval::init(
        &mut approval_data,
        bump,
        action,
        expires_at_slot,
        pool_info.address().as_ref().try_into().unwrap(),
        actor,
        &policy_authority,
        request_hash,
        nonce,
    )
}

/// Approve or reject a delegated approval inside PER.
///
/// Accounts: policy authority signer, approval writable.
pub fn process_policy_approval_decision(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() != 1 || (data[0] != DECISION_APPROVE && data[0] != DECISION_REJECT) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let authority = &accounts[0];
    let approval_info = &accounts[1];
    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_program_owner(approval_info, program_id)?;
    validate_account_writable(approval_info)?;
    let mut approval_data = approval_info.try_borrow_mut()?;
    PolicyApproval::validate(&approval_data)?;
    if PolicyApproval::status(&approval_data) != POLICY_STATUS_PENDING {
        return Err(UTXOpiaError::PolicyApprovalAlreadyUsed.into());
    }
    if authority.address().as_ref() != PolicyApproval::policy_authority(&approval_data) {
        return Err(UTXOpiaError::Unauthorized.into());
    }
    if Clock::get()?.slot > PolicyApproval::expires_at_slot(&approval_data) {
        return Err(UTXOpiaError::PolicyApprovalExpired.into());
    }
    PolicyApproval::set_status(
        &mut approval_data,
        if data[0] == DECISION_APPROVE {
            POLICY_STATUS_APPROVED
        } else {
            POLICY_STATUS_REJECTED
        },
    );
    Ok(())
}

pub fn compute_policy_request_hash(
    program_id: &Pubkey,
    pool: &Pubkey,
    actor: &Pubkey,
    action: u8,
    instruction_data: &[u8],
) -> [u8; 32] {
    crate::utils::bitcoin::sha256_parts([
        REQUEST_DOMAIN,
        program_id.as_ref(),
        pool.as_ref(),
        actor.as_ref(),
        &[action],
        instruction_data,
    ])
}

/// Validate and consume an approved account. Call this before any asset state
/// mutation; Solana transaction atomicity rolls the status back if later work fails.
pub fn consume_policy_approval(
    program_id: &Pubkey,
    approval_info: &AccountInfo,
    policy_program_info: &AccountInfo,
    pool_info: &AccountInfo,
    actor: &Pubkey,
    expected_policy_authority: &[u8; 32],
    action: u8,
    instruction_data: &[u8],
) -> ProgramResult {
    let policy_program_id = Pubkey::new_from_array(crate::constants::POLICY_PROGRAM_ID);
    if policy_program_info.address() != &policy_program_id || !policy_program_info.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    validate_program_owner(approval_info, &policy_program_id)?;
    validate_account_writable(approval_info)?;
    validate_program_owner(pool_info, program_id)?;
    validate_pool_state_pda(pool_info, program_id)?;
    let expected_hash =
        compute_policy_request_hash(program_id, pool_info.address(), actor, action, instruction_data);
    let approval_data = approval_info.try_borrow()?;
    PolicyApproval::validate(&approval_data)?;
    if PolicyApproval::status(&approval_data) != POLICY_STATUS_APPROVED {
        return Err(UTXOpiaError::PolicyApprovalRequired.into());
    }
    if PolicyApproval::action(&approval_data) != action
        || PolicyApproval::pool(&approval_data) != pool_info.address().as_ref()
        || PolicyApproval::actor(&approval_data) != actor.as_ref()
        || PolicyApproval::policy_authority(&approval_data) != expected_policy_authority
        || PolicyApproval::request_hash(&approval_data) != &expected_hash
    {
        return Err(UTXOpiaError::PolicyApprovalMismatch.into());
    }
    if Clock::get()?.slot > PolicyApproval::expires_at_slot(&approval_data) {
        return Err(UTXOpiaError::PolicyApprovalExpired.into());
    }
    let (expected, bump) = find_program_address(
        &[
            PolicyApproval::SEED,
            pool_info.address().as_ref(),
            PolicyApproval::request_hash(&approval_data),
            PolicyApproval::nonce(&approval_data),
        ],
        &policy_program_id,
    );
    if approval_info.address() != &expected || PolicyApproval::bump(&approval_data) != bump {
        return Err(ProgramError::InvalidSeeds);
    }
    drop(approval_data);

    let (zkbtc_mint, pool_bump) = {
        let pool_data = pool_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        (pool.zkbtc_mint, pool.bump)
    };
    let mut consume_data = [0u8; 34];
    consume_data[0] = 39;
    consume_data[1] = action;
    consume_data[2..34].copy_from_slice(&expected_hash);
    let accounts = [
        AccountMeta::readonly_signer(pool_info.address()),
        AccountMeta::writable(approval_info.address()),
    ];
    let instruction = Instruction {
        program_id: &policy_program_id,
        accounts: &accounts,
        data: &consume_data,
    };
    let bump_bytes = [pool_bump];
    let signer_seeds = [
        Seed::from(PoolState::SEED),
        Seed::from(&zkbtc_mint),
        Seed::from(&bump_bytes),
    ];
    let signers = [Signer::from(&signer_seeds)];
    invoke_signed(
        &instruction,
        &[pool_info, approval_info, policy_program_info],
        &signers,
    )
}

fn is_permissioned_action(action: u8) -> bool {
    matches!(
        action,
        crate::instruction::COMPLETE_DEPOSIT_PERMISSIONED
            | crate::instruction::SHIELD_PERMISSIONED
            | crate::instruction::TRANSACT
            | crate::instruction::UNSHIELD
            | crate::instruction::REDEEM
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_hash_binds_actor_action_and_payload() {
        let program = Pubkey::new_from_array([1; 32]);
        let pool = Pubkey::new_from_array([2; 32]);
        let actor = Pubkey::new_from_array([3; 32]);
        let a = compute_policy_request_hash(&program, &pool, &actor, 13, b"payload");
        let b = compute_policy_request_hash(&program, &pool, &actor, 14, b"payload");
        let c = compute_policy_request_hash(
            &program,
            &pool,
            &Pubkey::new_from_array([4; 32]),
            13,
            b"payload",
        );
        assert_ne!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn approval_pda_is_namespaced_by_pool() {
        let program = Pubkey::new_from_array([1; 32]);
        let request_hash = [7u8; 32];
        let nonce = [9u8; 32];
        let pool_a = Pubkey::new_from_array([2; 32]);
        let pool_b = Pubkey::new_from_array([3; 32]);
        let a = find_program_address(
            &[
                PolicyApproval::SEED,
                pool_a.as_ref(),
                &request_hash,
                &nonce,
            ],
            &program,
        )
        .0;
        let b = find_program_address(
            &[
                PolicyApproval::SEED,
                pool_b.as_ref(),
                &request_hash,
                &nonce,
            ],
            &program,
        )
        .0;
        assert_ne!(a, b);
    }
}
