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

/// Upper bound on intent parts; the widest caller supplies three.
pub const MAX_INTENT_PARTS: usize = 3;

/// Hash of what the authority actually decides, not of the bytes that carry it.
///
/// A spend's instruction data contains both intent and proof machinery. The
/// machinery moves every time the proof is regenerated — the merkle root follows
/// other people's deposits, output commitments take fresh blinding, stealth data
/// is re-randomized — so hashing the whole payload made an approval valid only
/// for one exact proof. Any delay on the authority's side aged the root out, the
/// spender had to re-prove, and the approval they had just been granted no longer
/// matched. That is why callers now pass only the fields a decision turns on:
///
/// - which notes are being spent (`nullifiers`)
/// - how much leaves (`amounts`)
/// - where it goes (recipient owners for unshield, BTC scripts for redeem)
///
/// Excluded on purpose: merkle root, proof, output commitments, stealth data and
/// the bound-params hash. The program verifies every one of them independently,
/// and re-proving cannot change the decision they belong to — the output total is
/// pinned by the circuit's balance constraint and the payout is pinned by the
/// amounts and destinations above, so all a fresh proof can move is the change
/// note's blinding, which the authority neither sees nor cares about.
///
/// Value entry (`shield`/`complete_deposit`) passes its whole instruction data:
/// nothing there ages, so the spender can hold the exact bytes and submit them
/// whenever the answer arrives.
///
/// Each part is folded to a fixed 32 bytes before the parts are joined, so two
/// different partitions of the same concatenated bytes cannot collide (same
/// reasoning as `length_prefixed_hash` in the redeem path).
pub fn compute_policy_request_hash(
    program_id: &Pubkey,
    pool: &Pubkey,
    actor: &Pubkey,
    action: u8,
    intent_parts: &[&[u8]],
) -> Result<[u8; 32], ProgramError> {
    if intent_parts.len() > MAX_INTENT_PARTS {
        return Err(ProgramError::InvalidArgument);
    }
    let mut digests = [0u8; MAX_INTENT_PARTS * 32];
    for (i, part) in intent_parts.iter().enumerate() {
        digests[i * 32..(i + 1) * 32].copy_from_slice(&crate::utils::sha256(part));
    }
    Ok(crate::utils::bitcoin::sha256_parts([
        REQUEST_DOMAIN,
        program_id.as_ref(),
        pool.as_ref(),
        actor.as_ref(),
        &[action],
        &[intent_parts.len() as u8],
        &digests[..intent_parts.len() * 32],
    ]))
}

/// How a permissioned pool's spend is authorized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpendPath {
    /// Open pool: nothing decides anything.
    Open,
    /// An approval was supplied; the auditor decided this exact spend, so the
    /// destination is unrestricted.
    Verified,
    /// No approval, no waiting — but the destination must already be in the
    /// pool's exit registry.
    Ragequit,
}

/// Only spends that leave the pool have a ragequit. `transact` moves value
/// inside it, where there is no external destination a registry could bound, so
/// an unapproved internal transfer is simply refused. That asymmetry is the
/// point: an auditor can halt an identified participant's circulation, and can
/// still never stop them withdrawing.
fn allows_ragequit(action: u8) -> bool {
    matches!(action, crate::instruction::UNSHIELD | crate::instruction::REDEEM)
}

/// Resolve which path a spend is taking from the accounts it supplied.
pub fn resolve_spend_path(
    permissioned: bool,
    approval: bool,
    policy_program: bool,
    action: u8,
) -> Result<SpendPath, ProgramError> {
    if !permissioned {
        return Ok(SpendPath::Open);
    }
    match (approval, policy_program) {
        (true, true) => Ok(SpendPath::Verified),
        // Half the pair is no pair: neither account alone reaches the consume CPI.
        (true, false) | (false, true) => Err(UTXOpiaError::PolicyApprovalRequired.into()),
        (false, false) if allows_ragequit(action) => Ok(SpendPath::Ragequit),
        (false, false) => Err(UTXOpiaError::RagequitNotAvailable.into()),
    }
}

/// The verified path's spend rule, free of account plumbing so a test exercises
/// what the instruction runs. Mirrored by `spend_is_allowed` in the policy
/// program's `consume`; the two must stay in lockstep.
///
/// Silence and "no" weigh the same, and neither traps anything: an unanswered or
/// refused exit takes the ragequit path instead, which needs no approval and no
/// waiting.
pub fn spend_is_allowed(status: u8, slot: u64, expires_at: u64) -> ProgramResult {
    if status != POLICY_STATUS_APPROVED {
        return Err(UTXOpiaError::PolicyApprovalRequired.into());
    }
    if slot > expires_at {
        return Err(UTXOpiaError::PolicyApprovalExpired.into());
    }
    Ok(())
}

/// Validate and consume an approval account. Call this before any asset state
/// mutation; Solana transaction atomicity rolls the status back if later work fails.

pub fn consume_policy_approval(
    program_id: &Pubkey,
    approval_info: &AccountInfo,
    policy_program_info: &AccountInfo,
    pool_info: &AccountInfo,
    actor: &Pubkey,
    expected_policy_authority: &[u8; 32],
    action: u8,
    intent_parts: &[&[u8]],
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
        compute_policy_request_hash(program_id, pool_info.address(), actor, action, intent_parts)?;
    let approval_data = approval_info.try_borrow()?;
    PolicyApproval::validate(&approval_data)?;
    if PolicyApproval::action(&approval_data) != action
        || PolicyApproval::pool(&approval_data) != pool_info.address().as_ref()
        || PolicyApproval::actor(&approval_data) != actor.as_ref()
        || PolicyApproval::policy_authority(&approval_data) != expected_policy_authority
        || PolicyApproval::request_hash(&approval_data) != &expected_hash
    {
        return Err(UTXOpiaError::PolicyApprovalMismatch.into());
    }
    spend_is_allowed(
        PolicyApproval::status(&approval_data),
        Clock::get()?.slot,
        PolicyApproval::expires_at_slot(&approval_data),
    )?;
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

/// Mirror of the allowlist in `utxopia-policy`'s `lib.rs`. Both must accept the same set:
/// an action missing from either one can never obtain an approval, so the instruction is
/// dead on arrival (fail-closed, but silently). `policy-allowlist-parity.test.ts` pins them
/// together — the discriminator-parity test pins the numbers, not the membership.
fn is_permissioned_action(action: u8) -> bool {
    matches!(
        action,
        crate::instruction::COMPLETE_DEPOSIT_PERMISSIONED
            | crate::instruction::SHIELD_PERMISSIONED
            | crate::instruction::VERIFY_DEPOSIT_PERMISSIONED
            | crate::instruction::TRANSACT
            | crate::instruction::UNSHIELD
            | crate::instruction::REDEEM
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::POLICY_STATUS_CONSUMED;

    const PROGRAM: Pubkey = Pubkey::new_from_array([1; 32]);
    const POOL: Pubkey = Pubkey::new_from_array([2; 32]);
    const ACTOR: Pubkey = Pubkey::new_from_array([3; 32]);

    /// An unshield-shaped intent: nullifiers, amounts, destinations.
    fn unshield_hash(nullifiers: &[u8], amounts: &[u8], destinations: &[u8]) -> [u8; 32] {
        compute_policy_request_hash(
            &PROGRAM,
            &POOL,
            &ACTOR,
            crate::instruction::UNSHIELD,
            &[nullifiers, amounts, destinations],
        )
        .unwrap()
    }

    const NULLIFIERS: &[u8] = &[9u8; 64];
    const AMOUNTS: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 1];
    const DESTINATIONS: &[u8] = &[7u8; 32];

    fn baseline() -> [u8; 32] {
        unshield_hash(NULLIFIERS, AMOUNTS, DESTINATIONS)
    }

    #[test]
    fn request_hash_binds_actor_action_and_pool() {
        let a = compute_policy_request_hash(&PROGRAM, &POOL, &ACTOR, 13, &[b"x"]).unwrap();
        let different_action =
            compute_policy_request_hash(&PROGRAM, &POOL, &ACTOR, 14, &[b"x"]).unwrap();
        let different_actor = compute_policy_request_hash(
            &PROGRAM,
            &POOL,
            &Pubkey::new_from_array([4; 32]),
            13,
            &[b"x"],
        )
        .unwrap();
        let different_pool = compute_policy_request_hash(
            &PROGRAM,
            &Pubkey::new_from_array([5; 32]),
            &ACTOR,
            13,
            &[b"x"],
        )
        .unwrap();
        assert_ne!(a, different_action);
        assert_ne!(a, different_actor);
        assert_ne!(a, different_pool);
    }

    /// The whole point: regenerating the proof moves the merkle root, the output
    /// commitments and the stealth data, and none of them reach this hash — so an
    /// approval survives a re-proof instead of being invalidated by it.
    #[test]
    fn the_hash_is_immune_to_everything_a_re_proof_changes() {
        assert_eq!(baseline(), unshield_hash(NULLIFIERS, AMOUNTS, DESTINATIONS));
    }

    #[test]
    fn swapping_the_spent_notes_changes_the_hash() {
        let mut other = [9u8; 64];
        other[0] = 8;
        assert_ne!(baseline(), unshield_hash(&other, AMOUNTS, DESTINATIONS));
    }

    #[test]
    fn changing_the_amount_changes_the_hash() {
        let other: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 2];
        assert_ne!(baseline(), unshield_hash(NULLIFIERS, other, DESTINATIONS));
    }

    #[test]
    fn changing_the_destination_changes_the_hash() {
        assert_ne!(baseline(), unshield_hash(NULLIFIERS, AMOUNTS, &[6u8; 32]));
    }

    /// Folding each part to a fixed digest before joining means the boundaries
    /// between nullifiers, amounts and destinations cannot be slid: two different
    /// partitions of the same concatenated bytes must not collide.
    #[test]
    fn part_boundaries_cannot_be_shifted() {
        let split_one =
            compute_policy_request_hash(&PROGRAM, &POOL, &ACTOR, 14, &[b"ab", b"c"]).unwrap();
        let split_two =
            compute_policy_request_hash(&PROGRAM, &POOL, &ACTOR, 14, &[b"a", b"bc"]).unwrap();
        assert_ne!(split_one, split_two);
    }

    /// Dropping a part must not silently produce the same commitment either.
    #[test]
    fn a_missing_part_is_a_different_request() {
        let three = compute_policy_request_hash(&PROGRAM, &POOL, &ACTOR, 14, &[b"a", b"b", b"c"]);
        let two = compute_policy_request_hash(&PROGRAM, &POOL, &ACTOR, 14, &[b"a", b"b"]);
        assert_ne!(three.unwrap(), two.unwrap());
    }

    /// Cross-implementation golden vector. The SDK (`buildPolicyRequestHash`)
    /// and the backend coordinator (`policy_request_hash`) assert this same
    /// value; if any one of the three drifts, every Verified spend starts
    /// failing with PolicyApprovalMismatch and only this test says why.
    #[test]
    fn golden_vector_pins_the_preimage_across_implementations() {
        let hash = baseline();
        let mut hex = [0u8; 64];
        for (i, byte) in hash.iter().enumerate() {
            const DIGITS: &[u8; 16] = b"0123456789abcdef";
            hex[i * 2] = DIGITS[(byte >> 4) as usize];
            hex[i * 2 + 1] = DIGITS[(byte & 0x0f) as usize];
        }
        assert_eq!(
            core::str::from_utf8(&hex).unwrap(),
            "2107b88df0674b34fca97dbcd5504cdac884a7ecc28d77ae48be3440c07ce14b"
        );
    }

    #[test]
    fn more_parts_than_the_buffer_holds_is_rejected_not_truncated() {
        let too_many: &[&[u8]] = &[b"a", b"b", b"c", b"d"];
        assert!(
            compute_policy_request_hash(&PROGRAM, &POOL, &ACTOR, 14, too_many).is_err(),
            "silently hashing a prefix would let a caller drop the destination"
        );
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

    use crate::instruction::{REDEEM, TRANSACT, UNSHIELD};

    fn path(permissioned: bool, approval: bool, policy_program: bool, action: u8) -> Option<SpendPath> {
        resolve_spend_path(permissioned, approval, policy_program, action).ok()
    }

    /// An open pool spends without ever touching the policy program.
    #[test]
    fn an_open_pool_decides_nothing() {
        assert_eq!(path(false, false, false, TRANSACT), Some(SpendPath::Open));
        assert_eq!(path(false, true, true, UNSHIELD), Some(SpendPath::Open));
    }

    #[test]
    fn supplying_both_policy_accounts_is_the_verified_path() {
        for action in [TRANSACT, UNSHIELD, REDEEM] {
            assert_eq!(path(true, true, true, action), Some(SpendPath::Verified));
        }
    }

    /// Half the pair is no pair: neither account alone reaches the consume CPI,
    /// and it must not silently fall through to an unrestricted ragequit.
    #[test]
    fn a_half_supplied_approval_is_refused_not_downgraded() {
        for action in [TRANSACT, UNSHIELD, REDEEM] {
            assert_eq!(path(true, true, false, action), None);
            assert_eq!(path(true, false, true, action), None);
        }
    }

    /// The guarantee the whole design rests on: an auditor who never answers, or
    /// answers "no", cannot stop a spender from leaving.
    #[test]
    fn exits_always_have_a_ragequit() {
        assert_eq!(path(true, false, false, UNSHIELD), Some(SpendPath::Ragequit));
        assert_eq!(path(true, false, false, REDEEM), Some(SpendPath::Ragequit));
    }

    /// ...and the matching limit: value may always leave, but it may not move
    /// inside the pool without the auditor.
    #[test]
    fn transact_has_no_ragequit() {
        assert_eq!(path(true, false, false, TRANSACT), None);
        assert_eq!(
            resolve_spend_path(true, false, false, TRANSACT).unwrap_err(),
            UTXOpiaError::RagequitNotAvailable.into()
        );
    }

    const EXPIRES_AT: u64 = 10;

    fn allowed(status: u8, slot: u64) -> bool {
        spend_is_allowed(status, slot, EXPIRES_AT).is_ok()
    }

    #[test]
    fn an_approval_spends_until_it_expires() {
        assert!(allowed(POLICY_STATUS_APPROVED, EXPIRES_AT));
        assert!(!allowed(POLICY_STATUS_APPROVED, EXPIRES_AT + 1));
        // A consumed approval is spent, whatever the clock says.
        assert!(!allowed(POLICY_STATUS_CONSUMED, EXPIRES_AT));
    }

    /// An undecided or refused approval never becomes spendable by waiting. The
    /// escape hatch is the ragequit path, not a timer on this one.
    #[test]
    fn waiting_never_ripens_a_pending_or_rejected_approval() {
        for status in [POLICY_STATUS_PENDING, POLICY_STATUS_REJECTED] {
            assert!(!allowed(status, EXPIRES_AT));
            assert!(!allowed(status, EXPIRES_AT + 1));
            assert!(!allowed(status, u64::MAX));
        }
    }

    /// Value entering the pool is the auditor's to gate outright — a deposit has
    /// nothing to escape from, so it gets no unapproved path either.
    #[test]
    fn entry_actions_have_no_ragequit() {
        use crate::instruction::{COMPLETE_DEPOSIT_PERMISSIONED, SHIELD_PERMISSIONED};

        for action in [SHIELD_PERMISSIONED, COMPLETE_DEPOSIT_PERMISSIONED] {
            assert_eq!(path(true, false, false, action), None);
        }
    }
}
