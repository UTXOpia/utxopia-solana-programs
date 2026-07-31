//! Exit-destination registry: the ragequit half of a permissioned pool's exits.
//!
//! A permissioned pool has two ways out:
//!
//!   Verified — an auditor approval is consumed; the destination is unrestricted.
//!   Ragequit — no approval at all; the destination must be registered here.
//!
//! The auditor therefore controls *where* an unapproved exit can land, never
//! *whether* it can happen. Refusing to answer, or refusing outright, cannot
//! strand a spender: they still reach a registered address. That is what keeps
//! the pool out of custodial territory — the operator has no ability to prevent
//! withdrawal, only to constrain it to vetted, attributable endpoints.
//!
//! `register_exit_destination` (disc 39)
//!   Data:     kind:u8 || key:[u8; 32]
//!   Accounts: 0. auditor (signer, payer)
//!             1. pool_state (read)
//!             2. exit_destination PDA (writable, uninitialized)
//!             3. system_program (read)
//!
//! There is deliberately no counterpart that closes an entry. See
//! `state::exit_destination` for why removal must stay impossible.
//!
//! `shield_permissioned` enforces the matching invariant on the way in: an SPL
//! depositor must already have their own entry here, so no value enters without
//! a way back out. The check keys on the depositor's signer, which is exactly
//! the owner an SPL ragequit pays.
//!
//! `complete_deposit_permissioned` (BTC) deliberately has no equivalent check,
//! and should not grow one. At that moment nobody — not this program, not the
//! coordinator — knows the beneficial owner: the recipient is a stealth note
//! public key and the signer is the auditor acting on someone's behalf. That is
//! inherent to stealth addressing, not missing plumbing. Making it an on-chain
//! check would mean the depositor committing an exit script inside the Bitcoin
//! transaction itself, alongside the note key — a change to an already-deployed
//! deposit format, bought for a guarantee that is already covered twice over:
//! the auditor co-signs every such deposit and can simply decline until the
//! participant is registered, and the resulting notes are zkBTC, an SPL token
//! in this pool, so their holder can ragequit out through `unshield` to their
//! registered wallet regardless. For BTC entry the invariant is an onboarding
//! discipline; for SPL entry it is enforced above.

use crate::error::UTXOpiaError;
use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError, Pubkey};
use crate::state::{is_valid_exit_kind, ExitDestination, PoolState};
use crate::utils::{
    create_pda_account, validate_account_writable, validate_pool_state_pda,
    validate_program_owner, validate_system_program,
};
use pinocchio::{
    sysvars::{rent::Rent, Sysvar},
    ProgramResult,
};

const REGISTER_DATA_LEN: usize = 1 + 32;

pub fn process_register_exit_destination(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    if accounts.len() != 4 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    if data.len() != REGISTER_DATA_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let auditor = &accounts[0];
    let pool_info = &accounts[1];
    let destination_info = &accounts[2];
    let system_program = &accounts[3];

    if !auditor.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    validate_program_owner(pool_info, program_id)?;
    validate_pool_state_pda(pool_info, program_id)?;
    validate_account_writable(destination_info)?;
    validate_system_program(system_program)?;

    let kind = data[0];
    if !is_valid_exit_kind(kind) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let key: &[u8; 32] = data[1..33].try_into().unwrap();

    {
        let pool_data = pool_info.try_borrow()?;
        let pool = PoolState::from_bytes(&pool_data)?;
        if !pool.permissioned() {
            return Err(UTXOpiaError::NotPermissioned.into());
        }
        // A frozen auditor may still widen the escape hatch. Freezing is meant to
        // stop value entering, and must never reach the one path that guarantees
        // funds can leave.
        if auditor.address().as_ref() != pool.auditor() {
            return Err(UTXOpiaError::Unauthorized.into());
        }
    }

    let (expected, bump) = exit_destination_pda(program_id, pool_info.address(), kind, key);
    if destination_info.address() != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    // Re-registering an existing destination is a no-op rather than an error, so
    // a retried or duplicated ops call cannot wedge the auditor's setup flow.
    if destination_info.owned_by(program_id) && destination_info.data_len() > 0 {
        let existing = destination_info.try_borrow()?;
        return ExitDestination::validate(&existing);
    }

    let kind_bytes = [kind];
    let bump_bytes = [bump];
    let signer_seeds: &[&[u8]] = &[
        ExitDestination::SEED,
        pool_info.address().as_ref(),
        &kind_bytes,
        key,
        &bump_bytes,
    ];
    create_pda_account(
        auditor,
        destination_info,
        program_id,
        Rent::get()?.try_minimum_balance(ExitDestination::LEN)?,
        ExitDestination::LEN as u64,
        signer_seeds,
    )?;
    let mut destination_data = destination_info.try_borrow_mut()?;
    ExitDestination::init(&mut destination_data, bump, kind, key)
}

pub fn exit_destination_pda(
    program_id: &Pubkey,
    pool: &Pubkey,
    kind: u8,
    key: &[u8; 32],
) -> (Pubkey, u8) {
    find_program_address(
        &[ExitDestination::SEED, pool.as_ref(), &[kind], key],
        program_id,
    )
}

/// Assert the supplied account is the registry entry for `(kind, key)` in this
/// pool. Deriving the address from the destination the caller is actually paying
/// means a spender cannot substitute some other registered entry for their own.
pub fn assert_exit_destination_registered(
    program_id: &Pubkey,
    pool: &Pubkey,
    destination_info: &AccountInfo,
    kind: u8,
    key: &[u8; 32],
) -> ProgramResult {
    let (expected, _) = exit_destination_pda(program_id, pool, kind, key);
    // A never-registered destination resolves to an uninitialized address, so the
    // "wrong account" and "not registered yet" cases report the same thing rather
    // than a bare owner mismatch.
    if destination_info.address() != &expected
        || !destination_info.owned_by(program_id)
        || destination_info.data_len() == 0
    {
        return Err(UTXOpiaError::ExitDestinationNotRegistered.into());
    }
    let data = destination_info.try_borrow()?;
    ExitDestination::validate(&data)?;
    if ExitDestination::kind(&data) != kind || ExitDestination::key(&data) != key {
        return Err(UTXOpiaError::ExitDestinationNotRegistered.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{EXIT_KIND_BTC_SCRIPT, EXIT_KIND_SOLANA_OWNER};

    const PROGRAM: Pubkey = Pubkey::new_from_array([1; 32]);
    const POOL_A: Pubkey = Pubkey::new_from_array([2; 32]);
    const POOL_B: Pubkey = Pubkey::new_from_array([3; 32]);

    #[test]
    fn a_destination_is_scoped_to_one_pool() {
        let key = [9u8; 32];
        let a = exit_destination_pda(&PROGRAM, &POOL_A, EXIT_KIND_SOLANA_OWNER, &key).0;
        let b = exit_destination_pda(&PROGRAM, &POOL_B, EXIT_KIND_SOLANA_OWNER, &key).0;
        assert_ne!(a, b, "one pool's registry must not authorize another's exit");
    }

    /// A 32-byte Solana owner and a 32-byte BTC script hash live in the same key
    /// space; only the kind seed keeps registering one from authorizing the other.
    #[test]
    fn kind_separates_solana_owners_from_btc_scripts() {
        let key = [9u8; 32];
        let sol = exit_destination_pda(&PROGRAM, &POOL_A, EXIT_KIND_SOLANA_OWNER, &key).0;
        let btc = exit_destination_pda(&PROGRAM, &POOL_A, EXIT_KIND_BTC_SCRIPT, &key).0;
        assert_ne!(sol, btc);
    }

    #[test]
    fn each_key_gets_its_own_entry() {
        let a = exit_destination_pda(&PROGRAM, &POOL_A, EXIT_KIND_SOLANA_OWNER, &[1u8; 32]).0;
        let b = exit_destination_pda(&PROGRAM, &POOL_A, EXIT_KIND_SOLANA_OWNER, &[2u8; 32]).0;
        assert_ne!(a, b);
    }

    /// Cross-implementation vector. `ops/scripts/auditor/register-exit-destination.ts`
    /// derives this same address with web3.js, and `shield_permissioned` refuses
    /// a depositor whose entry is not at exactly this address — so a seed that
    /// drifts on either side locks every new participant out of the pool with a
    /// bare ExitDestinationNotRegistered and nothing pointing at why.
    ///
    /// Reproduce:
    ///   bun run scripts/auditor/register-exit-destination.ts --dry-run \
    ///     --program CktRuQ2mttgRGkXJtyksdKHjUdc2C4TgDzyB98oEzy8 \
    ///     --pool    8qbHbw2BbbTHBW1sbeqakYXVKRQM8Ne7pLK7m6CVfeR \
    ///     --owner   4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi
    #[test]
    fn the_pda_matches_what_the_ops_script_derives() {
        let program = Pubkey::new_from_array([3; 32]);
        let pool = Pubkey::new_from_array([2; 32]);
        let (address, _) =
            exit_destination_pda(&program, &pool, EXIT_KIND_SOLANA_OWNER, &[1u8; 32]);
        assert_eq!(
            address.as_ref(),
            &[
                143, 133, 159, 175, 42, 205, 224, 30, 222, 199, 64, 110, 29, 17, 181, 43, 20, 188,
                41, 26, 246, 158, 251, 2, 147, 158, 135, 195, 24, 149, 226, 167
            ]
        );
    }

    #[test]
    fn register_data_must_be_exactly_kind_plus_key() {
        assert_eq!(REGISTER_DATA_LEN, 33);
        for len in [0usize, 1, 32, 34] {
            assert_ne!(len, REGISTER_DATA_LEN);
        }
    }
}
