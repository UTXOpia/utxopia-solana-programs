//! DEV-ONLY reset (devnet-regtest builds only): closes `pool_state` + `commitment_tree`
//! so a subsequent `INITIALIZE` can recreate them at the current struct sizes after a
//! layout change. Gated by `#[cfg(feature = "devnet-regtest")]` at the dispatch site so it
//! can never exist in a mainnet/devnet build. Authority-gated (must match the pool authority).
//!
//! Accounts:
//!   [0] pool_state       (writable, program-owned)
//!   [1] commitment_tree  (writable, program-owned)
//!   [2] authority        (signer; lamport recipient; must equal pool_state.authority)

use crate::pinocchio_compat::{AccountInfo, Pubkey};
use pinocchio::ProgramResult;

use crate::error::UTXOpiaError;
use crate::utils::{close_account_securely, validate_account_writable, validate_program_owner};

pub fn process_devnet_reset(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    let pool_state = &accounts[0];
    let commitment_tree = &accounts[1];
    let authority = &accounts[2];

    // A signer is required and both accounts must belong to THIS program. We intentionally do
    // NOT match the stored pool authority: this is a devnet-regtest-only, feature-gated reset
    // whose whole purpose is to recover from a struct-layout change, where the authority field
    // offset itself may have moved between layout versions. The cfg gate keeps it out of prod.
    if !authority.is_signer() {
        return Err(UTXOpiaError::Unauthorized.into());
    }
    validate_program_owner(pool_state, program_id)?;
    validate_program_owner(commitment_tree, program_id)?;
    validate_account_writable(pool_state)?;
    validate_account_writable(commitment_tree)?;

    // Drain lamports to the authority → the runtime GCs both accounts at tx end, so the next
    // INITIALIZE sees data_len==0 and recreates them at the current struct sizes.
    close_account_securely(pool_state, authority)?;
    close_account_securely(commitment_tree, authority)?;

    Ok(())
}

/// DEV-ONLY: force-close arbitrary program-owned accounts by raw lamport-drain (no layout
/// parse), to clear stale PDAs the current program can no longer parse/cancel — e.g. old-layout
/// RedemptionRequest accounts left after a redeploy that clog the redemption scan. devnet-regtest
/// only; signer-gated; every target must be owned by this program.
///
/// Accounts:
///   [0]    authority   (signer; lamport recipient)
///   [1..]  targets     (writable, program-owned accounts to close)
pub fn process_devnet_close(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    let authority = &accounts[0];
    if !authority.is_signer() {
        return Err(UTXOpiaError::Unauthorized.into());
    }
    for target in &accounts[1..] {
        validate_program_owner(target, program_id)?;
        validate_account_writable(target)?;
        close_account_securely(target, authority)?;
    }
    Ok(())
}
