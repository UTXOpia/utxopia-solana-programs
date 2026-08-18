//! DEV-ONLY force-close (devnet-regtest builds only): drains lamports from arbitrary
//! program-owned accounts without parsing their layout, so a redeploy can clear state the
//! current program can no longer parse — `pool_state` + `commitment_tree` after a struct-layout
//! change (the next `INITIALIZE` then recreates them at the current sizes), stale `TokenConfig`s,
//! or old-layout `RedemptionRequest` PDAs that clog the redemption scan.
//!
//! Gated twice: `#[cfg(feature = "devnet-regtest")]` at the dispatch site keeps it out of any
//! mainnet build, and the handler requires the program's upgrade authority. `is_signer()` alone
//! was not a gate — the feature IS enabled in the deployed devnet-regtest binary, so any signer
//! could close any program-owned account in it.
//!
//! Accounts:
//!   [0]    authority     (signer; lamport recipient; must be the program upgrade authority)
//!   [1]    program_data  (this program's ProgramData account)
//!   [2..]  targets       (writable, program-owned accounts to close)

use crate::pinocchio_compat::{AccountInfo, ProgramError, Pubkey};
use pinocchio::ProgramResult;

use crate::utils::{
    close_account_securely, validate_account_writable, validate_program_owner,
    validate_upgrade_authority,
};

pub fn process_devnet_close(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    _data: &[u8],
) -> ProgramResult {
    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let authority = &accounts[0];
    validate_upgrade_authority(program_id, &accounts[1], authority)?;
    for target in &accounts[2..] {
        validate_program_owner(target, program_id)?;
        validate_account_writable(target)?;
        close_account_securely(target, authority)?;
    }
    Ok(())
}
