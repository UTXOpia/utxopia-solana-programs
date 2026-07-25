//! Small Pinocchio 0.10 compatibility layer.
//!
//! UTXOpia's program code was written against Pinocchio 0.9 names
//! (`AccountInfo`, `Pubkey`, and `find_program_address`). Pinocchio 0.10 moved
//! those to `AccountView`, `Address`, and associated address methods. Keep the
//! protocol code readable while we migrate the dependency needed by MagicBlock.

pub use pinocchio::error::ProgramError;
pub use pinocchio::{AccountView as AccountInfo, Address as Pubkey};
use solana_address::Address;

#[inline(always)]
pub fn find_program_address(seeds: &[&[u8]], program_id: &Pubkey) -> (Pubkey, u8) {
    Address::find_program_address(seeds, program_id)
}

#[inline(always)]
pub fn account_owner(account: &AccountInfo) -> &Pubkey {
    // Pinocchio 0.10 marks raw owner access unsafe because it returns a pointer
    // into the runtime account view. The returned reference is used only during
    // the current instruction and never stored.
    unsafe { account.owner() }
}
