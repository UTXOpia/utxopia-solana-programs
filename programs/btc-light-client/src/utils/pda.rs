//! PDA creation helper with pre-funded-account poisoning resistance.

use pinocchio::{
    account_info::AccountInfo, instruction::Signer, pubkey::Pubkey, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};

/// Create a program-owned PDA, tolerating a pre-funded (poisoned) target.
///
/// # Security
/// Every PDA address in this program is deterministic, so a griefer can transfer
/// a single lamport to the known address before the program initializes it. A
/// bare `CreateAccount` then fails (`SystemError::AccountAlreadyInUse`), which
/// would permanently block header ingestion / verification at that address — a
/// permissionless denial of service.
///
/// To stay resilient, when the account is already funded but still
/// uninitialized we reconstruct it in place: top up the rent shortfall with
/// `Transfer`, then `Allocate` the space and `Assign` ownership to this program,
/// both authorized by the PDA seeds.
///
/// `signers` must contain exactly the seed signer for `pda` (e.g. `&[signer]`).
#[inline]
pub fn create_or_claim_pda(
    payer: &AccountInfo,
    pda: &AccountInfo,
    program_id: &Pubkey,
    lamports: u64,
    space: u64,
    signers: &[Signer],
) -> ProgramResult {
    if pda.lamports() == 0 {
        return CreateAccount {
            from: payer,
            to: pda,
            lamports,
            space,
            owner: program_id,
        }
        .invoke_signed(signers);
    }

    // Pre-funded PDA: rebuild it in place instead of failing.
    let current = pda.lamports();
    if lamports > current {
        Transfer {
            from: payer,
            to: pda,
            lamports: lamports - current,
        }
        .invoke()?;
    }
    if (pda.data_len() as u64) < space {
        Allocate {
            account: pda,
            space,
        }
        .invoke_signed(signers)?;
    }
    if pda.owner() != program_id {
        Assign {
            account: pda,
            owner: program_id,
        }
        .invoke_signed(signers)?;
    }
    Ok(())
}
