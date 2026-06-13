//! UTXOpia - Privacy-Preserving BTC to Solana Bridge (Pinocchio)
//!
//! SHIELDED-ONLY ARCHITECTURE (JoinSplit Model):
//! - zkBTC exists only as commitments in Merkle tree
//! - Users never hold public zkBTC tokens
//! - Amount revealed ONLY at BTC withdrawal
//! - All deposits use stealth announcements for recipient discovery
//! - All transfers use JoinSplit(N,M) proofs with EdDSA-Poseidon signatures
//!
//! ## Privacy Guarantee
//!
//! | Operation     | Amount Visible? |
//! |---------------|-----------------|
//! | Deposit       | No (in commitment) |
//! | Transact      | No (JoinSplit) |
//! | Withdraw      | Yes (unavoidable) |
//!
//! ## Core Flow
//!
//! ```text
//! BTC Deposit → Verify SPV → Stealth Announcement → Mint to Pool → Commitment in Tree
//!                                                                          ↓
//!                                    JoinSplit Transact (private, ZK proof)
//!                                                                          ↓
//!                              Withdraw → ZK Proof → Burn from Pool → BTC
//! ```

#[cfg(not(feature = "no-entrypoint"))]
use pinocchio::entrypoint;
use pinocchio::{
    account_info::AccountInfo, program_error::ProgramError, pubkey::Pubkey, ProgramResult,
};

pub mod constants;
pub mod cpi;
pub mod error;
pub mod instructions;
pub mod state;
pub mod utils;

/// Program ID (update after deployment)
pub const ID: Pubkey = [
    0x0a, 0x6a, 0x3c, 0x1e, 0x87, 0x32, 0x1a, 0x5c, 0x7f, 0x4b, 0x2d, 0x9e, 0x8a, 0x6c, 0x3f, 0x1b,
    0x5d, 0x2a, 0x8e, 0x4c, 0x7b, 0x3a, 0x1f, 0x6d, 0x9c, 0x5e, 0x2b, 0x8f, 0x4a, 0x7d, 0x3c, 0x1e,
];

/// Instruction discriminators grouped by category.
pub mod instruction {
    // Core (0-2)
    pub const INITIALIZE: u8 = 0;
    pub const SET_PAUSED: u8 = 1;
    pub const SET_POOL_CONFIG: u8 = 2;

    // Pool updates (3-5)
    pub const PROPOSE_POOL_UPDATE: u8 = 3;
    pub const EXECUTE_POOL_UPDATE: u8 = 4;
    pub const CANCEL_POOL_UPDATE: u8 = 5;

    // VK admin (6-7)
    pub const INIT_VK_REGISTRY: u8 = 6;
    pub const UPDATE_VK_REGISTRY: u8 = 7;

    // Multi-token (8-10)
    pub const REGISTER_TOKEN: u8 = 8;
    pub const UPDATE_TOKEN_CONFIG: u8 = 9;
    pub const CLAIM_FEES: u8 = 10;

    // Deposit (11-12)
    pub const COMPLETE_DEPOSIT: u8 = 11;
    pub const SHIELD: u8 = 12;

    // JoinSplit (13-15) — all share n_in + n_out + n_pub + proof_source header
    pub const TRANSACT: u8 = 13;
    pub const UNSHIELD: u8 = 14;
    pub const REDEEM: u8 = 15;

    // Redemption lifecycle (17-19)
    pub const COMPLETE_REDEMPTION: u8 = 17;
    pub const MARK_PROCESSING: u8 = 18;
    pub const CANCEL_REDEMPTION: u8 = 19;

    // Tree management (20)
    pub const ROTATE_TREE: u8 = 20;

    // OP_RETURN-free deposits (24-25).
    // Backend's deposit_tracker uses 24 to register a DepositIntent PDA before
    // sweep, then 25 to verify the swept tx against that PDA on chain.
    pub const REGISTER_DEPOSIT_INTENT: u8 = 24;
    pub const VERIFY_DEPOSIT: u8 = 25;

    // Ika pre-broadcast signing approval (27)
    pub const APPROVE_REDEMPTION_SIGNING: u8 = 27;
}

#[cfg(not(feature = "no-entrypoint"))]
entrypoint!(process_instruction);

/// Main entrypoint - routes to instruction handlers
pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8],
) -> ProgramResult {
    let (discriminator, data) = instruction_data
        .split_first()
        .ok_or(ProgramError::InvalidInstructionData)?;

    match *discriminator {
        // Core (0-2)
        instruction::INITIALIZE => instructions::process_initialize(program_id, accounts, data),
        instruction::SET_PAUSED => process_set_paused(program_id, accounts, data),
        instruction::SET_POOL_CONFIG => {
            instructions::process_set_pool_config(program_id, accounts, data)
        }
        // Pool updates (3-5)
        instruction::PROPOSE_POOL_UPDATE => {
            instructions::process_propose_pool_update(program_id, accounts, data)
        }
        instruction::EXECUTE_POOL_UPDATE => {
            instructions::process_execute_pool_update(program_id, accounts, data)
        }
        instruction::CANCEL_POOL_UPDATE => {
            instructions::process_cancel_pool_update(program_id, accounts, data)
        }
        // VK admin (6-7)
        instruction::INIT_VK_REGISTRY => {
            instructions::process_init_vk_registry(program_id, accounts, data)
        }
        instruction::UPDATE_VK_REGISTRY => {
            instructions::process_update_vk_registry(program_id, accounts, data)
        }
        // Multi-token (8-10)
        instruction::REGISTER_TOKEN => {
            instructions::process_register_token(program_id, accounts, data)
        }
        instruction::UPDATE_TOKEN_CONFIG => {
            instructions::process_update_token_config(program_id, accounts, data)
        }
        instruction::CLAIM_FEES => instructions::process_claim_fees(program_id, accounts, data),
        // Deposit (11-12)
        instruction::COMPLETE_DEPOSIT => {
            instructions::process_complete_deposit(program_id, accounts, data)
        }
        instruction::SHIELD => instructions::process_shield(program_id, accounts, data),
        // JoinSplit (13-15)
        instruction::TRANSACT => instructions::process_transact(program_id, accounts, data),
        instruction::UNSHIELD => instructions::process_unshield(program_id, accounts, data),
        instruction::REDEEM => instructions::process_redeem(program_id, accounts, data),
        // Redemption lifecycle (17-19)
        instruction::COMPLETE_REDEMPTION => {
            instructions::process_complete_redemption(program_id, accounts, data)
        }
        instruction::MARK_PROCESSING => {
            instructions::process_mark_processing(program_id, accounts, data)
        }
        instruction::CANCEL_REDEMPTION => {
            instructions::process_cancel_redemption(program_id, accounts, data)
        }
        // Tree management (20)
        instruction::ROTATE_TREE => instructions::process_rotate_tree(program_id, accounts, data),
        // OP_RETURN-free deposits (24-25)
        instruction::REGISTER_DEPOSIT_INTENT => {
            instructions::process_register_deposit_intent(program_id, accounts, data)
        }
        instruction::VERIFY_DEPOSIT => {
            instructions::process_verify_deposit(program_id, accounts, data)
        }
        // Ika pre-broadcast signing approval (27)
        instruction::APPROVE_REDEMPTION_SIGNING => {
            instructions::process_approve_redemption_signing(program_id, accounts, data)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// Set pool paused state (admin only)
fn process_set_paused(program_id: &Pubkey, accounts: &[AccountInfo], data: &[u8]) -> ProgramResult {
    use crate::error::UTXOpiaError;
    use crate::state::PoolState;
    use crate::utils::validate_program_owner;
    use pinocchio::sysvars::{clock::Clock, Sysvar};

    if accounts.len() < 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }

    let pool_state = &accounts[0];
    let authority = &accounts[1];

    validate_program_owner(pool_state, program_id)?;

    if !authority.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let paused = data[0] != 0;

    {
        let mut pool_data = pool_state.try_borrow_mut_data()?;
        let pool = PoolState::from_bytes_mut(&mut pool_data)?;

        if authority.key().as_ref() != pool.authority {
            return Err(UTXOpiaError::Unauthorized.into());
        }

        pool.set_paused(paused);
        let ts = Clock::get()?.unix_timestamp;
        pool.set_last_update(ts);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_discriminators_unique() {
        let discriminators: &[u8] = &[
            instruction::INITIALIZE,
            instruction::SET_PAUSED,
            instruction::SET_POOL_CONFIG,
            instruction::PROPOSE_POOL_UPDATE,
            instruction::EXECUTE_POOL_UPDATE,
            instruction::CANCEL_POOL_UPDATE,
            instruction::INIT_VK_REGISTRY,
            instruction::UPDATE_VK_REGISTRY,
            instruction::REGISTER_TOKEN,
            instruction::UPDATE_TOKEN_CONFIG,
            instruction::CLAIM_FEES,
            instruction::COMPLETE_DEPOSIT,
            instruction::SHIELD,
            instruction::TRANSACT,
            instruction::UNSHIELD,
            instruction::REDEEM,
            instruction::COMPLETE_REDEMPTION,
            instruction::MARK_PROCESSING,
            instruction::CANCEL_REDEMPTION,
        ];

        for (i, &d1) in discriminators.iter().enumerate() {
            for (j, &d2) in discriminators.iter().enumerate() {
                if i != j {
                    assert_ne!(d1, d2, "Duplicate at {} and {}", i, j);
                }
            }
        }
    }

    #[test]
    fn test_account_discriminators_unique() {
        use crate::state::commitment_tree::COMMITMENT_TREE_DISCRIMINATOR;
        use crate::state::completion_receipt::COMPLETION_RECEIPT_DISCRIMINATOR;
        use crate::state::deposit_intent::DEPOSIT_INTENT_DISCRIMINATOR;
        use crate::state::deposit_receipt::DEPOSIT_RECEIPT_DISCRIMINATOR;
        use crate::state::nullifier::NULLIFIER_RECORD_DISCRIMINATOR;
        use crate::state::pool::POOL_STATE_DISCRIMINATOR;
        use crate::state::pool_config::POOL_CONFIG_DISCRIMINATOR;
        use crate::state::redemption::REDEMPTION_REQUEST_DISCRIMINATOR;
        use crate::state::token_config::TOKEN_CONFIG_DISCRIMINATOR;
        use crate::state::utxo::UTXO_RECORD_DISCRIMINATOR;
        use crate::state::vk_registry::VK_REGISTRY_DISCRIMINATOR;

        // All UTXOpia-owned account discriminators must be unique
        let discs: &[u8] = &[
            POOL_STATE_DISCRIMINATOR,         // 0x01
            NULLIFIER_RECORD_DISCRIMINATOR,   // 0x03
            REDEMPTION_REQUEST_DISCRIMINATOR, // 0x04
            COMMITMENT_TREE_DISCRIMINATOR,    // 0x05
            DEPOSIT_RECEIPT_DISCRIMINATOR,    // 0x06
            DEPOSIT_INTENT_DISCRIMINATOR,     // 0x07
            COMPLETION_RECEIPT_DISCRIMINATOR, // 0x08
            UTXO_RECORD_DISCRIMINATOR,        // 0x09
            POOL_CONFIG_DISCRIMINATOR,        // 0x0A
            TOKEN_CONFIG_DISCRIMINATOR,       // 0x0B
            VK_REGISTRY_DISCRIMINATOR,        // 0x14
        ];

        for (i, &d1) in discs.iter().enumerate() {
            for (j, &d2) in discs.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        d1, d2,
                        "Duplicate account discriminator at {} (0x{:02x}) and {} (0x{:02x})",
                        i, d1, j, d2
                    );
                }
            }
        }
    }

    #[test]
    fn test_utxo_discriminator_value() {
        use crate::state::utxo::UTXO_RECORD_DISCRIMINATOR;
        assert_eq!(UTXO_RECORD_DISCRIMINATOR, 0x09);
    }
}
