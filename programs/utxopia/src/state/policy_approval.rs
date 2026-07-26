//! One-time approval for a permissioned-pool asset instruction.

use crate::pinocchio_compat::ProgramError;

pub const POLICY_APPROVAL_DISCRIMINATOR: u8 = 0x0c;
pub const POLICY_APPROVAL_VERSION: u8 = 1;

pub const POLICY_STATUS_PENDING: u8 = 0;
pub const POLICY_STATUS_APPROVED: u8 = 1;
pub const POLICY_STATUS_REJECTED: u8 = 2;
pub const POLICY_STATUS_CONSUMED: u8 = 3;

/// Byte-stable account layout. Accessors are used instead of casting so the
/// layout has no host-alignment dependency.
pub struct PolicyApproval;

impl PolicyApproval {
    pub const LEN: usize = 176;
    pub const SEED: &'static [u8] = b"policy_approval";

    const DISCRIMINATOR: usize = 0;
    const VERSION: usize = 1;
    const STATUS: usize = 2;
    const BUMP: usize = 3;
    const ACTION: usize = 4;
    const EXPIRES_AT_SLOT: core::ops::Range<usize> = 8..16;
    const POOL: core::ops::Range<usize> = 16..48;
    const ACTOR: core::ops::Range<usize> = 48..80;
    const POLICY_AUTHORITY: core::ops::Range<usize> = 80..112;
    const REQUEST_HASH: core::ops::Range<usize> = 112..144;
    const NONCE: core::ops::Range<usize> = 144..176;

    #[allow(clippy::too_many_arguments)]
    pub fn init(
        data: &mut [u8],
        bump: u8,
        action: u8,
        expires_at_slot: u64,
        pool: &[u8; 32],
        actor: &[u8; 32],
        policy_authority: &[u8; 32],
        request_hash: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<(), ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data.fill(0);
        data[Self::DISCRIMINATOR] = POLICY_APPROVAL_DISCRIMINATOR;
        data[Self::VERSION] = POLICY_APPROVAL_VERSION;
        data[Self::STATUS] = POLICY_STATUS_PENDING;
        data[Self::BUMP] = bump;
        data[Self::ACTION] = action;
        data[Self::EXPIRES_AT_SLOT].copy_from_slice(&expires_at_slot.to_le_bytes());
        data[Self::POOL].copy_from_slice(pool);
        data[Self::ACTOR].copy_from_slice(actor);
        data[Self::POLICY_AUTHORITY].copy_from_slice(policy_authority);
        data[Self::REQUEST_HASH].copy_from_slice(request_hash);
        data[Self::NONCE].copy_from_slice(nonce);
        Ok(())
    }

    pub fn validate(data: &[u8]) -> Result<(), ProgramError> {
        if data.len() != Self::LEN
            || data[Self::DISCRIMINATOR] != POLICY_APPROVAL_DISCRIMINATOR
            || data[Self::VERSION] != POLICY_APPROVAL_VERSION
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(())
    }

    pub fn status(data: &[u8]) -> u8 {
        data[Self::STATUS]
    }
    pub fn set_status(data: &mut [u8], status: u8) {
        data[Self::STATUS] = status;
    }
    pub fn bump(data: &[u8]) -> u8 {
        data[Self::BUMP]
    }
    pub fn action(data: &[u8]) -> u8 {
        data[Self::ACTION]
    }
    pub fn expires_at_slot(data: &[u8]) -> u64 {
        u64::from_le_bytes(data[Self::EXPIRES_AT_SLOT].try_into().unwrap())
    }
    pub fn pool(data: &[u8]) -> &[u8; 32] {
        data[Self::POOL].try_into().unwrap()
    }
    pub fn actor(data: &[u8]) -> &[u8; 32] {
        data[Self::ACTOR].try_into().unwrap()
    }
    pub fn policy_authority(data: &[u8]) -> &[u8; 32] {
        data[Self::POLICY_AUTHORITY].try_into().unwrap()
    }
    pub fn request_hash(data: &[u8]) -> &[u8; 32] {
        data[Self::REQUEST_HASH].try_into().unwrap()
    }
    pub fn nonce(data: &[u8]) -> &[u8; 32] {
        data[Self::NONCE].try_into().unwrap()
    }
}
