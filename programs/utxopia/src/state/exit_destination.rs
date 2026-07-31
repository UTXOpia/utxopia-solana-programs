//! Auditor-registered exit destination for the ragequit path.
//!
//! The set is modelled as one PDA per entry: existence *is* membership, so there
//! is no list to scan, no realloc, and no size cap. Append-only falls out of the
//! design — the program has no instruction that closes one, so an auditor can
//! widen the escape hatch but never narrow it. That asymmetry is load-bearing:
//! a removable entry would hand the auditor back the ability to trap funds.

use crate::pinocchio_compat::ProgramError;

pub const EXIT_DESTINATION_DISCRIMINATOR: u8 = 0x0d;
pub const EXIT_DESTINATION_VERSION: u8 = 1;

/// Kind is a PDA seed, so a Solana owner and a BTC script hash that happen to
/// share the same 32 bytes still resolve to different accounts.
pub const EXIT_KIND_SOLANA_OWNER: u8 = 0;
pub const EXIT_KIND_BTC_SCRIPT: u8 = 1;

pub fn is_valid_exit_kind(kind: u8) -> bool {
    matches!(kind, EXIT_KIND_SOLANA_OWNER | EXIT_KIND_BTC_SCRIPT)
}

/// Byte-stable account layout, accessors instead of casting (mirrors the other
/// state accounts so the layout has no host-alignment dependency).
pub struct ExitDestination;

impl ExitDestination {
    pub const LEN: usize = 36;
    pub const SEED: &'static [u8] = b"exit_destination";

    const DISCRIMINATOR: usize = 0;
    const VERSION: usize = 1;
    const BUMP: usize = 2;
    const KIND: usize = 3;
    const KEY: core::ops::Range<usize> = 4..36;

    pub fn init(data: &mut [u8], bump: u8, kind: u8, key: &[u8; 32]) -> Result<(), ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data.fill(0);
        data[Self::DISCRIMINATOR] = EXIT_DESTINATION_DISCRIMINATOR;
        data[Self::VERSION] = EXIT_DESTINATION_VERSION;
        data[Self::BUMP] = bump;
        data[Self::KIND] = kind;
        data[Self::KEY].copy_from_slice(key);
        Ok(())
    }

    pub fn validate(data: &[u8]) -> Result<(), ProgramError> {
        if data.len() != Self::LEN
            || data[Self::DISCRIMINATOR] != EXIT_DESTINATION_DISCRIMINATOR
            || data[Self::VERSION] != EXIT_DESTINATION_VERSION
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(())
    }

    pub fn bump(data: &[u8]) -> u8 {
        data[Self::BUMP]
    }
    pub fn kind(data: &[u8]) -> u8 {
        data[Self::KIND]
    }
    pub fn key(data: &[u8]) -> &[u8; 32] {
        data[Self::KEY].try_into().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_then_validate_roundtrips() {
        let mut data = [0u8; ExitDestination::LEN];
        let key = [7u8; 32];
        ExitDestination::init(&mut data, 254, EXIT_KIND_BTC_SCRIPT, &key).unwrap();
        ExitDestination::validate(&data).unwrap();
        assert_eq!(ExitDestination::bump(&data), 254);
        assert_eq!(ExitDestination::kind(&data), EXIT_KIND_BTC_SCRIPT);
        assert_eq!(ExitDestination::key(&data), &key);
    }

    #[test]
    fn validate_rejects_foreign_or_short_accounts() {
        let mut data = [0u8; ExitDestination::LEN];
        ExitDestination::init(&mut data, 1, EXIT_KIND_SOLANA_OWNER, &[0u8; 32]).unwrap();

        let mut wrong_disc = data;
        wrong_disc[0] = POOL_STATE_DISCRIMINATOR_FOR_TEST;
        assert!(ExitDestination::validate(&wrong_disc).is_err());

        let mut wrong_version = data;
        wrong_version[1] = EXIT_DESTINATION_VERSION + 1;
        assert!(ExitDestination::validate(&wrong_version).is_err());

        assert!(ExitDestination::validate(&data[..ExitDestination::LEN - 1]).is_err());
    }

    const POOL_STATE_DISCRIMINATOR_FOR_TEST: u8 = 0x01;

    #[test]
    fn only_the_two_known_kinds_are_accepted() {
        assert!(is_valid_exit_kind(EXIT_KIND_SOLANA_OWNER));
        assert!(is_valid_exit_kind(EXIT_KIND_BTC_SCRIPT));
        for kind in [2u8, 3, 0xff] {
            assert!(!is_valid_exit_kind(kind));
        }
    }
}
