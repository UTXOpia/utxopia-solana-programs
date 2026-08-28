//! Read-only reader for btc-light-client's VerifiedTransaction and BitcoinLightClient accounts
//!
//! Lightweight module to read btc-light-client accounts from utxopia.
//! No Borsh, just zero-copy byte reading.

use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError, Pubkey};

/// Discriminator for VerifiedTransaction account (must match btc-light-client)
pub const VERIFIED_TX_DISCRIMINATOR: u8 = 0x08;

/// PDA seed for VerifiedTransaction (must match btc-light-client)
pub const VERIFIED_TX_SEED: &[u8] = b"verified_tx";

/// PDA seed for the singleton BitcoinLightClient account (must match btc-light-client)
pub const LIGHT_CLIENT_SEED: &[u8] = b"btc_light_client";

/// Discriminator for BitcoinLightClient account (must match btc-light-client)
pub const BTC_LIGHT_CLIENT_DISCRIMINATOR: u8 = 0x06;

/// Pin a VerifiedTransaction account to its canonical PDA `["verified_tx", block_hash, txid]`.
///
/// Owner + discriminator checks alone are not enough: they accept any btc-light-client-owned
/// account whose first byte is the VT discriminator. Re-deriving the PDA from the block_hash
/// and txid stored *inside* the account and matching it against the account's own address
/// proves the account was created by the light client's `verify_transaction` at the canonical
/// address — a forged/substituted account cannot satisfy this.
pub fn assert_canonical_verified_tx(
    account_key: &Pubkey,
    block_hash: &[u8; 32],
    txid: &[u8; 32],
    btc_lc_id: &Pubkey,
) -> Result<(), ProgramError> {
    let (expected, _) = find_program_address(&[VERIFIED_TX_SEED, block_hash, txid], btc_lc_id);
    if account_key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

/// Pin the BitcoinLightClient (tip) account to its canonical singleton PDA.
pub fn assert_canonical_light_client(
    account_key: &Pubkey,
    btc_lc_id: &Pubkey,
) -> Result<(), ProgramError> {
    let (expected, _) = find_program_address(&[LIGHT_CLIENT_SEED], btc_lc_id);
    if account_key != &expected {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(())
}

/// Minimum size of VerifiedTransaction account
const VERIFIED_TX_MIN_LEN: usize = 120;

/// Minimum size of BitcoinLightClient account for reading tip_height
const LIGHT_CLIENT_MIN_LEN: usize = 144;

/// Read-only view of btc-light-client VerifiedTransaction PDA (120 bytes)
///
/// Layout:
/// - disc(1) + bump(1) + _pad(2) + block_height(4) + block_hash(32) + txid(32) + verified_at(8) + tx_index(4) + _reserved(36)
pub struct VerifiedTransactionView<'a> {
    data: &'a [u8],
}

impl<'a> VerifiedTransactionView<'a> {
    /// Parse from account data, validating discriminator and length
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, ProgramError> {
        if data.len() < VERIFIED_TX_MIN_LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != VERIFIED_TX_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(Self { data })
    }

    /// Block height (u32 LE at bytes [4..8])
    pub fn block_height(&self) -> u32 {
        u32::from_le_bytes(self.data[4..8].try_into().unwrap())
    }

    /// Block hash (32 bytes at [8..40])
    pub fn block_hash(&self) -> &[u8; 32] {
        self.data[8..40].try_into().unwrap()
    }

    /// Transaction ID (32 bytes at [40..72])
    pub fn txid(&self) -> &[u8; 32] {
        self.data[40..72].try_into().unwrap()
    }

    /// Verified-at timestamp (i64 LE at [72..80])
    pub fn verified_at(&self) -> i64 {
        i64::from_le_bytes(self.data[72..80].try_into().unwrap())
    }

    /// Transaction index in block (u32 LE at [80..84])
    pub fn tx_index(&self) -> u32 {
        u32::from_le_bytes(self.data[80..84].try_into().unwrap())
    }

    /// Reinit epoch this proof was minted under (u32 LE at [84..88]).
    /// Bound at verify_transaction time to the light client's reinit epoch so a stale
    /// proof from a pre-reinitialization chain instance can be detected.
    pub fn reinit_epoch(&self) -> u32 {
        u32::from_le_bytes(self.data[84..88].try_into().unwrap())
    }
}

/// Read tip height from btc-light-client BitcoinLightClient account
///
/// Layout offset 136..144 is tip_height (u64 LE)
pub fn light_client_tip_height(data: &[u8]) -> Result<u64, ProgramError> {
    if data.len() < LIGHT_CLIENT_MIN_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[0] != BTC_LIGHT_CLIENT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(u64::from_le_bytes(data[136..144].try_into().unwrap()))
}

/// Bitcoin network the light client tracks (`BitcoinLightClient.network`, offset 3).
/// 0 = mainnet, 1 = testnet3, 2 = testnet4, 3 = regtest.
///
/// The network this build's light client MUST be tracking, or `None` for a featureless host
/// build (`cargo test`/`check`) which never reads a real client — an SBF build with no network
/// feature is already a `compile_error!` in `lib.rs`. `localnet + devnet` together match two
/// arms and fail loudly as a duplicate definition, which is the same way the light-client
/// program id behaves.
///
/// Verified against the deployed clients on 2026-08-28: the devnet client
/// (`9MBq6FCqw1tSh7Vn7rJjWEz8pRcZ5R6mfEzgALiAJwM9`) reports 2, the devnet-regtest client
/// (`F7w1wWioDcKjoQkgqFZBbSATB3mxReFRJSBEJTn3CopZ`) reports 3.
#[cfg(feature = "mainnet")]
const EXPECTED_NETWORK: Option<u8> = Some(0);
#[cfg(all(
    not(feature = "mainnet"),
    feature = "devnet",
    not(feature = "devnet-regtest")
))]
const EXPECTED_NETWORK: Option<u8> = Some(2);
#[cfg(all(
    not(feature = "mainnet"),
    any(feature = "devnet-regtest", feature = "localnet")
))]
const EXPECTED_NETWORK: Option<u8> = Some(3);
#[cfg(all(
    not(feature = "mainnet"),
    not(feature = "devnet"),
    not(feature = "localnet")
))]
const EXPECTED_NETWORK: Option<u8> = None;

/// Reject a light client that is not tracking the network this build is for.
///
/// The whole bridge rests on "a `VerifiedTransaction` PDA exists, therefore real Bitcoin work
/// backs it" — but every consensus rule in btc-light-client (PoW, difficulty, median-time-past)
/// is gated on that one `network` byte, and nothing on this side used to look at it. A light
/// client pointed at regtest satisfies the same PDA derivation while checking nothing, so a
/// build must refuse to read a client tracking anything but its own network. Cheap: one byte,
/// once per SPV consumer.
///
/// This used to be gated on `#[cfg(feature = "mainnet")]`, which meant the devnet build — the
/// one actually deployed — performed no check at all, while carrying `process_reinitialize`
/// (compiled in for every non-mainnet flavour) that can rewrite `network` to regtest. A devnet
/// light-client admin could therefore turn the whole SPV layer into "verify nothing" and this
/// side would not notice (audit_2 N-6).
pub fn assert_light_client_network(data: &[u8]) -> Result<(), ProgramError> {
    if data.len() < LIGHT_CLIENT_MIN_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[0] != BTC_LIGHT_CLIENT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    if let Some(expected) = EXPECTED_NETWORK {
        if data[3] != expected {
            return Err(ProgramError::InvalidAccountData);
        }
    }
    Ok(())
}

/// Minimum size of BitcoinLightClient account for reading the reinit epoch (offset 176..180).
const LIGHT_CLIENT_EPOCH_MIN_LEN: usize = 180;

/// Read the reinit epoch from btc-light-client BitcoinLightClient account.
///
/// Layout offset 176..180 is reinit_epoch (u32 LE), stored in the account's _reserved region.
pub fn light_client_reinit_epoch(data: &[u8]) -> Result<u32, ProgramError> {
    if data.len() < LIGHT_CLIENT_EPOCH_MIN_LEN {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[0] != BTC_LIGHT_CLIENT_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(u32::from_le_bytes(data[176..180].try_into().unwrap()))
}

/// Assert that a VerifiedTransaction proof belongs to the current light-client chain instance.
///
/// After `process_reinitialize` resets the singleton light client to a different chain, old
/// proofs keep their PDA and discriminator but carry the *previous* reinit epoch. Comparing the
/// proof's epoch against the current light-client epoch rejects stale/wrong-chain proofs.
pub fn assert_verified_tx_current_epoch(
    vt: &VerifiedTransactionView,
    light_client_data: &[u8],
) -> Result<(), ProgramError> {
    let current_epoch = light_client_reinit_epoch(light_client_data)?;
    if vt.reinit_epoch() != current_epoch {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

/// PDA seed for HeightIndex (must match btc-light-client)
pub const HEIGHT_INDEX_SEED: &[u8] = b"height_index";

/// Discriminator for HeightIndex account (must match btc-light-client)
pub const HEIGHT_INDEX_DISCRIMINATOR: u8 = 0x09;

/// HeightIndex layout: disc(1) + bump(1) + _padding(6) + block_hash(32) + height(8)
const HEIGHT_INDEX_LEN: usize = 48;

/// Require live proof that `block_hash` is *still* the canonical block at `block_height`.
///
/// A `VerifiedTransaction` PDA is a permanent record of a merkle proof that was valid when
/// `verify_transaction` ran. Nothing ever invalidates one. `assert_canonical_verified_tx`
/// re-derives the PDA from the block hash and txid stored *inside that same account*, so it
/// proves the account was minted by the light client and nothing about whether the fact still
/// holds; and the confirmation count is computed against `tip`, which only grows, so it is
/// vacuous for a stale proof. After a reorg that orphans the block, both checks still pass and
/// the deposit or redemption settles against a transaction that is no longer in the chain
/// (audit_1 F-BTC-04).
///
/// `HeightIndex` is what btc-light-client's own `verify_transaction` treats as the canonicality
/// oracle, so consulting it here puts the spend path on the same footing.
///
/// The account is located by address rather than by a fixed index: its PDA is fully determined
/// by `block_height`, which comes from the PDA-pinned `VerifiedTransaction`, and the four entry
/// points into these instructions have different trailing-account layouts. Callers append it
/// anywhere. Absence is an error, never a skip — an optional check is not a check (that is what
/// made F-BTC-03 bypassable).
pub fn assert_block_still_canonical(
    accounts: &[AccountInfo],
    block_height: u64,
    block_hash: &[u8; 32],
    btc_lc_id: &Pubkey,
) -> Result<(), ProgramError> {
    let height_le = block_height.to_le_bytes();
    let (expected, _) = find_program_address(&[HEIGHT_INDEX_SEED, &height_le], btc_lc_id);

    let hi = accounts
        .iter()
        .find(|a| a.address().as_ref() == expected.as_ref())
        .ok_or(ProgramError::NotEnoughAccountKeys)?;

    if crate::pinocchio_compat::account_owner(hi) != btc_lc_id {
        return Err(ProgramError::IllegalOwner);
    }

    let data = hi.try_borrow()?;
    check_height_index_bytes(&data, &height_le, block_hash)
}

/// Byte-level half of [`assert_block_still_canonical`], split out so the layout can be tested
/// on the host — offsets into a foreign program's account are where this goes wrong, and they
/// cannot drift silently if a test pins them.
pub fn check_height_index_bytes(
    data: &[u8],
    height_le: &[u8; 8],
    block_hash: &[u8; 32],
) -> Result<(), ProgramError> {
    if data.len() < HEIGHT_INDEX_LEN || data[0] != HEIGHT_INDEX_DISCRIMINATOR {
        return Err(ProgramError::InvalidAccountData);
    }
    // Redundant with the seed, but the seed only proves the address; this proves the account
    // agrees about which height it indexes.
    if &data[40..48] != height_le {
        return Err(ProgramError::InvalidAccountData);
    }
    if data[8..40] != block_hash[..] {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

#[cfg(test)]
mod height_index_tests {
    use super::*;

    /// Mirrors btc-light-client's `HeightIndex`:
    /// disc(1) + bump(1) + _padding(6) + block_hash(32) + height(8) = 48.
    fn blob(disc: u8, block_hash: &[u8; 32], height: u64) -> [u8; 48] {
        let mut d = [0u8; 48];
        d[0] = disc;
        d[1] = 254; // bump — must not be read as anything
        d[8..40].copy_from_slice(block_hash);
        d[40..48].copy_from_slice(&height.to_le_bytes());
        d
    }

    #[test]
    fn accepts_the_canonical_block_at_that_height() {
        let hash = [0xABu8; 32];
        let d = blob(HEIGHT_INDEX_DISCRIMINATOR, &hash, 149_843);
        assert!(check_height_index_bytes(&d, &149_843u64.to_le_bytes(), &hash).is_ok());
    }

    #[test]
    fn rejects_a_reorged_block_at_the_same_height() {
        // The exact F-BTC-04 shape: a VerifiedTransaction still names the orphan, while the
        // height index has moved on to the block that actually won.
        let orphan = [0xABu8; 32];
        let winner = [0xCDu8; 32];
        let d = blob(HEIGHT_INDEX_DISCRIMINATOR, &winner, 149_843);
        assert!(check_height_index_bytes(&d, &149_843u64.to_le_bytes(), &orphan).is_err());
        assert!(check_height_index_bytes(&d, &149_843u64.to_le_bytes(), &winner).is_ok());
    }

    #[test]
    fn rejects_a_height_index_for_a_different_height() {
        let hash = [0xABu8; 32];
        let d = blob(HEIGHT_INDEX_DISCRIMINATOR, &hash, 149_843);
        assert!(check_height_index_bytes(&d, &149_844u64.to_le_bytes(), &hash).is_err());
    }

    #[test]
    fn rejects_wrong_discriminator_and_short_data() {
        let hash = [0xABu8; 32];
        let h = 149_843u64.to_le_bytes();
        // 0x07 is BlockHeader, 0x08 VerifiedTransaction — both are btc-light-client-owned, so
        // the owner check upstream does not separate them. Only the discriminator does.
        for wrong in [0x00u8, 0x06, 0x07, 0x08] {
            let d = blob(wrong, &hash, 149_843);
            assert!(check_height_index_bytes(&d, &h, &hash).is_err(), "disc {wrong:#04x}");
        }
        let d = blob(HEIGHT_INDEX_DISCRIMINATOR, &hash, 149_843);
        assert!(check_height_index_bytes(&d[..47], &h, &hash).is_err());
    }

    /// If HeightIndex ever grows, the fields we read must not move. Pins the offsets against
    /// the layout comment rather than against our own constructor.
    #[test]
    fn offsets_match_the_btc_light_client_layout() {
        let hash = [0x11u8; 32];
        let d = blob(HEIGHT_INDEX_DISCRIMINATOR, &hash, 0x0203_0405_0607_0809);
        assert_eq!(d[0], HEIGHT_INDEX_DISCRIMINATOR);
        assert_eq!(&d[8..40], &hash[..]);
        assert_eq!(u64::from_le_bytes(d[40..48].try_into().unwrap()), 0x0203_0405_0607_0809);
        assert_eq!(HEIGHT_INDEX_LEN, 48);
    }
}
