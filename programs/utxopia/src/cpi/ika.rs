//! Ika dWallet `approve_message` CPI helper.
//!
//! Constructs the CPI instruction by hand against `pinocchio = 0.9` rather
//! than depending on `ika-dwallet-pinocchio` (which pins `pinocchio ^0.10`
//! and would conflict with our workspace). Source of truth for the byte
//! layout, account ordering, and PDA seed: `docs/recon/2026-05-09-ika-sdk-brief.md`
//! (recon against `dwallet-labs/ika-pre-alpha` @ commit `3bd7945e012950e54fb4d0057b72a7d466556fc1`).
//!
//! Effect: this CPI causes the Ika program to create a `MessageApproval`
//! PDA owned by the Ika program; the off-chain network's mock signer (in
//! pre-alpha) then asynchronously fills a `Sign` account with the resulting
//! Schnorr/ECDSA signature.

use pinocchio::{
    account_info::AccountInfo,
    cpi::invoke_signed,
    instruction::{AccountMeta, Instruction, Seed, Signer},
    program_error::ProgramError,
    pubkey::Pubkey,
    ProgramResult,
};

/// Discriminator for the `approve_message` instruction on the Ika dWallet program.
pub const IX_APPROVE_MESSAGE: u8 = 8;

/// CPI authority PDA seed used by the Ika dWallet program.
/// `find_program_address(&[CPI_AUTHORITY_SEED], &our_program_id)` yields the PDA
/// that the Ika program treats as our program's signing principal.
pub const CPI_AUTHORITY_SEED: &[u8] = b"__ika_cpi_authority";

/// `u16` instruction-data value identifying ECDSA + SHA-256 (legacy Bitcoin).
/// See `crates/ika-dwallet-types/src/lib.rs:163` in the upstream repo.
pub const SIG_SCHEME_ECDSA_SHA256: u16 = 1;

/// `u16` value for Bitcoin BIP-143 segwit (ECDSA + double-SHA-256).
pub const SIG_SCHEME_ECDSA_DOUBLE_SHA256: u16 = 2;

/// `u16` value for Bitcoin Taproot (Schnorr + SHA-256). **UTXOpia v2 uses this.**
pub const SIG_SCHEME_TAPROOT_SHA256: u16 = 3;

/// Total length of the `approve_message` instruction data.
pub const APPROVE_MESSAGE_IX_DATA_LEN: usize = 100;

/// Build the 100-byte `approve_message` instruction-data buffer.
///
/// Layout (matches `chains/solana/program-sdk/pinocchio/src/cpi.rs:62` upstream):
/// ```text
/// [ 0     ] u8     discriminator       = IX_APPROVE_MESSAGE (8)
/// [ 1     ] u8     bump                = MessageApproval PDA bump
/// [ 2..34 ] [u8;32] message_digest      = Ika's digest of the message to sign
/// [34..66 ] [u8;32] message_metadata    = scheme-specific metadata; zeros for Taproot
/// [66..98 ] [u8;32] user_pubkey         = a 32-byte tag the Ika program echoes back
/// [98..100] u16 LE  signature_scheme    = e.g. SIG_SCHEME_TAPROOT_SHA256
/// ```
#[inline]
pub fn build_approve_message_ix_data(
    bump: u8,
    message_digest: &[u8; 32],
    message_metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
) -> [u8; APPROVE_MESSAGE_IX_DATA_LEN] {
    let mut data = [0u8; APPROVE_MESSAGE_IX_DATA_LEN];
    data[0] = IX_APPROVE_MESSAGE;
    data[1] = bump;
    data[2..34].copy_from_slice(message_digest);
    data[34..66].copy_from_slice(message_metadata_digest);
    data[66..98].copy_from_slice(user_pubkey);
    data[98..100].copy_from_slice(&signature_scheme.to_le_bytes());
    data
}

/// Account inputs for `approve_message`.
///
/// Order is fixed by the Ika program. The caller must pass `caller_program`
/// and `cpi_authority` matching this UTXOpia program; the Ika program
/// verifies the dWallet's `authority` field equals `cpi_authority.key()`.
pub struct ApproveMessageAccounts<'a> {
    /// The DWalletCoordinator PDA on the Ika program (readonly).
    pub coordinator: &'a AccountInfo,
    /// MessageApproval PDA on the Ika program — empty, will be created (writable).
    pub message_approval: &'a AccountInfo,
    /// The Ika dWallet account (readonly, owned by the Ika program).
    pub dwallet: &'a AccountInfo,
    /// Our program's account (readonly, must be executable; the Ika program checks).
    pub caller_program: &'a AccountInfo,
    /// Our CPI authority PDA (readonly, signer via `invoke_signed`).
    pub cpi_authority: &'a AccountInfo,
    /// Pays for the new MessageApproval PDA (writable, signer).
    pub payer: &'a AccountInfo,
    /// System program (readonly).
    pub system_program: &'a AccountInfo,
    /// The Ika dWallet program account itself (passed as the CPI target).
    pub dwallet_program: &'a AccountInfo,
}

/// Curve byte for Secp256k1 in the canonical MessageApproval payload.
const CURVE_SECP256K1_LE: [u8; 2] = [0x00, 0x00];

/// Derive the canonical MessageApproval PDA bump for our dWallet.
///
/// Matches the upstream voting example (`findMessageApprovalPda` in
/// `scripts/ika-setup/lib/ika-setup-vendored.ts`):
///
/// ```text
/// seeds = "dwallet"
///       || payload[..32] || payload[32..]    where payload = curve_le(2) || compressed_pubkey(33)
///       || "message_approval"
///       || signature_scheme_le(2)
///       || message_hash(32)
/// ```
///
/// We don't store the compressed-pubkey parity prefix on chain (PoolConfig
/// only has the 32-byte x-only key), so we try both BIP-340 parities and
/// return the bump of whichever matches the caller-supplied account. Two
/// `find_program_address` calls worst case (~10k CU) — rounding error
/// against the rest of the withdraw path.
pub fn find_message_approval_pda_bump(
    ika_program: &Pubkey,
    dwallet_xonly_pubkey: &[u8; 32],
    message_digest: &[u8; 32],
    expected: &Pubkey,
    signature_scheme: u16,
) -> Result<u8, ProgramError> {
    let scheme_le = signature_scheme.to_le_bytes();
    for parity in [0x02u8, 0x03u8] {
        let mut payload = [0u8; 35];
        payload[..2].copy_from_slice(&CURVE_SECP256K1_LE);
        payload[2] = parity;
        payload[3..].copy_from_slice(dwallet_xonly_pubkey);
        let (pda, bump) = pinocchio::pubkey::find_program_address(
            &[
                b"dwallet",
                &payload[..32],
                &payload[32..],
                b"message_approval",
                &scheme_le,
                message_digest,
            ],
            ika_program,
        );
        if &pda == expected {
            return Ok(bump);
        }
    }
    Err(ProgramError::InvalidSeeds)
}

/// Issue the `approve_message` CPI to the Ika dWallet program.
#[allow(clippy::too_many_arguments)]
pub fn approve_message(
    accounts: ApproveMessageAccounts<'_>,
    message_digest: &[u8; 32],
    message_metadata_digest: &[u8; 32],
    user_pubkey: &[u8; 32],
    signature_scheme: u16,
    message_approval_bump: u8,
    cpi_authority_bump: u8,
) -> ProgramResult {
    if accounts.cpi_authority.key() == &Pubkey::default() {
        return Err(ProgramError::InvalidArgument);
    }

    let ix_data = build_approve_message_ix_data(
        message_approval_bump,
        message_digest,
        message_metadata_digest,
        user_pubkey,
        signature_scheme,
    );

    let metas = [
        AccountMeta::readonly(accounts.coordinator.key()),
        AccountMeta::writable(accounts.message_approval.key()),
        AccountMeta::readonly(accounts.dwallet.key()),
        AccountMeta::readonly(accounts.caller_program.key()),
        AccountMeta::readonly_signer(accounts.cpi_authority.key()),
        AccountMeta::writable_signer(accounts.payer.key()),
        AccountMeta::readonly(accounts.system_program.key()),
    ];

    let instruction = Instruction {
        program_id: accounts.dwallet_program.key(),
        accounts: &metas,
        data: &ix_data,
    };

    let bump_bytes = [cpi_authority_bump];
    let signer_seeds: [Seed; 2] = [Seed::from(CPI_AUTHORITY_SEED), Seed::from(&bump_bytes)];
    let signers = [Signer::from(&signer_seeds)];

    invoke_signed(
        &instruction,
        &[
            accounts.coordinator,
            accounts.message_approval,
            accounts.dwallet,
            accounts.caller_program,
            accounts.cpi_authority,
            accounts.payer,
            accounts.system_program,
            accounts.dwallet_program,
        ],
        &signers,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recon-brief vectors: the byte layout of `approve_message` instruction data
    /// must exactly match the upstream contract. See
    /// `chains/solana/program-sdk/pinocchio/src/cpi.rs:62` in `dwallet-labs/ika-pre-alpha`.
    #[test]
    fn approve_message_ix_data_layout_taproot() {
        let bump = 0xAB;
        let mut sighash = [0u8; 32];
        for (i, b) in sighash.iter_mut().enumerate() {
            *b = i as u8; // 0x00, 0x01, ..., 0x1F
        }
        let metadata = [0u8; 32];
        let mut user = [0u8; 32];
        for (i, b) in user.iter_mut().enumerate() {
            *b = 0xCC ^ (i as u8);
        }

        let data = build_approve_message_ix_data(
            bump,
            &sighash,
            &metadata,
            &user,
            SIG_SCHEME_TAPROOT_SHA256,
        );

        // Total length is exactly 100 bytes.
        assert_eq!(data.len(), 100);
        // [0]: discriminator
        assert_eq!(data[0], IX_APPROVE_MESSAGE);
        assert_eq!(data[0], 8);
        // [1]: bump
        assert_eq!(data[1], 0xAB);
        // [2..34]: message_digest
        assert_eq!(&data[2..34], &sighash);
        // [34..66]: message_metadata_digest
        assert_eq!(&data[34..66], &metadata);
        // [66..98]: user_pubkey
        assert_eq!(&data[66..98], &user);
        // [98..100]: signature_scheme little-endian u16
        assert_eq!(&data[98..100], &3u16.to_le_bytes());
    }

    #[test]
    fn approve_message_ix_data_signature_scheme_constants_match_recon() {
        // The upstream enum (crates/ika-dwallet-types/src/lib.rs:163) assigns
        // these explicit u16 discriminants. Drift caught here at compile time.
        assert_eq!(SIG_SCHEME_ECDSA_SHA256, 1);
        assert_eq!(SIG_SCHEME_ECDSA_DOUBLE_SHA256, 2);
        assert_eq!(SIG_SCHEME_TAPROOT_SHA256, 3);
    }

    #[test]
    fn approve_message_ix_data_zero_inputs_round_trip() {
        let zeros = [0u8; 32];
        let data =
            build_approve_message_ix_data(0, &zeros, &zeros, &zeros, SIG_SCHEME_ECDSA_SHA256);
        assert_eq!(data[0], IX_APPROVE_MESSAGE);
        assert_eq!(data[1], 0);
        assert!(data[2..98].iter().all(|&b| b == 0));
        assert_eq!(&data[98..100], &1u16.to_le_bytes());
    }

    #[test]
    fn approve_message_ix_data_distinguishes_metadata_from_user() {
        let sighash = [0xAAu8; 32];
        let meta = [0xBBu8; 32];
        let user = [0xCCu8; 32];

        let data =
            build_approve_message_ix_data(7, &sighash, &meta, &user, SIG_SCHEME_TAPROOT_SHA256);

        assert_eq!(data[2..34], [0xAAu8; 32]);
        assert_eq!(data[34..66], [0xBBu8; 32]);
        assert_eq!(data[66..98], [0xCCu8; 32]);
    }

    #[test]
    fn cpi_authority_seed_matches_recon() {
        // Upstream constant: `pub const CPI_AUTHORITY_SEED: &[u8] = b"__ika_cpi_authority";`
        // (chains/solana/program-sdk/pinocchio/src/lib.rs:53)
        assert_eq!(CPI_AUTHORITY_SEED, b"__ika_cpi_authority");
    }
}
