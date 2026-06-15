//! Program constants

/// Minimum deposit amount in satoshis (0.00005 BTC)
pub const MIN_DEPOSIT_SATS: u64 = 5_000;

/// Maximum deposit amount in satoshis (1000 BTC)
pub const MAX_DEPOSIT_SATS: u64 = 100_000_000_000;

/// Required Bitcoin confirmations
pub const REQUIRED_CONFIRMATIONS: u32 = 2;

/// Basis-points denominator. Configured fee bps must be strictly less than this so a
/// fee can never consume 100% of a deposit/withdrawal (which would mint zero / DoS).
pub const MAX_FEE_BPS: u16 = 10_000;

/// Maximum Groth16 proof size in bytes (256 bytes = 2 G1 + 1 G2)
pub const MAX_GROTH16_PROOF_SIZE: usize = 256;

/// Maximum BTC scriptPubKey length (raw bytes, not bech32 string)
/// P2TR/P2WSH = 34 bytes (OP_x + PUSH32 + 32-byte key/hash)
pub const MAX_BTC_SCRIPT_LEN: usize = 34;

/// BTC Light Client program ID — localnet (CuZv7it8XzwbBDAWDALsjCYUeEqN8qeoNVaRFn4zgZig)
/// Generated from target/deploy/btc_light_client-keypair.json (re-run cargo build-sbf if you regen the keypair)
#[cfg(all(feature = "localnet", not(feature = "devnet-regtest")))]
pub const BTC_LIGHT_CLIENT_PROGRAM_ID: [u8; 32] = [
    0xb0, 0xe7, 0xf9, 0xec, 0x8c, 0xab, 0x33, 0x84, 0x0e, 0x51, 0x4d, 0x02, 0xf5, 0x69, 0x54, 0x10,
    0xa7, 0x77, 0x67, 0x28, 0x6e, 0x4f, 0x27, 0x86, 0x50, 0x53, 0x3e, 0xa2, 0x3c, 0xce, 0x89, 0xb9,
];

/// BTC Light Client — devnet-regtest hybrid (8hCSNKf8ByqZdet2D4SDiZHDrB1u9ohkhqKKzr9i7vfQ)
/// Greenfield fresh deploy 2026-06-15. Tracks REGTEST headers (network_byte=3).
#[cfg(feature = "devnet-regtest")]
pub const BTC_LIGHT_CLIENT_PROGRAM_ID: [u8; 32] = [
    0x72, 0x4d, 0xf9, 0x1e, 0xc8, 0xc4, 0x80, 0x2c, 0x6a, 0x7c, 0x00, 0x7a, 0x03, 0x44, 0x91, 0x2c,
    0x89, 0xe8, 0x73, 0x4e, 0x07, 0x71, 0x59, 0x93, 0xb3, 0x9c, 0xc3, 0xad, 0x89, 0x36, 0x61, 0x67,
];

/// BTC Relay program ID — devnet (Ho6UTeF8yFnRdCK15tSZtcJozvkDABJZWYxkgGyWAfyq)
#[cfg(not(any(feature = "localnet", feature = "devnet-regtest")))]
pub const BTC_LIGHT_CLIENT_PROGRAM_ID: [u8; 32] = [
    // Live devnet btc-light-client: C8JoSKzondM7X1ESwrBSodGMrXWtEWNmawXyjh9zEWJZ
    0xa5, 0x4f, 0xbf, 0xc4, 0x89, 0x7f, 0xa5, 0x53, 0x1c, 0x76, 0xa4, 0x82, 0xba, 0xce, 0x0f, 0x72,
    0x9d, 0x18, 0x8b, 0xc4, 0x4e, 0x4d, 0xdb, 0xe9, 0xf2, 0x1d, 0x69, 0x81, 0xa2, 0x08, 0x41, 0xa6,
];

/// Audited JoinSplit scope (N + M). VK registry accounts support variants up to 10.
pub const MAX_SAFE_JOINSPLIT_SIZE: usize = 10;

/// Guard against a contradictory build: `mainnet` must never be combined with a
/// dev/test network feature, or `CHAIN_ID` (baked into every bound_params_hash) would be
/// ambiguous and could silently weaken cross-chain replay protection.
#[cfg(all(
    feature = "mainnet",
    any(feature = "devnet", feature = "localnet", feature = "devnet-regtest")
))]
compile_error!("`mainnet` feature is mutually exclusive with devnet/localnet/devnet-regtest");

/// Chain ID for bound params hash verification (prevents cross-chain replay).
/// NOTE: a non-mainnet build (the default) uses the devnet domain separator. A mainnet
/// deployment MUST be built with `--features mainnet`; otherwise proofs are bound to the
/// devnet CHAIN_ID. The guard above only catches contradictory combinations.
#[cfg(not(feature = "mainnet"))]
pub const CHAIN_ID: u64 = 103; // Solana devnet

#[cfg(feature = "mainnet")]
pub const CHAIN_ID: u64 = 101; // Solana mainnet

/// Redemption processing timeout in slots (~24 hours at ~2.5 slots/sec).
/// If a redemption stays in Processing longer than this, the user can cancel.
pub const REDEMPTION_TIMEOUT_SLOTS: u64 = 216_000;

/// Canonical Bitcoin redemption-tx parameters. The backend
/// (`backend/src/redemption/builder.rs`) MUST construct redemption txs with
/// exactly these values, otherwise the on-chain reconstructed sighash (see
/// `approve_redemption_signing`) will not match the broadcast tx and approval
/// will be rejected. These pin the otherwise non-deterministic tx fields so the
/// program can re-derive the BIP-341 sighash from trusted state.
pub const BTC_TX_VERSION: u32 = 2;
pub const BTC_TX_LOCKTIME: u32 = 0;
/// Per-input nSequence: ENABLE_RBF_NO_LOCKTIME (0xFFFFFFFD).
pub const BTC_INPUT_SEQUENCE: u32 = 0xFFFF_FFFD;
/// Dust threshold (sats): a change-to-pool output is only created when change
/// strictly exceeds this. Must equal the backend's `BTC_DUST_THRESHOLD`.
pub const BTC_DUST_THRESHOLD_SATS: u64 = 330;

/// Timelock delay for pool parameter updates (48 hours in seconds)
pub const TIMELOCK_DELAY_SECS: i64 = 48 * 60 * 60;

/// Token-2022 program ID (TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb)
pub const TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];

/// Legacy Token program ID (TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA)
pub const TOKEN_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];
