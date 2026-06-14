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

/// BTC Light Client — devnet-regtest hybrid (E3Q7dNDNw9W8oL1ghm62Ecau4zHBZ1W5zxrnNVaoRs6v)
/// Same Solana devnet program account, but tracks REGTEST headers (network_byte=3).
#[cfg(feature = "devnet-regtest")]
pub const BTC_LIGHT_CLIENT_PROGRAM_ID: [u8; 32] = [
    0xc1, 0xc5, 0x3a, 0x1f, 0x0b, 0x32, 0x3f, 0x0f, 0x36, 0xd8, 0x6f, 0xe9, 0x13, 0xa4, 0x48, 0x8d,
    0x2d, 0xd6, 0x4c, 0x28, 0xf7, 0x74, 0x9b, 0x4a, 0xd3, 0xc0, 0x0e, 0x91, 0x28, 0x34, 0x5f, 0x1f,
];

/// BTC Relay program ID — devnet (Ho6UTeF8yFnRdCK15tSZtcJozvkDABJZWYxkgGyWAfyq)
#[cfg(not(any(feature = "localnet", feature = "devnet-regtest")))]
pub const BTC_LIGHT_CLIENT_PROGRAM_ID: [u8; 32] = [
    0xf9, 0x89, 0xe5, 0x99, 0x89, 0xcc, 0x7e, 0xc1, 0xa0, 0x54, 0xb3, 0x8a, 0x3f, 0xa4, 0x56, 0x44,
    0x9a, 0x2e, 0x83, 0xd2, 0xbe, 0xf4, 0x78, 0x48, 0x02, 0x46, 0xb5, 0x87, 0x45, 0xea, 0x9d, 0xb0,
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
