/// Discriminator for BitcoinLightClient account
pub(crate) const BTC_LIGHT_CLIENT_DISCRIMINATOR: u8 = 0x06;

/// Discriminator for BlockHeader account
pub(crate) const BLOCK_HEADER_DISCRIMINATOR: u8 = 0x07;

/// Discriminator for VerifiedTransaction account
pub(crate) const VERIFIED_TX_DISCRIMINATOR: u8 = 0x08;

/// Discriminator for HeightIndex account
pub(crate) const HEIGHT_INDEX_DISCRIMINATOR: u8 = 0x09;

pub(crate) const LIGHT_CLIENT_SEED: &[u8] = b"btc_light_client";
pub(crate) const BLOCK_HEADER_SEED: &[u8] = b"block";
pub(crate) const HEIGHT_INDEX_SEED: &[u8] = b"height_index";
pub(crate) const VERIFIED_TX_SEED: &[u8] = b"verified_tx";

/// Maximum number of headers in a single extend_blockchain batch
pub(crate) const MAX_BATCH_SIZE: u8 = 10;

/// Target timespan for difficulty adjustment (2 weeks in seconds)
pub(crate) const TARGET_TIMESPAN: u32 = 1_209_600;

/// Blocks per difficulty epoch
pub(crate) const BLOCKS_PER_EPOCH: u64 = 2016;

/// Required confirmations for SPV verification
pub(crate) const REQUIRED_CONFIRMATIONS: u64 = 6;

// Network IDs (stored in BitcoinLightClient.network)
pub(crate) const NETWORK_MAINNET: u8 = 0;
pub(crate) const NETWORK_TESTNET3: u8 = 1;
pub(crate) const NETWORK_TESTNET4: u8 = 2;
pub(crate) const NETWORK_REGTEST: u8 = 3;

/// Whether this build is allowed to track `network` at all.
///
/// `network` selects how much of Bitcoin consensus the client enforces — regtest retargets
/// nothing and has no meaningful work — so it is effectively a "verify / do not verify" switch
/// held by whoever called `initialize` first. A mainnet binary has no legitimate reason to track
/// regtest, and refusing it here means the switch cannot be flipped in production even by the
/// authority. Testnet3 was never supported.
pub(crate) fn network_allowed_in_build(network: u8) -> bool {
    match network {
        NETWORK_MAINNET | NETWORK_TESTNET4 => true,
        NETWORK_REGTEST => !cfg!(feature = "mainnet"),
        // Testnet3 has a defined id but no retarget handling in `required_bits_for_next_block`,
        // so accepting it would mean running with difficulty unchecked.
        NETWORK_TESTNET3 => false,
        _ => false,
    }
}
