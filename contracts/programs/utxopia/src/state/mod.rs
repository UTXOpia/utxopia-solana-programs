//! State account definitions (zero-copy)
//!
//! ## Core State Accounts
//!
//! | Account | Purpose |
//! |---------|---------|
//! | `PoolState` | Global pool config and statistics |
//! | `CommitmentTree` | Merkle tree of shielded commitments |
//!| `NullifierRecord` | Spent nullifiers (prevents double-spend) |
//! | `RedemptionRequest` | Pending BTC withdrawal request |
//!
//! ## External Account Readers (btc-light-client)
//!
//! | Reader | Purpose |
//! |--------|---------|
//! | `VerifiedTransactionView` | Read-only view of btc-light-client VerifiedTransaction PDA |
//! | `light_client_tip_height` | Read tip height from btc-light-client LightClient |

// Core state
pub mod commitment_tree;
pub mod completion_receipt;
pub mod deposit_intent;
pub mod deposit_receipt;
pub mod nullifier;
pub mod pool;
pub mod pool_config;
pub mod redemption;
pub mod token_config;
pub mod utxo;
pub mod verified_tx_reader;
pub mod vk_registry;

// Re-exports
pub use commitment_tree::*;
pub use completion_receipt::*;
pub use deposit_intent::*;
pub use deposit_receipt::*;
pub use nullifier::*;
pub use pool::*;
pub use pool_config::*;
pub use redemption::*;
pub use token_config::*;
pub use utxo::*;
pub use verified_tx_reader::*;
pub use vk_registry::*;

