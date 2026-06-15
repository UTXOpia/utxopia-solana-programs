//! Instruction handlers for UTXOpia (Multi-Token Shielded Pool)
//!
//! ## Discriminator Map
//!
//! | Disc | Instruction | Category |
//! |------|-------------|----------|
//! | 0 | `initialize` | Core |
//! | 1 | `set_paused` | Core |
//! | 2 | `set_pool_config` | Core |
//! | 3 | `propose_pool_update` | Pool updates |
//! | 4 | `execute_pool_update` | Pool updates |
//! | 5 | `cancel_pool_update` | Pool updates |
//! | 6 | `init_vk_registry` | VK admin |
//! | 7 | `update_vk_registry` | VK admin |
//! | 8 | `register_token` | Multi-token |
//! | 9 | `update_token_config` | Multi-token |
//! | 10 | `claim_fees` | Multi-token |
//! | 11 | `complete_deposit` | Deposit |
//! | 12 | `shield` | Deposit |
//! | 13 | `transact` | JoinSplit |
//! | 14 | `unshield` | JoinSplit (multi-output) |
//! | 15 | `redeem` | JoinSplit (multi-output) |
//! | 17 | `complete_redemption` | Redemption |
//! | 18 | `mark_processing` | Redemption |
//! | 19 | `cancel_redemption` | Redemption |
//! | 21 | `initialize_permissioned` | Core |
//! | 22 | `complete_deposit_permissioned` | Deposit |
//! | 23 | `shield_permissioned` | Deposit |
//! | 27 | `approve_redemption_signing` | Redemption |

// Core operations
pub mod approve_redemption_signing;
pub mod cancel_redemption;
pub mod complete_deposit;
pub mod complete_redemption;
pub mod initialize;
pub mod initialize_permissioned;
pub mod mark_processing;
pub mod redeem;
pub mod register_deposit_intent;
pub mod transact;
pub mod verify_deposit;

// Multi-token operations
pub mod claim_fees;
pub mod register_token;
pub mod shield;
pub mod unshield;
pub mod update_token_config;

// Admin utilities
pub mod admin_update_pool;
pub mod set_pool_config;

// VK registry (deployment)
pub mod init_vk_registry;

// Tree management
pub mod joinsplit_common;
pub mod rotate_tree;

// Re-exports
pub use admin_update_pool::*;
pub use approve_redemption_signing::*;
pub use cancel_redemption::*;
pub use claim_fees::*;
pub use complete_deposit::*;
pub use complete_redemption::*;
pub use init_vk_registry::*;
pub use initialize::*;
pub use initialize_permissioned::*;
pub use mark_processing::*;
pub use redeem::*;
pub use register_deposit_intent::*;
pub use register_token::*;
pub use rotate_tree::*;
pub use set_pool_config::*;
pub use shield::*;
pub use transact::*;
pub use unshield::*;
pub use update_token_config::*;
pub use verify_deposit::*;
