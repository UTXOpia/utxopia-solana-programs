//! Commitment tree state account (zero-copy)
//!
//! Implements a proper incremental Merkle tree using Poseidon hashing.
//! The tree supports up to 2^16 (65536) leaf commitments.
//!
//! This implementation matches standard ZK protocols (Tornado Cash, Semaphore):
//! - Pre-computed zero hashes for empty subtrees
//! - Frontier array to track rightmost filled nodes
//! - Standard Merkle path proofs compatible with ZK circuits

use crate::utils::crypto::poseidon2_hash;
use pinocchio::program_error::ProgramError;

/// Discriminator for CommitmentTree account
pub const COMMITMENT_TREE_DISCRIMINATOR: u8 = 0x05;

/// Maximum tree depth (supports 2^16 = 65536 commitments)
/// Reduced from 20 for JoinSplit circuit compatibility.
pub const TREE_DEPTH: usize = 16;

/// Number of historical roots to keep (for front-running protection).
/// Each inserted leaf records a root, and a multi-output JoinSplit inserts up to
/// MAX_SAFE_JOINSPLIT_SIZE leaves, so a small burst of txs could otherwise evict a root a
/// victim is still proving against and revert their spend. 256 raises that eviction bar well
/// above any realistic insertion rate over a proof-generation window (audit f02).
pub const ROOT_HISTORY_SIZE: usize = 256;

/// Pre-computed zero hashes for each level of the tree
/// ZERO[0] = 0 (empty leaf)
/// ZERO[i] = Poseidon(ZERO[i-1], ZERO[i-1])
///
/// These values must match the SDK's ZERO_HASHES exactly!
/// Pre-computed using Circom-compatible Poseidon with BN254 scalar field.
/// (matches Solana's sol_poseidon syscall and circomlib's poseidon.circom)
pub const ZERO_HASHES: [[u8; 32]; TREE_DEPTH + 1] = [
    [0u8; 32], // Level 0: Empty leaf
    hex_literal::hex!("2098f5fb9e239eab3ceac3f27b81e481dc3124d55ffed523a839ee8446b64864"), // Level 1
    hex_literal::hex!("1069673dcdb12263df301a6ff584a7ec261a44cb9dc68df067a4774460b1f1e1"), // Level 2
    hex_literal::hex!("18f43331537ee2af2e3d758d50f72106467c6eea50371dd528d57eb2b856d238"), // Level 3
    hex_literal::hex!("07f9d837cb17b0d36320ffe93ba52345f1b728571a568265caac97559dbc952a"), // Level 4
    hex_literal::hex!("2b94cf5e8746b3f5c9631f4c5df32907a699c58c94b2ad4d7b5cec1639183f55"), // Level 5
    hex_literal::hex!("2dee93c5a666459646ea7d22cca9e1bcfed71e6951b953611d11dda32ea09d78"), // Level 6
    hex_literal::hex!("078295e5a22b84e982cf601eb639597b8b0515a88cb5ac7fa8a4aabe3c87349d"), // Level 7
    hex_literal::hex!("2fa5e5f18f6027a6501bec864564472a616b2e274a41211a444cbe3a99f3cc61"), // Level 8
    hex_literal::hex!("0e884376d0d8fd21ecb780389e941f66e45e7acce3e228ab3e2156a614fcd747"), // Level 9
    hex_literal::hex!("1b7201da72494f1e28717ad1a52eb469f95892f957713533de6175e5da190af2"), // Level 10
    hex_literal::hex!("1f8d8822725e36385200c0b201249819a6e6e1e4650808b5bebc6bface7d7636"), // Level 11
    hex_literal::hex!("2c5d82f66c914bafb9701589ba8cfcfb6162b0a12acf88a8d0879a0471b5f85a"), // Level 12
    hex_literal::hex!("14c54148a0940bb820957f5adf3fa1134ef5c4aaa113f4646458f270e0bfbfd0"), // Level 13
    hex_literal::hex!("190d33b12f986f961e10c0ee44d8b9af11be25588cad89d416118e4bf4ebe80c"), // Level 14
    hex_literal::hex!("22f98aa9ce704152ac17354914ad73ed1167ae6596af510aa5b3649325e06c92"), // Level 15
    hex_literal::hex!("2a7c7c9b6ce5880b9f6f228d72bf6a575a526f29c66ecceef8b753d38bba7323"), // Level 16
];

/// Commitment tree for Merkle proofs (zero-copy layout)
///
/// Layout:
/// - discriminator: 1 byte
/// - bump: 1 byte
/// - padding: 6 bytes
/// - current_root: 32 bytes
/// - next_index: 8 bytes
/// - frontier: 16 * 32 = 512 bytes (rightmost filled nodes at each level)
/// - root_history: 256 * 32 = 8192 bytes
/// - root_history_index: 4 bytes
/// - reserved: 60 bytes
#[repr(C)]
pub struct CommitmentTree {
    /// Account discriminator
    pub discriminator: u8,

    /// Bump seed
    pub bump: u8,

    /// Padding for alignment
    _padding: [u8; 6],

    /// Current Merkle root
    pub current_root: [u8; 32],

    /// Number of leaves in the tree
    next_index: [u8; 8],

    /// Frontier: rightmost filled node hash at each level
    /// frontier[0] = last inserted leaf
    /// frontier[i] = rightmost filled node at level i
    pub frontier: [[u8; 32]; TREE_DEPTH],

    /// Historical roots for validation (circular buffer)
    pub root_history: [[u8; 32]; ROOT_HISTORY_SIZE],

    /// Current root history index
    root_history_index: [u8; 4],

    /// This tree's own rotation index (matches the PDA seed
    /// [SEED_PREFIX, tree_index]). Lets validate_frozen_tree confirm a historical tree in O(1)
    /// instead of deriving every index 0..active_index (audit f23). Carved from _reserved, so
    /// the layout/size is unchanged; legacy index-0 trees decode correctly (zero).
    tree_index: [u8; 4],

    /// Reserved for future use
    _reserved: [u8; 56],
}

impl CommitmentTree {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub const SEED_PREFIX: &'static [u8] = b"commitment_tree";

    /// Maximum number of leaves (2^16 = 65536)
    pub const MAX_LEAVES: u64 = 1u64 << TREE_DEPTH;

    /// Parse from account data
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != COMMITMENT_TREE_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Parse as mutable from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != COMMITMENT_TREE_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Initialize a new commitment tree in the given buffer
    pub fn init(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data[..Self::LEN].fill(0);
        data[0] = COMMITMENT_TREE_DISCRIMINATOR;

        let tree = unsafe { &mut *(data.as_mut_ptr() as *mut Self) };

        // Initialize current_root to the empty tree root (hash of all zeros)
        tree.current_root = ZERO_HASHES[TREE_DEPTH];

        Ok(tree)
    }

    // Getters
    pub fn next_index(&self) -> u64 {
        u64::from_le_bytes(self.next_index)
    }

    pub fn root_history_index(&self) -> u32 {
        u32::from_le_bytes(self.root_history_index)
    }

    pub fn tree_index(&self) -> u32 {
        u32::from_le_bytes(self.tree_index)
    }

    pub fn set_tree_index(&mut self, value: u32) {
        self.tree_index = value.to_le_bytes();
    }

    // Setters
    pub fn set_next_index(&mut self, value: u64) {
        self.next_index = value.to_le_bytes();
    }

    pub fn set_root_history_index(&mut self, value: u32) {
        self.root_history_index = value.to_le_bytes();
    }

    /// Check if a root is valid (current or in history)
    pub fn is_valid_root(&self, root: &[u8; 32]) -> bool {
        // Root history slots are zero-filled before the first ROOT_HISTORY_SIZE
        // updates. Zero is not a valid Poseidon tree root and must not be
        // accepted merely because an unused history slot contains it.
        if root == &[0u8; 32] {
            return false;
        }

        // Check current root
        if self.current_root == *root {
            return true;
        }

        // Check historical roots
        for historical_root in &self.root_history {
            if historical_root == root {
                return true;
            }
        }

        false
    }

    /// Add new root to history (called after tree update)
    fn update_root(&mut self, new_root: [u8; 32]) {
        let index = self.root_history_index() as usize;
        self.root_history[index % ROOT_HISTORY_SIZE] = self.current_root;
        self.set_root_history_index((index + 1) as u32);
        self.current_root = new_root;
    }

    /// Check if tree has capacity for more leaves
    pub fn has_capacity(&self) -> bool {
        self.next_index() < Self::MAX_LEAVES
    }

    /// Insert a new leaf commitment into the tree
    ///
    /// Uses the standard incremental Merkle tree algorithm:
    /// 1. Place leaf at position `next_index`
    /// 2. Walk up the tree, computing parent hashes
    /// 3. For left children (even index): save to frontier, pair with zero hash
    /// 4. For right children (odd index): pair with frontier value
    ///
    /// This produces the same root as a full sparse Merkle tree,
    /// but only requires O(depth) storage instead of O(2^depth).
    ///
    /// # Returns
    /// The leaf index where the commitment was inserted
    pub fn insert_leaf(&mut self, commitment: &[u8; 32]) -> Result<u64, ProgramError> {
        let leaf_index = self.next_index();
        if leaf_index >= Self::MAX_LEAVES {
            return Err(crate::error::UTXOpiaError::TreeFull.into());
        }

        let mut current_hash = *commitment;
        let mut current_index = leaf_index as usize;

        // Walk up the tree from leaf to root
        for (level, zero_hash) in ZERO_HASHES.iter().enumerate().take(TREE_DEPTH) {
            if current_index % 2 == 0 {
                // This is a left child - save to frontier and pair with zero hash
                self.frontier[level] = current_hash;
                current_hash = poseidon2_hash(&current_hash, zero_hash)?;
            } else {
                // This is a right child - pair with frontier (left sibling)
                current_hash = poseidon2_hash(&self.frontier[level], &current_hash)?;
            }
            current_index /= 2;
        }

        // Update root
        self.update_root(current_hash);

        // Increment leaf counter
        self.set_next_index(leaf_index + 1);

        Ok(leaf_index)
    }

    /// Insert a leaf and return the new root (for verification)
    pub fn insert_leaf_and_get_root(
        &mut self,
        commitment: &[u8; 32],
    ) -> Result<([u8; 32], u64), ProgramError> {
        let index = self.insert_leaf(commitment)?;
        Ok((self.current_root, index))
    }
}

#[cfg(test)]
#[path = "commitment_tree_tests.rs"]
mod tests;
