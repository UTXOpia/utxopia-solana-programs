//! Verification Key Registry state account
//!
//! Stores Groth16 verification key hashes on-chain for JoinSplit(N,M) variants.

use pinocchio::program_error::ProgramError;

/// Discriminator for VK Registry account
pub const VK_REGISTRY_DISCRIMINATOR: u8 = 0x14;

/// Compute number of public inputs for a JoinSplit(N, M) variant
/// Public inputs: merkleRoot + boundParamsHash + N nullifiers + M commitments
pub fn joinsplit_num_public_inputs(n_inputs: u8, n_outputs: u8) -> usize {
    2 + (n_inputs as usize) + (n_outputs as usize)
}

/// On-chain verification key hash storage (Groth16)
///
/// Layout (256 bytes total):
/// - discriminator: 1 byte
/// - _padding: 1 byte
/// - n_inputs: 1 byte (JoinSplit N)
/// - n_outputs: 1 byte (JoinSplit M)
/// - authority: 32 bytes (who can update)
/// - vk_hash: 32 bytes (hash of the Groth16 verification key)
/// - reserved: 188 bytes
#[repr(C)]
pub struct VkRegistry {
    /// Account discriminator
    pub discriminator: u8,
    /// Reserved (was circuit_type, now always JoinSplit)
    _padding: u8,
    /// JoinSplit N (number of inputs)
    pub n_inputs: u8,
    /// JoinSplit M (number of outputs)
    pub n_outputs: u8,
    /// Authority that can update this VK hash
    pub authority: [u8; 32],
    /// Groth16 verification key hash
    pub vk_hash: [u8; 32],
    /// Reserved for future use
    _reserved: [u8; 188],
}

impl VkRegistry {
    pub const SIZE: usize = 256;
    pub const SEED: &'static [u8] = b"vk_registry";

    /// Parse from account data
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != VK_REGISTRY_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Parse as mutable
    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != VK_REGISTRY_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Initialize a new VK registry
    pub fn init(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        data[..Self::SIZE].fill(0);
        data[0] = VK_REGISTRY_DISCRIMINATOR;
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Check if authority matches
    pub fn is_authority(&self, pubkey: &[u8; 32]) -> bool {
        self.authority == *pubkey
    }

    /// Get number of public inputs
    pub fn num_public_inputs(&self) -> usize {
        joinsplit_num_public_inputs(self.n_inputs, self.n_outputs)
    }

    /// Get VK hash
    pub fn get_vk_hash(&self) -> &[u8; 32] {
        &self.vk_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_joinsplit_public_inputs() {
        assert_eq!(joinsplit_num_public_inputs(1, 2), 5); // root + bound + 1 null + 2 comm
        assert_eq!(joinsplit_num_public_inputs(2, 2), 6);
        assert_eq!(joinsplit_num_public_inputs(1, 1), 4);
    }

    #[test]
    fn test_vk_registry_size() {
        assert_eq!(VkRegistry::SIZE, 256);
    }
}
