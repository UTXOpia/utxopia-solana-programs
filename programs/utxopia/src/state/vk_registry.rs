//! Verification Key Registry state account
//!
//! Stores Groth16 verification key material on-chain for JoinSplit(N,M) variants.

use pinocchio::program_error::ProgramError;

/// Discriminator for VK Registry account
pub const VK_REGISTRY_DISCRIMINATOR: u8 = 0x14;

/// Compute number of public inputs for a JoinSplit(N, M) variant
/// Public inputs: merkleRoot + boundParamsHash + N nullifiers + M commitments
pub fn joinsplit_num_public_inputs(n_inputs: u8, n_outputs: u8) -> usize {
    2 + (n_inputs as usize) + (n_outputs as usize)
}

/// Maximum number of IC points for the audited JoinSplit scope.
/// IC contains one base point plus one point per public input.
pub const MAX_IC_POINTS: usize = 1 + 2 + crate::constants::MAX_SAFE_JOINSPLIT_SIZE;

/// On-chain verification key storage (Groth16)
///
/// Layout (1060 bytes total):
/// - discriminator: 1 byte
/// - _padding: 1 byte
/// - n_inputs: 1 byte (JoinSplit N)
/// - n_outputs: 1 byte (JoinSplit M)
/// - authority: 32 bytes (who can update)
/// - vk_hash: 32 bytes (hash of the Groth16 verification key)
/// - delta_g2: 128 bytes
/// - ic_len: 1 byte
/// - _reserved: 31 bytes
/// - ic: MAX_IC_POINTS G1 points (64 bytes each)
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
    /// Groth16 delta G2 point
    pub delta_g2: [u8; 128],
    /// Number of populated IC points
    pub ic_len: u8,
    /// Reserved for future use
    _reserved: [u8; 31],
    /// Groth16 IC points, padded with zeros
    pub ic: [[u8; 64]; MAX_IC_POINTS],
}

impl VkRegistry {
    pub const SIZE: usize = core::mem::size_of::<Self>();
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

    /// True once the VK material has been permanently frozen (see [`Self::freeze`]).
    /// Stored in the first byte of the reserved area so the 1060-byte layout is unchanged.
    pub fn is_frozen(&self) -> bool {
        self._reserved[0] != 0
    }

    /// Permanently freeze this registry. One-way: there is no unfreeze. After freezing,
    /// `process_update_vk_registry` is rejected, removing the single-authority forge vector.
    pub fn freeze(&mut self) {
        self._reserved[0] = 1;
    }

    /// Get number of public inputs
    pub fn num_public_inputs(&self) -> usize {
        joinsplit_num_public_inputs(self.n_inputs, self.n_outputs)
    }

    /// Get VK hash
    pub fn get_vk_hash(&self) -> &[u8; 32] {
        &self.vk_hash
    }

    /// Get delta G2 point
    pub fn get_delta_g2(&self) -> &[u8; 128] {
        &self.delta_g2
    }

    /// Get populated IC points
    pub fn get_ic(&self) -> Result<&[[u8; 64]], ProgramError> {
        let len = self.ic_len as usize;
        if len == 0 || len > MAX_IC_POINTS || len != self.num_public_inputs() + 1 {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(&self.ic[..len])
    }

    /// Set Groth16 verification key material.
    pub fn set_vk(
        &mut self,
        vk_hash: &[u8; 32],
        delta_g2: &[u8; 128],
        ic: &[[u8; 64]],
    ) -> Result<(), ProgramError> {
        if ic.is_empty() || ic.len() > MAX_IC_POINTS || ic.len() != self.num_public_inputs() + 1 {
            return Err(ProgramError::InvalidInstructionData);
        }

        self.vk_hash.copy_from_slice(vk_hash);
        self.delta_g2.copy_from_slice(delta_g2);
        self.ic_len = ic.len() as u8;
        self.ic = [[0u8; 64]; MAX_IC_POINTS];
        self.ic[..ic.len()].copy_from_slice(ic);
        Ok(())
    }
}

#[cfg(test)]
#[path = "vk_registry_tests.rs"]
mod tests;
