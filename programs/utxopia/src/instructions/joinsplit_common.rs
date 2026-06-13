use pinocchio::{
    account_info::AccountInfo,
    program_error::ProgramError,
    pubkey::{find_program_address, Pubkey},
    sysvars::rent::Rent,
    ProgramResult,
};

use crate::error::UTXOpiaError;
use crate::state::{CommitmentTree, NullifierRecord, VkRegistry, NULLIFIER_RECORD_DISCRIMINATOR};
use crate::utils::groth16::GROTH16_PROOF_SIZE;
use crate::utils::{create_pda_account, validate_account_writable};

pub const MAX_JOINSPLIT_SIZE: usize = crate::constants::MAX_SAFE_JOINSPLIT_SIZE;
pub const MAX_PUBLIC_OUTPUTS: usize = 3;
pub const STEALTH_DATA_PER_OUTPUT: usize = 72;
pub const CHADBUFFER_AUTHORITY_SIZE: usize = 32;
pub const ZERO_REF: &[u8; 32] = &[0u8; 32];

pub fn take_bytes<'a>(
    data: &'a [u8],
    offset: &mut usize,
    len: usize,
) -> Result<&'a [u8], ProgramError> {
    let end = offset
        .checked_add(len)
        .ok_or(ProgramError::InvalidInstructionData)?;
    if end > data.len() {
        return Err(ProgramError::InvalidInstructionData);
    }

    let bytes = &data[*offset..end];
    *offset = end;
    Ok(bytes)
}

pub fn read_u64_le(data: &[u8], offset: &mut usize) -> Result<u64, ProgramError> {
    let bytes = take_bytes(data, offset, 8)?;
    let mut out = [0u8; 8];
    out.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(out))
}

#[derive(Clone, Copy)]
pub struct JoinSplitHeader {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub n_public_outputs: usize,
    pub proof_source: u8,
}

pub struct JoinSplitPrefix<'a> {
    pub proof_bytes: &'a [u8],
    pub merkle_root: &'a [u8; 32],
    pub bound_params_hash: &'a [u8; 32],
    pub nullifiers: [&'a [u8; 32]; MAX_JOINSPLIT_SIZE],
    pub commitments_out: [&'a [u8; 32]; MAX_JOINSPLIT_SIZE],
    pub stealth_data_start: usize,
    pub stealth_data_end: usize,
}

pub fn parse_header(data: &[u8]) -> Result<JoinSplitHeader, ProgramError> {
    if data.len() < 4 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let header = JoinSplitHeader {
        n_inputs: data[0] as usize,
        n_outputs: data[1] as usize,
        n_public_outputs: data[2] as usize,
        proof_source: data[3],
    };

    if header.proof_source > 1
        || header.n_inputs == 0
        || header.n_outputs == 0
        || header.n_inputs + header.n_outputs > MAX_JOINSPLIT_SIZE
    {
        return Err(ProgramError::InvalidInstructionData);
    }

    Ok(header)
}

pub fn validate_public_outputs(
    header: JoinSplitHeader,
    require_none: bool,
) -> Result<(), ProgramError> {
    if require_none {
        if header.n_public_outputs != 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
        return Ok(());
    }

    if header.n_public_outputs == 0
        || header.n_public_outputs > MAX_PUBLIC_OUTPUTS
        || header.n_public_outputs > header.n_outputs
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}

pub fn validate_account_count(
    accounts_len: usize,
    min_accounts: usize,
    proof_source: u8,
) -> ProgramResult {
    let required_accounts = min_accounts + usize::from(proof_source == 1);
    if accounts_len < required_accounts {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    Ok(())
}

pub fn parse_prefix<'a>(
    data: &'a [u8],
    accounts: &'a [AccountInfo],
    header: JoinSplitHeader,
    n_tree_outputs: usize,
    proof_buf: &'a mut [u8; GROTH16_PROOF_SIZE],
) -> Result<JoinSplitPrefix<'a>, ProgramError> {
    let proof_data_size = if header.proof_source == 0 {
        GROTH16_PROOF_SIZE
    } else {
        0
    };
    let min_len = 4
        + proof_data_size
        + 32
        + 32
        + header.n_inputs * 32
        + header.n_outputs * 32
        + n_tree_outputs * STEALTH_DATA_PER_OUTPUT;
    if data.len() < min_len {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut offset = 4;
    let proof_bytes: &[u8] = if header.proof_source == 0 {
        let proof = &data[offset..offset + GROTH16_PROOF_SIZE];
        offset += GROTH16_PROOF_SIZE;
        proof
    } else {
        let buf_info = &accounts[accounts.len() - 1];
        crate::utils::chadbuffer::validate_chadbuffer_owner(buf_info)?;
        let buf_data = buf_info.try_borrow_data()?;
        if buf_data.len() < CHADBUFFER_AUTHORITY_SIZE + GROTH16_PROOF_SIZE {
            return Err(ProgramError::InvalidAccountData);
        }
        let src =
            &buf_data[CHADBUFFER_AUTHORITY_SIZE..CHADBUFFER_AUTHORITY_SIZE + GROTH16_PROOF_SIZE];
        proof_buf.copy_from_slice(src);
        proof_buf.as_slice()
    };

    let merkle_root: &[u8; 32] = data[offset..offset + 32].try_into().unwrap();
    offset += 32;
    let bound_params_hash: &[u8; 32] = data[offset..offset + 32].try_into().unwrap();
    offset += 32;

    let mut nullifiers: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];
    for nullifier in nullifiers.iter_mut().take(header.n_inputs) {
        *nullifier = data[offset..offset + 32].try_into().unwrap();
        offset += 32;
    }

    let mut commitments_out: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];
    for commitment in commitments_out.iter_mut().take(header.n_outputs) {
        *commitment = data[offset..offset + 32].try_into().unwrap();
        offset += 32;
    }

    let stealth_data_start = offset;
    let stealth_data_end = stealth_data_start + n_tree_outputs * STEALTH_DATA_PER_OUTPUT;

    Ok(JoinSplitPrefix {
        proof_bytes,
        merkle_root,
        bound_params_hash,
        nullifiers,
        commitments_out,
        stealth_data_start,
        stealth_data_end,
    })
}

pub fn verify_vk_merkle_and_proof(
    vk_registry_info: &AccountInfo,
    commitment_tree_info: &AccountInfo,
    header: JoinSplitHeader,
    prefix: &JoinSplitPrefix<'_>,
) -> ProgramResult {
    {
        let vk_data = vk_registry_info.try_borrow_data()?;
        let vk = VkRegistry::from_bytes(&vk_data)?;

        if vk.n_inputs != header.n_inputs as u8 || vk.n_outputs != header.n_outputs as u8 {
            return Err(UTXOpiaError::InvalidVkRegistry.into());
        }
    }

    {
        let tree_data = commitment_tree_info.try_borrow_data()?;
        let tree = CommitmentTree::from_bytes(&tree_data)?;
        if !tree.is_valid_root(prefix.merkle_root) {
            return Err(UTXOpiaError::InvalidMerkleProof.into());
        }
    }

    const MAX_PUBLIC_INPUTS: usize = 2 + MAX_JOINSPLIT_SIZE;
    let mut public_inputs: [&[u8; 32]; MAX_PUBLIC_INPUTS] = [ZERO_REF; MAX_PUBLIC_INPUTS];
    let mut pi_len = 0;
    public_inputs[pi_len] = prefix.merkle_root;
    pi_len += 1;
    public_inputs[pi_len] = prefix.bound_params_hash;
    pi_len += 1;
    for nullifier in prefix.nullifiers.iter().take(header.n_inputs) {
        public_inputs[pi_len] = *nullifier;
        pi_len += 1;
    }
    for commitment in prefix.commitments_out.iter().take(header.n_outputs) {
        public_inputs[pi_len] = *commitment;
        pi_len += 1;
    }

    let (delta_g2, ic) =
        crate::utils::groth16::load_joinsplit_vk(header.n_inputs as u8, header.n_outputs as u8)?;
    crate::utils::groth16::verify_groth16_joinsplit_proof(
        prefix.proof_bytes,
        &public_inputs[..pi_len],
        delta_g2,
        ic,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn create_nullifier_records(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    start_index: usize,
    nullifiers: &[&[u8; 32]],
    payer: &AccountInfo,
    rent: &Rent,
    operation_type: u8,
    instruction_disc: u8,
) -> ProgramResult {
    let mut null_hashes: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];

    for (i, nullifier) in nullifiers.iter().enumerate() {
        let nullifier_info = &accounts[start_index + i];
        validate_account_writable(nullifier_info)?;

        let nullifier_seeds: &[&[u8]] = &[NullifierRecord::SEED, nullifier.as_ref()];
        let (expected_pda, bump) = find_program_address(nullifier_seeds, program_id);
        if nullifier_info.key() != &expected_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        {
            let nullifier_data = nullifier_info.try_borrow_data()?;
            if !nullifier_data.is_empty() && nullifier_data[0] == NULLIFIER_RECORD_DISCRIMINATOR {
                return Err(UTXOpiaError::NullifierAlreadyUsed.into());
            }
        }

        let bump_bytes = [bump];
        let signer_seeds: &[&[u8]] = &[NullifierRecord::SEED, nullifier.as_ref(), &bump_bytes];
        create_pda_account(
            payer,
            nullifier_info,
            program_id,
            rent.minimum_balance(NullifierRecord::LEN),
            NullifierRecord::LEN as u64,
            signer_seeds,
        )?;

        {
            let mut nullifier_data = nullifier_info.try_borrow_mut_data()?;
            NullifierRecord::init(&mut nullifier_data)?;
        }

        null_hashes[i] = *nullifier;
    }

    crate::utils::events::emit_nullifiers_batch(
        &null_hashes[..nullifiers.len()],
        operation_type,
        instruction_disc,
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_bytes_rejects_short_input_without_advancing() {
        let data = [1u8, 2, 3];
        let mut offset = 1usize;

        let err = take_bytes(&data, &mut offset, 4).unwrap_err();

        assert_eq!(err, ProgramError::InvalidInstructionData);
        assert_eq!(offset, 1);
    }

    #[test]
    fn read_u64_le_advances_offset() {
        let data = [9u8, 8, 7, 6, 5, 4, 3, 2, 1];
        let mut offset = 1usize;

        let value = read_u64_le(&data, &mut offset).unwrap();

        assert_eq!(value, u64::from_le_bytes([8, 7, 6, 5, 4, 3, 2, 1]));
        assert_eq!(offset, data.len());
    }
}
