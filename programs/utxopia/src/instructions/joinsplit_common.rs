use crate::pinocchio_compat::{find_program_address, AccountInfo, ProgramError, Pubkey};
use pinocchio::{sysvars::rent::Rent, ProgramResult};

use crate::error::UTXOpiaError;
use crate::state::{
    CommitmentTree, NullifierRecord, PoolState, VkRegistry, COMMITMENT_TREE_DISCRIMINATOR,
    NULLIFIER_RECORD_DISCRIMINATOR,
};
use crate::utils::groth16::GROTH16_PROOF_SIZE;
use crate::utils::{create_pda_account, validate_account_writable, validate_frozen_tree};

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

/// What the caller declares it is passing, so the program never has to guess.
///
/// This byte used to be `proof_source`, valued 0 or 1 — bit 0 keeps that exact
/// meaning, so instruction-data offsets are unchanged and nothing downstream
/// shifts. The remaining bits replace the positional heuristics that used to
/// recover the optional account tail by counting backwards from the end and by
/// asking whether an account "looks like" a commitment tree.
///
/// A flag only selects **which slot to read**. Every slot still validates owner,
/// signer and PDA seeds exactly as before, so a caller that lies about what it
/// passed does not gain anything — it breaks its own transaction. What the flags
/// buy is that adding an optional account no longer perturbs the arithmetic that
/// recovers the others, and that a stuffed extra account is caught by the
/// end-of-list check instead of being silently absorbed into a subtraction.
pub mod jsflags {
    /// Proof lives in the trailing `ChadBuffer` rather than instruction data.
    pub const PROOF_IN_BUFFER: u8 = 1 << 0;
    /// A relayer signs and pays instead of the note owner.
    pub const RELAYER: u8 = 1 << 1;
    /// A rotated-out `CommitmentTree` is supplied to prove membership of notes
    /// committed before the rotation.
    pub const FROZEN_SOURCE_TREE: u8 = 1 << 2;
    /// `(PolicyApproval, policy_program)` pair for a permissioned pool.
    pub const POLICY: u8 = 1 << 3;
    /// Outputs are queued as `QueuedLeaf` PDAs instead of inserted inline.
    pub const QUEUED_LEAVES: u8 = 1 << 4;

    pub const ALL: u8 =
        PROOF_IN_BUFFER | RELAYER | FROZEN_SOURCE_TREE | POLICY | QUEUED_LEAVES;
}

#[derive(Clone, Copy)]
pub struct JoinSplitHeader {
    pub n_inputs: usize,
    pub n_outputs: usize,
    pub n_public_outputs: usize,
    /// See [`jsflags`]. Bit 0 is the historical `proof_source`.
    pub flags: u8,
}

impl JoinSplitHeader {
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }

    /// Bit 0, under its old name, for call sites that only care about the proof.
    pub fn proof_in_buffer(&self) -> bool {
        self.has(jsflags::PROOF_IN_BUFFER)
    }
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

/// Rebuild the canonical nullifier concatenation for the policy intent hash.
/// Parsing hands them back as separate refs; the hash wants one slice, in the
/// order the instruction listed them.
pub fn nullifiers_concat<'a>(
    prefix: &JoinSplitPrefix,
    n_inputs: usize,
    buf: &'a mut [u8; MAX_JOINSPLIT_SIZE * 32],
) -> &'a [u8] {
    for i in 0..n_inputs {
        buf[i * 32..(i + 1) * 32].copy_from_slice(prefix.nullifiers[i]);
    }
    &buf[..n_inputs * 32]
}

pub fn parse_header(data: &[u8]) -> Result<JoinSplitHeader, ProgramError> {
    if data.len() < 4 {
        return Err(ProgramError::InvalidInstructionData);
    }

    let header = JoinSplitHeader {
        n_inputs: data[0] as usize,
        n_outputs: data[1] as usize,
        n_public_outputs: data[2] as usize,
        flags: data[3],
    };

    // Reject unknown bits rather than ignoring them: a client built against a
    // newer flag set must fail loudly here, not have its extra accounts
    // reinterpreted as something else.
    if header.flags & !jsflags::ALL != 0
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
    let proof_data_size = if !header.proof_in_buffer() {
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
    let proof_bytes: &[u8] = if !header.proof_in_buffer() {
        let proof = &data[offset..offset + GROTH16_PROOF_SIZE];
        offset += GROTH16_PROOF_SIZE;
        proof
    } else {
        let buf_info = &accounts[accounts.len() - 1];
        crate::utils::chadbuffer::validate_chadbuffer_owner(buf_info)?;
        let buf_data = buf_info.try_borrow()?;
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
        let n: &[u8; 32] = data[offset..offset + 32].try_into().unwrap();
        // Reject non-canonical encodings: the syscall multiplies by the raw scalar and G1
        // has order r, so `n` and `n + r` prove the same statement, but the nullifier PDA
        // dedup seed uses these raw bytes — distinct PDAs for one note → double-spend.
        if !crate::utils::crypto::is_canonical_fr(n) {
            return Err(UTXOpiaError::InvalidZkProof.into());
        }
        *nullifier = n;
        offset += 32;
    }

    let mut commitments_out: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];
    for commitment in commitments_out.iter_mut().take(header.n_outputs) {
        let c: &[u8; 32] = data[offset..offset + 32].try_into().unwrap();
        // Reject non-canonical encodings. Groth16 verifies public inputs modulo r, so a
        // byte-distinct alias `c + k*r` would still satisfy the proof, but these RAW bytes are
        // inserted into the Merkle tree and emitted in stealth/memo events. A non-canonical alias
        // would create a leaf and metadata that the wallet/circuit can never reproduce, stranding
        // the output. Requiring canonical bytes keeps the on-chain leaf == the proved commitment.
        if !crate::utils::crypto::is_canonical_fr(c) {
            return Err(UTXOpiaError::InvalidZkProof.into());
        }
        *commitment = c;
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

/// Cheap identity check: does this account look like a program-owned CommitmentTree?
/// Used to detect an optional frozen source-tree account positionally without ambiguity
/// (relayer accounts are signers, proof buffers are ChadBuffer-owned — neither matches).
pub fn looks_like_commitment_tree(account: &AccountInfo, program_id: &Pubkey) -> bool {
    if !account.owned_by(program_id) {
        return false;
    }
    account
        .try_borrow()
        .map(|d| d.first().copied() == Some(COMMITMENT_TREE_DISCRIMINATOR))
        .unwrap_or(false)
}

pub fn verify_vk_merkle_and_proof(
    program_id: &Pubkey,
    pool_state_info: &AccountInfo,
    vk_registry_info: &AccountInfo,
    commitment_tree_info: &AccountInfo,
    active_index: u32,
    source_tree_info: Option<&AccountInfo>,
    header: JoinSplitHeader,
    prefix: &JoinSplitPrefix<'_>,
) -> Result<u32, ProgramError> {
    // Index of the tree the spent notes actually live in. Returned so the caller
    // can scope their nullifier PDAs to it: leaf indices restart at 0 in every
    // new tree and a nullifier is Poseidon(nullifyingKey, leafIndex), so the same
    // key holding leaf N in two trees derives one nullifier for two distinct
    // notes. Unscoped, spending either would permanently strand the other.
    let source_tree_index;
    {
        // The note may live in the active tree OR — after a tree rotation — in a frozen previous
        // tree. Validate the proof's merkle_root against the active tree first; if it does not
        // match, accept a caller-supplied frozen source tree whose (current or historical) root
        // matches. New output commitments are still inserted into the active tree by the caller.
        let active_root_ok = {
            let tree_data = commitment_tree_info.try_borrow()?;
            let tree = CommitmentTree::from_bytes(&tree_data)?;
            tree.is_valid_root(prefix.merkle_root)
        };
        if active_root_ok {
            source_tree_index = active_index;
        } else {
            let frozen_ok = match source_tree_info {
                Some(src) => {
                    validate_frozen_tree(
                        src,
                        pool_state_info,
                        program_id,
                        active_index,
                        prefix.merkle_root,
                    )?
                }
                None => false,
            };
            if !frozen_ok {
                return Err(UTXOpiaError::InvalidMerkleProof.into());
            }
            // Safe to read: validate_frozen_tree proved this is a commitment tree
            // PDA of this pool whose root the proof was built against.
            let src = source_tree_info.ok_or(UTXOpiaError::InvalidMerkleProof)?;
            let tree_data = src.try_borrow()?;
            source_tree_index = CommitmentTree::from_bytes(&tree_data)?.tree_index();
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

    // Pin the VK registry to its canonical PDA ["vk_registry", n_inputs, n_outputs]. Owner +
    // discriminator + (n_inputs, n_outputs) checks alone would accept any program-owned account
    // with matching size fields; re-deriving the address proves it is the admin-registered,
    // freezable VK for this circuit size and not a substituted account with forged delta_g2/ic.
    let (expected_vk, _) = find_program_address(
        &[
            VkRegistry::SEED,
            &[header.n_inputs as u8],
            &[header.n_outputs as u8],
        ],
        program_id,
    );
    if vk_registry_info.address() != &expected_vk {
        return Err(UTXOpiaError::InvalidVkRegistry.into());
    }

    let vk_data = vk_registry_info.try_borrow()?;
    let vk = VkRegistry::from_bytes(&vk_data)?;
    if vk.n_inputs != header.n_inputs as u8 || vk.n_outputs != header.n_outputs as u8 {
        return Err(UTXOpiaError::InvalidVkRegistry.into());
    }
    let ic = vk.get_ic()?;

    crate::utils::groth16::verify_groth16_joinsplit_proof(
        prefix.proof_bytes,
        &public_inputs[..pi_len],
        vk.get_delta_g2(),
        ic,
    )?;

    Ok(source_tree_index)
}

#[allow(clippy::too_many_arguments)]
pub fn create_nullifier_records(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    start_index: usize,
    nullifiers: &[&[u8; 32]],
    pool_state_info: &AccountInfo,
    source_tree_index: u32,
    payer: &AccountInfo,
    rent: &Rent,
    operation_type: u8,
    instruction_disc: u8,
) -> ProgramResult {
    let pool_state = pool_state_info.address();
    // Tree 0 keeps the original seeds. Every nullifier ever recorded lives under
    // them, and re-deriving would leave those PDAs unreachable — making every
    // already-spent note spendable again. Trees created by a rotation get their
    // own namespace instead, which is what stops leaf-index reuse across trees
    // from stranding notes. Nothing needs migrating and no extra account is
    // passed; see the module docs on `verify_vk_merkle_and_proof`.
    let tree_index_bytes = source_tree_index.to_le_bytes();
    let mut null_hashes: [&[u8; 32]; MAX_JOINSPLIT_SIZE] = [ZERO_REF; MAX_JOINSPLIT_SIZE];

    for (i, nullifier) in nullifiers.iter().enumerate() {
        let nullifier_info = &accounts[start_index + i];
        validate_account_writable(nullifier_info)?;

        // Pool-scoped: a nullifier is a function of the spender's key and the
        // note's leaf index, not of the pool, so the same seed spending into two
        // pools produces the same nullifier. Without the pool in the seeds those
        // share one global PDA, and spending in one pool permanently bricks the
        // twin note in the other with NullifierAlreadyUsed. Tree index is in the
        // seeds for the same reason, one level down: leaf indices restart at 0
        // after a rotation, so the same key derives one nullifier for a note in
        // each tree.
        let nullifier_seeds: &[&[u8]] = if source_tree_index == 0 {
            &[NullifierRecord::SEED, pool_state.as_ref(), nullifier.as_ref()]
        } else {
            &[
                NullifierRecord::SEED,
                pool_state.as_ref(),
                &tree_index_bytes,
                nullifier.as_ref(),
            ]
        };
        let (expected_pda, bump) = find_program_address(nullifier_seeds, program_id);
        if nullifier_info.address() != &expected_pda {
            return Err(ProgramError::InvalidSeeds);
        }

        {
            let nullifier_data = nullifier_info.try_borrow()?;
            if !nullifier_data.is_empty() && nullifier_data[0] == NULLIFIER_RECORD_DISCRIMINATOR {
                return Err(UTXOpiaError::NullifierAlreadyUsed.into());
            }
        }

        let bump_bytes = [bump];
        let signer_seeds: &[&[u8]] = if source_tree_index == 0 {
            &[
                NullifierRecord::SEED,
                pool_state.as_ref(),
                nullifier.as_ref(),
                &bump_bytes,
            ]
        } else {
            &[
                NullifierRecord::SEED,
                pool_state.as_ref(),
                &tree_index_bytes,
                nullifier.as_ref(),
                &bump_bytes,
            ]
        };
        create_pda_account(
            payer,
            nullifier_info,
            program_id,
            rent.try_minimum_balance(NullifierRecord::LEN)?,
            NullifierRecord::LEN as u64,
            signer_seeds,
        )?;

        {
            let mut nullifier_data = nullifier_info.try_borrow_mut()?;
            NullifierRecord::init(&mut nullifier_data)?;
        }

        null_hashes[i] = *nullifier;
    }

    crate::utils::events::emit_nullifiers_batch(
        &null_hashes[..nullifiers.len()],
        operation_type,
        instruction_disc,
    );

    // Bump the pool's nullifier total here rather than in each spend instruction:
    // this is the one place every spend path creates nullifier records, so a new
    // path cannot forget it. Every caller's pool_state borrows are block-scoped
    // and released before this point.
    {
        let mut pool_data = pool_state_info.try_borrow_mut()?;
        PoolState::from_bytes_mut(&mut pool_data)?.add_nullifiers(nullifiers.len() as u32);
    }
    Ok(())
}

#[cfg(test)]
#[path = "joinsplit_common_tests.rs"]
mod tests;

/// Where each optional account sits, resolved from the declared flags alone.
///
/// Pure arithmetic, extracted so it can be tested without standing up a proof.
/// The slots it returns are still validated by the caller — owner, signer, seeds
/// — exactly as before; this only decides *which index* to look at.
#[derive(Debug, PartialEq, Eq)]
pub struct JoinSplitTail {
    pub relayer: Option<usize>,
    pub source_tree: Option<usize>,
    pub approval: Option<usize>,
    pub policy_program: Option<usize>,
    pub proof_buffer: Option<usize>,
}

/// Resolve the optional tail that follows the nullifiers.
///
/// Order is fixed: relayer, frozen source tree, (approval, policy_program),
/// proof buffer. `permissioned` comes from pool state rather than the flag byte
/// because the pool is authoritative; the caller's POLICY flag must agree with
/// it, which keeps the layout readable from flags while the authority stays
/// on-chain.
///
/// Rejects a list that is short **or** long. The subtraction-based version this
/// replaces silently absorbed a stuffed extra account into whichever count it
/// happened to land in.
pub fn resolve_joinsplit_tail(
    flags: u8,
    n_inputs: usize,
    permissioned: bool,
    account_count: usize,
) -> Result<JoinSplitTail, ProgramError> {
    if (flags & jsflags::POLICY != 0) != permissioned {
        return Err(ProgramError::InvalidInstructionData);
    }

    let mut cursor = 5 + n_inputs;
    let mut take = |present: bool| -> Result<Option<usize>, ProgramError> {
        if !present {
            return Ok(None);
        }
        if cursor >= account_count {
            return Err(ProgramError::NotEnoughAccountKeys);
        }
        let at = cursor;
        cursor += 1;
        Ok(Some(at))
    };

    let tail = JoinSplitTail {
        relayer: take(flags & jsflags::RELAYER != 0)?,
        source_tree: take(flags & jsflags::FROZEN_SOURCE_TREE != 0)?,
        approval: take(permissioned)?,
        policy_program: take(permissioned)?,
        proof_buffer: take(flags & jsflags::PROOF_IN_BUFFER != 0)?,
    };

    if cursor != account_count {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    Ok(tail)
}

#[cfg(test)]
mod tail_tests {
    use super::*;

    fn t(flags: u8, n_inputs: usize, permissioned: bool, n: usize) -> JoinSplitTail {
        resolve_joinsplit_tail(flags, n_inputs, permissioned, n).expect("resolves")
    }

    #[test]
    fn bare_spend_has_no_tail() {
        let got = t(0, 2, false, 7);
        assert_eq!(got.relayer, None);
        assert_eq!(got.source_tree, None);
        assert_eq!(got.approval, None);
        assert_eq!(got.proof_buffer, None);
    }

    #[test]
    fn slots_follow_the_declared_order() {
        // relayer + frozen tree + policy pair + proof buffer, n_inputs = 2.
        let flags = jsflags::RELAYER
            | jsflags::FROZEN_SOURCE_TREE
            | jsflags::POLICY
            | jsflags::PROOF_IN_BUFFER;
        let got = t(flags, 2, true, 12);
        assert_eq!(got.relayer, Some(7));
        assert_eq!(got.source_tree, Some(8));
        assert_eq!(got.approval, Some(9));
        assert_eq!(got.policy_program, Some(10));
        assert_eq!(got.proof_buffer, Some(11));
    }

    #[test]
    fn one_optional_account_does_not_move_the_others() {
        // The whole point: dropping the relayer shifts only the relayer.
        let with = t(jsflags::RELAYER | jsflags::PROOF_IN_BUFFER, 1, false, 8);
        let without = t(jsflags::PROOF_IN_BUFFER, 1, false, 7);
        assert_eq!(with.relayer, Some(6));
        assert_eq!(with.proof_buffer, Some(7));
        assert_eq!(without.relayer, None);
        assert_eq!(without.proof_buffer, Some(6));
    }

    #[test]
    fn a_stuffed_extra_account_is_rejected() {
        // The subtraction this replaced absorbed it silently.
        assert!(resolve_joinsplit_tail(0, 2, false, 8).is_err());
        assert!(resolve_joinsplit_tail(jsflags::RELAYER, 2, false, 9).is_err());
    }

    #[test]
    fn a_short_list_is_rejected() {
        assert!(resolve_joinsplit_tail(jsflags::RELAYER, 2, false, 7).is_err());
        assert!(resolve_joinsplit_tail(jsflags::POLICY, 2, true, 8).is_err());
    }

    #[test]
    fn the_policy_flag_must_agree_with_pool_state() {
        // Caller claims a policy pair on a public pool, or omits it on a
        // permissioned one: both are refused rather than silently reinterpreted.
        assert!(resolve_joinsplit_tail(jsflags::POLICY, 2, false, 9).is_err());
        assert!(resolve_joinsplit_tail(0, 2, true, 9).is_err());
    }
}
