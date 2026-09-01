//! A commitment that is fully paid for but not yet placed in the tree.
//!
//! Deliberately **not** called a mempool. Nothing here is unconfirmed,
//! replaceable or droppable: by the time one of these exists the proof has
//! verified and the input notes' nullifiers are already written. Only the leaf's
//! *position* is outstanding. Dropping a `QueuedLeaf` destroys the output note
//! while leaving its inputs spent — burning user funds — so the program has no
//! instruction that closes one except `merge_queued_leaves`, which closes it in
//! the same instruction that inserts it.
//!
//! Contrast `NullifierRecord`, which is permanent: closing one would let a note
//! be spent twice. The suffix carries that difference on purpose — `Record` is
//! forever, `Queued` is in transit.
//!
//! The stealth payload rides along because the announcement that carries a
//! leaf index can only be emitted once the index exists, i.e. at merge time.
//!
//! `nullifier_debt` is how `pool_state.nullifier_count` survives being taken off
//! the hot path. That counter is not decoration: the backend reconciler compares
//! it against the local set, and by its own comment it is the *only* thing that
//! catches missing nullifier rows — leaves and root can both agree while spent
//! notes still look spendable. So instead of dropping it, the spend records how
//! many nullifiers it wrote and `merge_queued_leaves` applies the sum. The
//! counter stays exact; only its timing moves, and it moves in the safe
//! direction (on-chain lags, so the reconciler's `local >= on_chain` floor
//! cannot false-positive — detection is delayed, never lost).
//!
//! Exactly one leaf per spend carries the debt; its siblings carry 0. Splitting
//! it any other way double-counts.

//! ## Known divergence from inline placement
//!
//! The PDA is seeded on the commitment, so a commitment can be queued only
//! once. Inline placement has no such limit: two *different* deposits that
//! collide on a commitment — same recipient, token and value, and the sender
//! reused the blinding factor — are two real notes, and both belong in the tree
//! at their own leaves. Queued, the second is refused at account creation.
//!
//! Left as is, but the reason is narrower than it first looks.
//!
//! Colliding commitments are NOT merely a 2^-256 curiosity in this protocol.
//! `complete_deposit` computes `Poseidon(note_public_key, token_id,
//! shielded_amount)`, and the BTC deposit address is derived from that same note
//! key — so paying the same deposit address twice for the same amount produces
//! byte-identical commitments every time. That is address reuse, not a hash
//! collision. It is handled: both land at their own leaves, announcements and
//! merkle proofs are keyed on leaf_index throughout, and each note spends once.
//!
//! Only `transact` queues. Its output commitments carry a sender-chosen `npk`
//! derived with a fresh blinding factor, so for THIS path a collision really is
//! ~2^-256, and when it happens the spend fails cleanly and retries — nothing is
//! lost. Deposits, which can collide routinely, place inline and are unaffected.
//!
//! Do not generalise the queued restriction to the deposit path. Seeding on a
//! caller-supplied nonce would lift it, at the cost of a value the SDK must
//! track and the program cannot check.
//!
//! Worth knowing because it makes the queued path strictly more restrictive
//! than the inline one — the same spend can succeed inline and fail queued.

use crate::pinocchio_compat::ProgramError;

pub const QUEUED_LEAF_DISCRIMINATOR: u8 = 0x16;
pub const QUEUED_LEAF_VERSION: u8 = 1;

/// Byte-stable layout with accessors, mirroring the other state accounts so
/// nothing depends on host alignment.
pub struct QueuedLeaf;

impl QueuedLeaf {
    pub const LEN: usize = 144;
    pub const SEED: &'static [u8] = b"queued_leaf";

    const DISCRIMINATOR: usize = 0;
    const VERSION: usize = 1;
    const BUMP: usize = 2;
    const TREE_INDEX: core::ops::Range<usize> = 3..7;
    const COMMITMENT: core::ops::Range<usize> = 7..39;
    /// Where the rent goes when the leaf merges. Recorded rather than refunded
    /// to whoever calls `merge_queued_leaves`, so a merger cannot harvest other
    /// people's rent by racing to merge.
    const PAYER: core::ops::Range<usize> = 39..71;
    const EPHEMERAL_PUB: core::ops::Range<usize> = 71..103;
    const ENCRYPTED_AMOUNT: core::ops::Range<usize> = 103..111;
    const ENCRYPTED_TOKEN_ID: core::ops::Range<usize> = 111..143;
    /// Nullifiers this spend wrote, carried by exactly one of its leaves so
    /// `merge_queued_leaves` can apply them once. 0 on the siblings.
    const NULLIFIER_DEBT: usize = 143;

    #[allow(clippy::too_many_arguments)]
    pub fn init(
        data: &mut [u8],
        bump: u8,
        tree_index: u32,
        commitment: &[u8; 32],
        payer: &[u8; 32],
        ephemeral_pub: &[u8; 32],
        encrypted_amount: &[u8; 8],
        encrypted_token_id: &[u8; 32],
        nullifier_debt: u8,
    ) -> Result<(), ProgramError> {
        if data.len() != Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data.fill(0);
        data[Self::DISCRIMINATOR] = QUEUED_LEAF_DISCRIMINATOR;
        data[Self::VERSION] = QUEUED_LEAF_VERSION;
        data[Self::BUMP] = bump;
        data[Self::TREE_INDEX].copy_from_slice(&tree_index.to_le_bytes());
        data[Self::COMMITMENT].copy_from_slice(commitment);
        data[Self::PAYER].copy_from_slice(payer);
        data[Self::EPHEMERAL_PUB].copy_from_slice(ephemeral_pub);
        data[Self::ENCRYPTED_AMOUNT].copy_from_slice(encrypted_amount);
        data[Self::ENCRYPTED_TOKEN_ID].copy_from_slice(encrypted_token_id);
        data[Self::NULLIFIER_DEBT] = nullifier_debt;
        Ok(())
    }

    pub fn validate(data: &[u8]) -> Result<(), ProgramError> {
        if data.len() != Self::LEN
            || data[Self::DISCRIMINATOR] != QUEUED_LEAF_DISCRIMINATOR
            || data[Self::VERSION] != QUEUED_LEAF_VERSION
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(())
    }

    pub fn tree_index(data: &[u8]) -> u32 {
        u32::from_le_bytes(data[Self::TREE_INDEX].try_into().unwrap())
    }

    pub fn commitment(data: &[u8]) -> &[u8; 32] {
        data[Self::COMMITMENT].try_into().unwrap()
    }

    pub fn payer(data: &[u8]) -> &[u8; 32] {
        data[Self::PAYER].try_into().unwrap()
    }

    pub fn ephemeral_pub(data: &[u8]) -> &[u8; 32] {
        data[Self::EPHEMERAL_PUB].try_into().unwrap()
    }

    pub fn encrypted_amount(data: &[u8]) -> &[u8; 8] {
        data[Self::ENCRYPTED_AMOUNT].try_into().unwrap()
    }

    pub fn encrypted_token_id(data: &[u8]) -> &[u8; 32] {
        data[Self::ENCRYPTED_TOKEN_ID].try_into().unwrap()
    }

    pub fn nullifier_debt(data: &[u8]) -> u8 {
        data[Self::NULLIFIER_DEBT]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Vec<u8> {
        let mut data = vec![0u8; QueuedLeaf::LEN];
        QueuedLeaf::init(
            &mut data,
            254,
            7,
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[4u8; 8],
            &[5u8; 32],
            3,
        )
        .expect("init");
        data
    }

    #[test]
    fn roundtrips_every_field() {
        let data = sample();
        QueuedLeaf::validate(&data).expect("validate");
        assert_eq!(QueuedLeaf::tree_index(&data), 7);
        assert_eq!(QueuedLeaf::commitment(&data), &[1u8; 32]);
        assert_eq!(QueuedLeaf::payer(&data), &[2u8; 32]);
        assert_eq!(QueuedLeaf::ephemeral_pub(&data), &[3u8; 32]);
        assert_eq!(QueuedLeaf::encrypted_amount(&data), &[4u8; 8]);
        assert_eq!(QueuedLeaf::encrypted_token_id(&data), &[5u8; 32]);
        assert_eq!(QueuedLeaf::nullifier_debt(&data), 3);
    }

    #[test]
    fn rejects_a_foreign_or_truncated_account() {
        let mut wrong_disc = sample();
        wrong_disc[0] = super::QUEUED_LEAF_DISCRIMINATOR + 1;
        assert!(QueuedLeaf::validate(&wrong_disc).is_err());

        let mut wrong_version = sample();
        wrong_version[1] = 2;
        assert!(QueuedLeaf::validate(&wrong_version).is_err());

        assert!(QueuedLeaf::validate(&sample()[..QueuedLeaf::LEN - 1]).is_err());
        assert!(
            QueuedLeaf::init(&mut [0u8; 8], 0, 0, &[0; 32], &[0; 32], &[0; 32], &[0; 8], &[0; 32], 0)
                .is_err()
        );
    }
}
