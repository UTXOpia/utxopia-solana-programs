use super::{CommitmentTree, TREE_DEPTH, ZERO_HASHES};

#[test]
fn rejects_zero_root_but_accepts_empty_tree_root() {
    let mut data = vec![0u8; CommitmentTree::LEN];
    let tree = CommitmentTree::init(&mut data).expect("tree init");

    assert!(!tree.is_valid_root(&[0u8; 32]));
    assert!(tree.is_valid_root(&ZERO_HASHES[TREE_DEPTH]));
}

/// The whole point of `insert_leaves_batch`: same tree, fewer history slots.
///
/// Guards the equivalence claim in its doc comment — if the batch path ever
/// diverges from the per-leaf path, every client-side Merkle proof breaks.
#[test]
fn batch_insert_matches_sequential_inserts() {
    let owned: [[u8; 32]; 9] = core::array::from_fn(|i| [i as u8 + 1; 32]);
    let commitments: [&[u8; 32]; 9] = core::array::from_fn(|i| &owned[i]);

    let mut seq_data = vec![0u8; CommitmentTree::LEN];
    let seq = CommitmentTree::init(&mut seq_data).expect("tree init");
    let seq_history_before = seq.root_history_index();
    for commitment in &owned {
        seq.insert_leaf(commitment).expect("sequential insert");
    }

    let mut batch_data = vec![0u8; CommitmentTree::LEN];
    let batch = CommitmentTree::init(&mut batch_data).expect("tree init");
    let batch_history_before = batch.root_history_index();
    let first = batch
        .insert_leaves_batch(&commitments)
        .expect("batch insert");

    assert_eq!(first, 0);
    assert_eq!(batch.current_root, seq.current_root, "roots diverged");
    assert_eq!(batch.next_index(), seq.next_index());
    assert_eq!(batch.frontier, seq.frontier, "frontier diverged");

    // Nine leaves cost nine history slots sequentially, one as a batch.
    assert_eq!(seq.root_history_index() - seq_history_before, 9);
    assert_eq!(batch.root_history_index() - batch_history_before, 1);

    // The pre-batch root is what lands in history, so proofs against it survive.
    assert!(batch.is_valid_root(&ZERO_HASHES[TREE_DEPTH]));
}

#[test]
fn batch_insert_rejects_an_empty_batch() {
    let mut data = vec![0u8; CommitmentTree::LEN];
    let tree = CommitmentTree::init(&mut data).expect("tree init");
    let before = tree.root_history_index();

    assert!(tree.insert_leaves_batch(&[]).is_err());
    assert_eq!(tree.root_history_index(), before, "empty batch moved history");
}
