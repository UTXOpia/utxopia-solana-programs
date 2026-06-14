    use super::{CommitmentTree, TREE_DEPTH, ZERO_HASHES};

    #[test]
    fn rejects_zero_root_but_accepts_empty_tree_root() {
        let mut data = vec![0u8; CommitmentTree::LEN];
        let tree = CommitmentTree::init(&mut data).expect("tree init");

        assert!(!tree.is_valid_root(&[0u8; 32]));
        assert!(tree.is_valid_root(&ZERO_HASHES[TREE_DEPTH]));
    }
