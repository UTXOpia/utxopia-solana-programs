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

/// Build a JoinSplit(1,1) instruction body (proof_source=0, 1 tree output) with the
/// given nullifier bytes. Layout: header(4) + proof(256) + root(32) + bound(32) +
/// nullifier(32) + commitment(32) + stealth(72).
fn joinsplit_1x1_with_nullifier(nullifier: [u8; 32]) -> Vec<u8> {
    let mut d = vec![1u8, 1, 1, 0]; // n_in=1, n_out=1, n_pub=1, proof_source=0
    d.extend_from_slice(&[0u8; GROTH16_PROOF_SIZE]); // proof
    d.extend_from_slice(&[0u8; 32]); // merkle_root
    d.extend_from_slice(&[0u8; 32]); // bound_params_hash
    d.extend_from_slice(&nullifier); // nullifier
    d.extend_from_slice(&[0u8; 32]); // commitment_out
    d.extend_from_slice(&[0u8; STEALTH_DATA_PER_OUTPUT]); // stealth for 1 tree output
    d
}

#[test]
fn parse_prefix_accepts_canonical_nullifier() {
    let data = joinsplit_1x1_with_nullifier([0u8; 32]);
    let header = parse_header(&data).unwrap();
    let mut proof_buf = [0u8; GROTH16_PROOF_SIZE];
    // proof_source==0 path never indexes accounts, so an empty slice is fine.
    let res = parse_prefix(&data, &[], header, 1, &mut proof_buf);
    assert!(res.is_ok(), "canonical nullifier should parse");
}

#[test]
fn parse_prefix_rejects_noncanonical_nullifier() {
    // 0xff..ff >= BN254 Fr modulus: a non-canonical alias that the alt_bn128 syscall
    // would reduce to the same field element while seeding a *different* nullifier PDA.
    // This is the double-spend vector — parsing must reject it outright.
    let data = joinsplit_1x1_with_nullifier([0xffu8; 32]);
    let header = parse_header(&data).unwrap();
    let mut proof_buf = [0u8; GROTH16_PROOF_SIZE];
    let res = parse_prefix(&data, &[], header, 1, &mut proof_buf);
    assert!(res.is_err(), "non-canonical nullifier must be rejected");
}

/// The precise attack value, not just a saturated one. `0xff..ff` above is comfortably above
/// the modulus; `n + r` sits just above it and is what an attacker would actually submit —
/// same field element, same proof, different PDA seed. It also stays under 2^256, which is what
/// makes the replay expressible in 32 bytes at all.
#[test]
fn parse_prefix_rejects_the_nullifier_plus_r_alias() {
    let r = crate::utils::crypto::BN254_FR_MODULUS;
    // A plausible Poseidon output, comfortably below r.
    let n = [
        0x0a, 0x1b, 0x2c, 0x3d, 0x4e, 0x5f, 0x60, 0x71, 0x82, 0x93, 0xa4, 0xb5, 0xc6, 0xd7, 0xe8,
        0xf9, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde,
        0xef, 0x00,
    ];

    // n + r, big-endian.
    let mut alias = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let sum = n[i] as u16 + r[i] as u16 + carry;
        alias[i] = sum as u8;
        carry = sum >> 8;
    }
    assert_eq!(carry, 0, "n + r must still fit in 32 bytes");
    assert_ne!(n, alias);

    let header = parse_header(&joinsplit_1x1_with_nullifier(n)).unwrap();
    let mut proof_buf = [0u8; GROTH16_PROOF_SIZE];

    let canonical = joinsplit_1x1_with_nullifier(n);
    assert!(
        parse_prefix(&canonical, &[], header, 1, &mut proof_buf).is_ok(),
        "the canonical nullifier must still parse"
    );

    let replayed = joinsplit_1x1_with_nullifier(alias);
    assert!(
        parse_prefix(&replayed, &[], header, 1, &mut proof_buf).is_err(),
        "n + r must be rejected: it proves the same statement but seeds a different PDA"
    );
}

/// The nullifier PDA must include pool_state, so the same nullifier in two pools
/// lands on two different accounts. Before this, one global PDA meant spending a
/// note in one pool bricked the same-seed twin note in the other.
#[test]
fn nullifier_pda_is_pool_scoped() {
    use crate::pinocchio_compat::{find_program_address, Pubkey};
    use crate::state::NullifierRecord;

    let program = Pubkey::from([7u8; 32]);
    let nullifier = [3u8; 32];
    let pool_a = [1u8; 32];
    let pool_b = [2u8; 32];

    let (addr_a, _) =
        find_program_address(&[NullifierRecord::SEED, &pool_a, &nullifier], &program);
    let (addr_b, _) =
        find_program_address(&[NullifierRecord::SEED, &pool_b, &nullifier], &program);

    // Same nullifier, different pool -> different PDA, so spending in A cannot
    // claim B's account and B's twin note stays spendable.
    assert_ne!(addr_a, addr_b, "pool must scope the nullifier PDA");

    // Stable within a pool, so dedup still works.
    let (again, _) =
        find_program_address(&[NullifierRecord::SEED, &pool_a, &nullifier], &program);
    assert_eq!(addr_a, again);
}

/// The rotation hazard this scoping exists for, stated as an address test.
///
/// A nullifier is Poseidon(nullifyingKey, leafIndex) and leaf indices restart at
/// 0 in every new tree, so one key holding leaf N in two trees produces a single
/// nullifier value for two distinct notes. If both mapped to one PDA, spending
/// either would strand the other for good.
mod nullifier_pda_is_scoped_per_tree {
    use crate::pinocchio_compat::{find_program_address, Pubkey};
    use crate::state::NullifierRecord;

    const PROGRAM_BYTES: [u8; 32] = [7u8; 32];
    const POOL: [u8; 32] = [9u8; 32];
    const NULLIFIER: [u8; 32] = [42u8; 32];

    fn pda_for(tree_index: u32) -> Pubkey {
        let idx = tree_index.to_le_bytes();
        let seeds: &[&[u8]] = if tree_index == 0 {
            &[NullifierRecord::SEED, &POOL, &NULLIFIER]
        } else {
            &[NullifierRecord::SEED, &POOL, &idx, &NULLIFIER]
        };
        find_program_address(seeds, &Pubkey::from(PROGRAM_BYTES)).0
    }

    /// Tree 0 must keep deriving exactly what it always did — every nullifier on
    /// chain today lives under those seeds, and moving them would make each
    /// already-spent note spendable again.
    #[test]
    fn tree_zero_keeps_the_legacy_address() {
        let legacy = find_program_address(
            &[NullifierRecord::SEED, &POOL, &NULLIFIER],
            &Pubkey::from(PROGRAM_BYTES),
        )
        .0;
        assert_eq!(pda_for(0), legacy);
    }

    #[test]
    fn the_same_nullifier_in_different_trees_gets_different_addresses() {
        let t0 = pda_for(0);
        let t1 = pda_for(1);
        let t2 = pda_for(2);
        assert_ne!(t0, t1, "tree 1 must not collide with tree 0");
        assert_ne!(t1, t2, "each rotation needs its own namespace");
        assert_ne!(t0, t2);
    }
}
