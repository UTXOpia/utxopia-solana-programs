use super::*;

fn ix_bytes(deposit_vout: u32, deposit_tx_size: u32) -> Vec<u8> {
    let mut d = Vec::with_capacity(VerifyDepositData::SIZE);
    d.extend_from_slice(&[0xAA; 32]); // sweep_txid
    d.extend_from_slice(&900u64.to_le_bytes()); // block_height
    d.extend_from_slice(&300u32.to_le_bytes()); // sweep_tx_size
    d.extend_from_slice(&deposit_tx_size.to_le_bytes());
    d.extend_from_slice(&[0xBB; 32]); // deposit_txid
    d.extend_from_slice(&[0x11; 32]); // ephemeral_pubkey
    d.extend_from_slice(&[0x22; 32]); // note_public_key
    d.extend_from_slice(&deposit_vout.to_le_bytes());
    d
}

#[test]
fn parses_every_field_at_its_documented_offset() {
    let parsed = VerifyDepositData::from_bytes(&ix_bytes(3, 250)).unwrap();

    assert_eq!(parsed.base.sweep_txid, [0xAA; 32]);
    assert_eq!(parsed.base.block_height, 900);
    assert_eq!(parsed.base.deposit_tx_size, 250);
    assert_eq!(parsed.base.deposit_txid, [0xBB; 32]);
    assert_eq!(parsed.ephemeral_pubkey, [0x11; 32]);
    assert_eq!(parsed.note_public_key, [0x22; 32]);
    assert_eq!(parsed.deposit_vout, 3);
}

/// disc 25 credits the deposit output directly, so the SPV-verified transaction
/// must BE the deposit. A caller passing a separate deposit tx is describing the
/// old two-step sweep, which this instruction no longer implements — and silently
/// accepting it would credit a pool_script output the leaf never proved.
#[test]
fn requires_the_proven_transaction_to_be_the_deposit() {
    // The no-sweep shape: no second tx, and deposit_txid names the proven one.
    let ok = VerifyDepositData::from_bytes(&ix_bytes(0, 0)).unwrap();
    assert_eq!(ok.base.deposit_tx_size, 0);
    assert_eq!(ok.base.deposit_txid, [0xBB; 32]);

    // Parsing stays permissive — the shape is enforced at the entry point, which
    // needs accounts. What matters here is that the two fields survive intact so
    // that check has something to test.
    let two_step = VerifyDepositData::from_bytes(&ix_bytes(0, 250)).unwrap();
    assert_eq!(two_step.base.deposit_tx_size, 250);
    assert_ne!(two_step.base.deposit_txid, two_step.base.sweep_txid);
}

#[test]
fn rejects_truncated_instruction_data() {
    let short = ix_bytes(0, 250)[..VerifyDepositData::SIZE - 1].to_vec();
    assert!(VerifyDepositData::from_bytes(&short).is_err());
}

/// sha256(npk || eph) for the fixtures below. Pinned in the SDK's
/// verify-deposit test too — if the two implementations drift, every deposit
/// address the client derives stops verifying on chain.
const PINNED_COMMITMENT: [u8; 32] = [
    0xad, 0xfa, 0xfc, 0x05, 0xaa, 0xc7, 0x33, 0xfe, 0x95, 0x09, 0xf4, 0x3b, 0xd1, 0xd1, 0x58, 0xc8,
    0x82, 0x89, 0x03, 0x51, 0xc7, 0xf3, 0x43, 0x63, 0x4c, 0x8e, 0xf9, 0xea, 0x42, 0xcd, 0xb5, 0x05,
];

#[test]
fn tweak_commitment_matches_the_sdk_byte_for_byte() {
    assert_eq!(tweak_commitment(&[0x22; 32], &[0x11; 32]), PINNED_COMMITMENT);
}

#[test]
fn tweak_commitment_binds_both_keys() {
    let npk = [0x22; 32];
    let eph = [0x11; 32];

    // Not the bare note key: a disc-25 address must never land on the address a
    // disc-11 deposit for the same note key would derive.
    assert_ne!(tweak_commitment(&npk, &eph), npk);

    // Order matters, so swapping the two keys does not verify against the address.
    assert_ne!(tweak_commitment(&npk, &eph), tweak_commitment(&eph, &npk));

    // A different ephemeral key gives a different address, which is what stops a
    // caller from substituting one and stranding the note undiscoverable.
    let mut other_eph = eph;
    other_eph[0] ^= 1;
    assert_ne!(tweak_commitment(&npk, &eph), tweak_commitment(&npk, &other_eph));

    assert_eq!(tweak_commitment(&npk, &eph), tweak_commitment(&npk, &eph));
}

/// The leaf hash for the fixtures below, computed independently.
const PINNED_LEAF_HASH: [u8; 32] = [
    0x06, 0xb2, 0x4c, 0x2f, 0xa6, 0x53, 0x21, 0x15, 0x57, 0xf4, 0xc8, 0x10, 0x6c, 0x52, 0xac, 0x04,
    0x48, 0x06, 0x06, 0xe0, 0x68, 0x50, 0xfd, 0x96, 0x7e, 0x87, 0xa9, 0x95, 0x75, 0x0a, 0x29, 0x33,
];

#[test]
fn leaf_script_is_the_shape_bitcoin_will_execute() {
    let commitment = tweak_commitment(&[0x22; 32], &[0x11; 32]);
    let ika = [0x33; 32];
    let script = deposit_leaf_script(&commitment, &ika);

    // <32-byte push> <commitment> OP_DROP <32-byte push> <ika_xonly> OP_CHECKSIG
    assert_eq!(script[0], 0x20);
    assert_eq!(&script[1..33], &commitment);
    assert_eq!(script[33], 0x75, "OP_DROP");
    assert_eq!(script[34], 0x20);
    assert_eq!(&script[35..67], &ika);
    assert_eq!(script[67], 0xac, "OP_CHECKSIG");
}

#[test]
fn leaf_hash_matches_bip341_tagged_hashing() {
    // Cross-checked against an independent implementation of
    // tagged_hash("TapLeaf", 0xc0 || compact_size(68) || script).
    assert_eq!(
        deposit_leaf_hash(&tweak_commitment(&[0x22; 32], &[0x11; 32]), &[0x33; 32]),
        PINNED_LEAF_HASH
    );
}

#[test]
fn the_leaf_binds_the_note_keys_and_the_custody_key() {
    // Every input to the address must move it. Otherwise a caller could swap one
    // and still point at a funding transaction it did not pay for.
    let commitment = tweak_commitment(&[0x22; 32], &[0x11; 32]);
    let base = deposit_leaf_hash(&commitment, &[0x33; 32]);

    assert_ne!(
        base,
        deposit_leaf_hash(&tweak_commitment(&[0x22; 32], &[0x12; 32]), &[0x33; 32]),
        "a different ephemeral key must derive a different address"
    );
    assert_ne!(
        base,
        deposit_leaf_hash(&tweak_commitment(&[0x23; 32], &[0x11; 32]), &[0x33; 32]),
        "a different note key must derive a different address"
    );
    assert_ne!(
        base,
        deposit_leaf_hash(&commitment, &[0x34; 32]),
        "another pool's custody key must derive a different address"
    );
}

#[test]
fn the_internal_key_is_unspendable_and_is_not_the_custody_key() {
    // The key path must be dead: Ika's MPC cannot sign for a tweaked key, so if
    // the internal key were the dWallet key plus a per-deposit tweak, the very
    // custodian meant to sweep the deposit could not spend it.
    assert_eq!(
        DEPOSIT_NUMS_INTERNAL_KEY,
        [
            0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9,
            0x7a, 0x5e, 0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a,
            0xce, 0x80, 0x3a, 0xc0,
        ],
        "BIP-341 NUMS point"
    );
}

/// The x-only output key of the address the fixtures derive, computed by the
/// SDK's `deriveTaprootAddress(leaf_hash, NUMS)` — i.e. the address a depositor
/// would actually be handed. In bech32m:
/// `bcrt1pl44ykzegsumc3vgmghv0m7qerrvzcwds2qmfqerhj85jy9dl3dvs084mpx`
const PINNED_OUTPUT_KEY: [u8; 32] = [
    0xfd, 0x6a, 0x4b, 0x0b, 0x28, 0x87, 0x37, 0x88, 0xb1, 0x1b, 0x45, 0xd8, 0xfd, 0xf8, 0x19, 0x18,
    0xd8, 0x2c, 0x39, 0xb0, 0x50, 0x36, 0x90, 0x64, 0x77, 0x91, 0xe9, 0x22, 0x15, 0xbf, 0x8b, 0x59,
];

/// The whole scheme, end to end: an address a client really derives is one this
/// program really accepts.
///
/// The hash-shape tests above would all still pass if the elliptic-curve half
/// disagreed with the SDK, and the failure would only show up as deposits that
/// silently never verify.
#[test]
fn accepts_an_address_the_sdk_derived() {
    let leaf_hash = deposit_leaf_hash(&tweak_commitment(&[0x22; 32], &[0x11; 32]), &[0x33; 32]);

    verify_taproot_output_key(&DEPOSIT_NUMS_INTERNAL_KEY, &leaf_hash, &PINNED_OUTPUT_KEY)
        .expect("the SDK-derived output key must verify against its own leaf");
}

#[test]
fn rejects_a_substituted_ephemeral_key() {
    // The attack this binding exists to stop: same note key, attacker's ephemeral
    // key. The commitment would still be right and the funds still the user's,
    // but the announcement becomes undecryptable and the note is lost to them.
    let forged = deposit_leaf_hash(&tweak_commitment(&[0x22; 32], &[0x12; 32]), &[0x33; 32]);

    assert!(
        verify_taproot_output_key(&DEPOSIT_NUMS_INTERNAL_KEY, &forged, &PINNED_OUTPUT_KEY).is_err(),
        "a leaf the funding transaction never paid must not verify"
    );
}

#[test]
fn rejects_another_pools_custody_key() {
    let other_pool = deposit_leaf_hash(&tweak_commitment(&[0x22; 32], &[0x11; 32]), &[0x34; 32]);

    assert!(
        verify_taproot_output_key(&DEPOSIT_NUMS_INTERNAL_KEY, &other_pool, &PINNED_OUTPUT_KEY)
            .is_err(),
        "the leaf names the custody key, so another pool's address must not verify"
    );
}

#[test]
fn each_output_of_one_funding_tx_gets_its_own_receipt() {
    // An exchange batch withdrawal pays several depositors in one transaction.
    // Keyed on the txid alone, the first completion would block all the others.
    let program_id = crate::ID;
    let txid = [0xBB; 32];

    let receipt = |vout: Option<u32>| {
        let vout_le = vout.map(|v| v.to_le_bytes());
        match &vout_le {
            Some(v) => {
                find_program_address(&[DepositReceipt::SEED, &txid[..], &v[..]], &program_id).0
            }
            None => find_program_address(&[DepositReceipt::SEED, &txid[..]], &program_id).0,
        }
    };

    assert_ne!(receipt(Some(0)), receipt(Some(1)));
    // And neither collides with the OP_RETURN flow's txid-only receipt.
    assert_ne!(receipt(Some(0)), receipt(None));
}

#[test]
fn binding_reports_its_scope() {
    assert_eq!(DepositBinding::OpReturn.deposit_vout(), None);
    assert_eq!(
        DepositBinding::Tweak {
            ephemeral_pubkey: [0x11; 32],
            note_public_key: [0x22; 32],
            deposit_vout: 7,
        }
        .deposit_vout(),
        Some(7)
    );
}

/// disc 26 carries a variable-length auditor ciphertext after the fixed header,
/// exactly as disc 22 does. Its offset must be the header size — reading it from
/// the wrong place hands the auditor someone else's bytes, and the policy
/// approval is bound to the WHOLE payload, so a shifted split silently fails to
/// match instead of failing loudly.
#[test]
fn the_permissioned_payload_splits_at_the_header() {
    let mut data = ix_bytes(3, 0);
    let ciphertext = [0xC1u8; 40];
    data.extend_from_slice(&ciphertext);

    let parsed = VerifyDepositData::from_bytes(&data).unwrap();
    assert_eq!(parsed.deposit_vout, 3);
    assert_eq!(parsed.ephemeral_pubkey, [0x11; 32]);
    assert_eq!(parsed.note_public_key, [0x22; 32]);

    assert_eq!(&data[VerifyDepositData::SIZE..], &ciphertext);
    // And an empty ciphertext is a valid payload, not a truncated one.
    assert_eq!(&ix_bytes(3, 0)[VerifyDepositData::SIZE..], &[] as &[u8]);
}

/// The two entry points must stay distinguishable to the policy approval, which
/// binds an approval to one discriminator. Sharing a value would let an approval
/// issued for a public deposit be spent on a permissioned one.
#[test]
fn the_two_deposit_discriminators_are_distinct() {
    assert_eq!(crate::instruction::VERIFY_DEPOSIT, 25);
    assert_eq!(crate::instruction::VERIFY_DEPOSIT_PERMISSIONED, 26);
    assert_ne!(
        crate::instruction::VERIFY_DEPOSIT,
        crate::instruction::VERIFY_DEPOSIT_PERMISSIONED
    );
    // And neither may collide with the OP_RETURN pair they replace.
    for other in [
        crate::instruction::COMPLETE_DEPOSIT,
        crate::instruction::COMPLETE_DEPOSIT_PERMISSIONED,
    ] {
        assert_ne!(crate::instruction::VERIFY_DEPOSIT, other);
        assert_ne!(crate::instruction::VERIFY_DEPOSIT_PERMISSIONED, other);
    }
}

