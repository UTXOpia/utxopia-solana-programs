use super::*;

#[test]
fn test_utxo_record_size() {
    assert_eq!(UtxoRecord::LEN, 56);
}

#[test]
fn test_utxo_record_seed() {
    assert_eq!(UtxoRecord::SEED, b"utxo");
}

/// The seed prefix alone no longer addresses a record: callers must pass the
/// owning pool between the prefix and the outpoint. Two pools deriving with the
/// same outpoint must land on different addresses, which is what stops one
/// pool's redemption from reserving the other's bitcoin.
#[test]
fn the_pool_is_part_of_the_utxo_address() {
    use crate::pinocchio_compat::{find_program_address, Pubkey};
    let program = Pubkey::from([9u8; 32]);
    let txid = [4u8; 32];
    let vout = 1u32.to_le_bytes();
    let pool_a = [1u8; 32];
    let pool_b = [2u8; 32];

    let (addr_a, _) =
        find_program_address(&[UtxoRecord::SEED, &pool_a, &txid, &vout], &program);
    let (addr_b, _) =
        find_program_address(&[UtxoRecord::SEED, &pool_b, &txid, &vout], &program);

    assert_ne!(addr_a, addr_b);
}

#[test]
fn test_utxo_record_discriminator() {
    assert_eq!(UTXO_RECORD_DISCRIMINATOR, 0x09);
}

#[test]
fn test_utxo_record_init() {
    let mut buf = [0u8; 56];
    let utxo = UtxoRecord::init(&mut buf).unwrap();

    assert_eq!(utxo.discriminator, UTXO_RECORD_DISCRIMINATOR);
    assert_eq!(utxo.get_status(), UtxoStatus::Unspent);
    assert_eq!(utxo.vout(), 0);
    assert_eq!(utxo.amount_sats(), 0);
    assert_eq!(utxo.txid, [0u8; 32]);
}

#[test]
fn test_utxo_record_init_too_small() {
    let mut buf = [0u8; 55]; // 1 byte short
    assert!(UtxoRecord::init(&mut buf).is_err());
}

#[test]
fn test_utxo_record_setters_getters() {
    let mut buf = [0u8; 56];
    let utxo = UtxoRecord::init(&mut buf).unwrap();

    let txid = [0xABu8; 32];
    utxo.set_txid(&txid);
    assert_eq!(utxo.txid, txid);

    utxo.set_vout(2);
    assert_eq!(utxo.vout(), 2);

    utxo.set_amount_sats(100_000);
    assert_eq!(utxo.amount_sats(), 100_000);

    utxo.set_status(UtxoStatus::Reserved);
    assert_eq!(utxo.get_status(), UtxoStatus::Reserved);
}

#[test]
fn test_utxo_record_from_bytes() {
    let mut buf = [0u8; 56];
    {
        let utxo = UtxoRecord::init(&mut buf).unwrap();
        utxo.set_vout(3);
        utxo.set_amount_sats(50_000);
        utxo.set_txid(&[0xCCu8; 32]);
    }

    let utxo = UtxoRecord::from_bytes(&buf).unwrap();
    assert_eq!(utxo.vout(), 3);
    assert_eq!(utxo.amount_sats(), 50_000);
    assert_eq!(utxo.txid, [0xCCu8; 32]);
    assert_eq!(utxo.get_status(), UtxoStatus::Unspent);
}

#[test]
fn test_utxo_record_from_bytes_wrong_discriminator() {
    let mut buf = [0u8; 56];
    buf[0] = 0x01; // wrong discriminator
    assert!(UtxoRecord::from_bytes(&buf).is_err());
}

#[test]
fn test_utxo_record_from_bytes_too_small() {
    let buf = [0x09u8; 10]; // correct disc but too small
    assert!(UtxoRecord::from_bytes(&buf).is_err());
}

#[test]
fn test_utxo_record_from_bytes_mut() {
    let mut buf = [0u8; 56];
    UtxoRecord::init(&mut buf).unwrap();

    let utxo = UtxoRecord::from_bytes_mut(&mut buf).unwrap();
    utxo.set_status(UtxoStatus::Reserved);
    assert_eq!(utxo.get_status(), UtxoStatus::Reserved);

    // Read back immutably
    let utxo2 = UtxoRecord::from_bytes(&buf).unwrap();
    assert_eq!(utxo2.get_status(), UtxoStatus::Reserved);
}

#[test]
fn test_utxo_status_values() {
    assert_eq!(UtxoStatus::Unspent as u8, 0);
    assert_eq!(UtxoStatus::Reserved as u8, 1);
}

#[test]
fn test_utxo_unknown_status_defaults_to_unspent() {
    let mut buf = [0u8; 56];
    UtxoRecord::init(&mut buf).unwrap();
    buf[1] = 0xFF; // invalid status byte
    let utxo = UtxoRecord::from_bytes(&buf).unwrap();
    assert_eq!(utxo.get_status(), UtxoStatus::Unspent);
}

#[test]
fn test_utxo_record_large_amount() {
    let mut buf = [0u8; 56];
    let utxo = UtxoRecord::init(&mut buf).unwrap();

    let max_btc = 21_000_000 * 100_000_000u64; // 21M BTC in sats
    utxo.set_amount_sats(max_btc);
    assert_eq!(utxo.amount_sats(), max_btc);
}

#[test]
fn test_utxo_record_max_vout() {
    let mut buf = [0u8; 56];
    let utxo = UtxoRecord::init(&mut buf).unwrap();
    utxo.set_vout(u32::MAX);
    assert_eq!(utxo.vout(), u32::MAX);
}

#[test]
fn test_utxo_record_zero_copy_layout() {
    // Verify the zero-copy layout matches the documented byte offsets
    let mut buf = [0u8; 56];
    let utxo = UtxoRecord::init(&mut buf).unwrap();

    utxo.set_status(UtxoStatus::Reserved);
    utxo.set_vout(7);
    let txid = [0x42u8; 32];
    utxo.set_txid(&txid);
    utxo.set_amount_sats(12345);
    utxo.set_reserved_for_request_id(99);
    assert_eq!(utxo.reserved_for_request_id(), 99);

    // Check raw bytes at documented offsets
    assert_eq!(buf[0], 0x09); // discriminator
    assert_eq!(buf[1], 1); // status = Reserved
    assert_eq!(buf[2], 0); // padding
    assert_eq!(buf[3], 0); // padding
    assert_eq!(buf[4..8], 7u32.to_le_bytes()); // vout
    assert_eq!(&buf[8..40], &txid); // txid
    assert_eq!(buf[40..48], 12345u64.to_le_bytes()); // amount_sats
    assert_eq!(buf[48..56], 99u64.to_le_bytes()); // reserved_for_request_id
}

/// A UTXO whose tapleaf cannot be rebuilt is a UTXO nobody can ever spend — the
/// key path is a NUMS point, so the commitment stored here is the only thing
/// standing between the pool and burned coins.
#[test]
fn leaf_commitment_round_trips() {
    let mut data = vec![0u8; UtxoRecord::LEN_WITH_LEAF];
    UtxoRecord::init(&mut data).unwrap();

    let commitment = [0xADu8; 32];
    UtxoRecord::set_leaf_commitment(&mut data, &commitment).unwrap();

    assert_eq!(UtxoRecord::leaf_commitment(&data), Some(&commitment));
    // The base record still parses — the commitment is a tail, not a field.
    assert_eq!(UtxoRecord::from_bytes(&data).unwrap().discriminator, data[0]);
}

/// Records written before the tail existed must keep working. They are key-path
/// UTXOs at the raw dWallet address and have no leaf to rebuild.
#[test]
fn a_record_without_the_tail_is_a_key_path_utxo() {
    let mut data = vec![0u8; UtxoRecord::LEN];
    UtxoRecord::init(&mut data).unwrap();

    assert!(UtxoRecord::from_bytes(&data).is_ok());
    assert_eq!(UtxoRecord::leaf_commitment(&data), None);

    // Writing into an account that was never sized for it must fail loudly
    // rather than scribble past the end or silently no-op.
    assert!(UtxoRecord::set_leaf_commitment(&mut data, &[0xADu8; 32]).is_err());
}

#[test]
fn the_tail_sits_past_every_field_the_record_uses() {
    let mut data = vec![0u8; UtxoRecord::LEN_WITH_LEAF];
    {
        let utxo = UtxoRecord::init(&mut data).unwrap();
        utxo.set_txid(&[0x11u8; 32]);
        utxo.set_vout(7);
        utxo.set_amount_sats(50_000);
    }
    UtxoRecord::set_leaf_commitment(&mut data, &[0xADu8; 32]).unwrap();

    // Neither write may have clobbered the other.
    let utxo = UtxoRecord::from_bytes(&data).unwrap();
    assert_eq!(utxo.txid, [0x11u8; 32]);
    assert_eq!(utxo.vout(), 7);
    assert_eq!(utxo.amount_sats(), 50_000);
    assert_eq!(UtxoRecord::leaf_commitment(&data), Some(&[0xADu8; 32]));
}

