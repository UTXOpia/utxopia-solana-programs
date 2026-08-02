use super::*;

#[test]
fn test_dwallet_binding_size() {
    assert_eq!(DwalletBinding::LEN, 33);
}

#[test]
fn test_dwallet_binding_seed() {
    assert_eq!(DwalletBinding::SEED, b"dwallet_binding");
}

#[test]
fn test_dwallet_binding_discriminator() {
    assert_eq!(DWALLET_BINDING_DISCRIMINATOR, 0x15);
}

#[test]
fn init_records_the_owning_pool() {
    let mut buf = [0u8; DwalletBinding::LEN];
    let pool = [7u8; 32];
    DwalletBinding::init(&mut buf, &pool).unwrap();

    assert_eq!(buf[0], DWALLET_BINDING_DISCRIMINATOR);
    assert_eq!(DwalletBinding::pool_state(&buf).unwrap(), pool);
}

/// The binding is only meaningful if a second pool reads back the *first*
/// pool's id — that mismatch is what `set_pool_config` refuses on.
#[test]
fn a_second_pool_reads_back_the_first_pools_id() {
    let mut buf = [0u8; DwalletBinding::LEN];
    let first = [1u8; 32];
    let second = [2u8; 32];
    DwalletBinding::init(&mut buf, &first).unwrap();

    let recorded = DwalletBinding::pool_state(&buf).unwrap();
    assert_eq!(recorded, first);
    assert_ne!(recorded, second);
}

#[test]
fn rejects_uninitialized_or_foreign_data() {
    let empty = [0u8; DwalletBinding::LEN];
    assert!(DwalletBinding::pool_state(&empty).is_err());

    let mut wrong_disc = [0u8; DwalletBinding::LEN];
    wrong_disc[0] = 0x09; // a UtxoRecord, say
    assert!(DwalletBinding::pool_state(&wrong_disc).is_err());

    let truncated = [DWALLET_BINDING_DISCRIMINATOR; 8];
    assert!(DwalletBinding::pool_state(&truncated).is_err());
}

#[test]
fn init_refuses_a_buffer_that_cannot_hold_the_pool() {
    let mut short = [0u8; 8];
    assert!(DwalletBinding::init(&mut short, &[3u8; 32]).is_err());
}
