use super::*;

fn init_pool() -> Vec<u8> {
    let mut buf = vec![0u8; PoolState::LEN];
    PoolState::init(&mut buf).unwrap();
    buf
}

#[test]
fn test_pool_state_size_unchanged() {
    // PoolState size must stay constant for zero-copy account layout.
    // _reserved was 20 bytes, now carved into: total_btc_held(8) + utxo_count(2) + _reserved(10)
    assert_eq!(PoolState::LEN, 268);
}

#[test]
fn test_pool_state_utxo_fields_default_zero() {
    let buf = init_pool();
    let pool = PoolState::from_bytes(&buf).unwrap();
    assert_eq!(pool.total_btc_held(), 0);
    assert_eq!(pool.utxo_count(), 0);
}

#[test]
fn test_pool_state_add_utxo() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    pool.add_utxo(50_000).unwrap();
    assert_eq!(pool.total_btc_held(), 50_000);
    assert_eq!(pool.utxo_count(), 1);

    pool.add_utxo(30_000).unwrap();
    assert_eq!(pool.total_btc_held(), 80_000);
    assert_eq!(pool.utxo_count(), 2);
}

#[test]
fn test_pool_state_remove_utxo() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    pool.add_utxo(50_000).unwrap();
    pool.add_utxo(30_000).unwrap();

    pool.remove_utxo(50_000).unwrap();
    assert_eq!(pool.total_btc_held(), 30_000);
    assert_eq!(pool.utxo_count(), 1);

    pool.remove_utxo(30_000).unwrap();
    assert_eq!(pool.total_btc_held(), 0);
    assert_eq!(pool.utxo_count(), 0);
}

#[test]
fn test_pool_state_remove_utxo_underflow() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    // Removing from zero should fail
    assert!(pool.remove_utxo(1).is_err());
}

#[test]
fn test_pool_state_remove_utxo_count_underflow() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    // Set total_btc_held > 0 but utxo_count = 0 (shouldn't happen, but test the guard)
    pool.set_total_btc_held(100);
    pool.set_utxo_count(0);
    assert!(pool.remove_utxo(50).is_err());
}

#[test]
fn test_pool_state_utxo_counters_independent_of_other_fields() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    // Set some other fields
    pool.set_deposit_count(10);
    pool.set_total_minted(1_000_000);
    pool.set_total_shielded(500_000);

    // UTXO operations should not affect them
    pool.add_utxo(100_000).unwrap();
    assert_eq!(pool.deposit_count(), 10);
    assert_eq!(pool.total_minted(), 1_000_000);
    assert_eq!(pool.total_shielded(), 500_000);
    assert_eq!(pool.total_btc_held(), 100_000);
    assert_eq!(pool.utxo_count(), 1);
}

#[test]
fn test_pool_state_utxo_fields_preserve_layout() {
    // Simulate an account with zeros in the reserved region. The UTXO fields
    // should read as 0.
    let mut buf = vec![0u8; PoolState::LEN];
    buf[0] = POOL_STATE_DISCRIMINATOR;
    let pool = PoolState::from_bytes(&buf).unwrap();

    assert_eq!(pool.total_btc_held(), 0);
    assert_eq!(pool.utxo_count(), 0);
}

#[test]
fn test_pool_state_set_total_btc_held() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    pool.set_total_btc_held(21_000_000 * 100_000_000);
    assert_eq!(pool.total_btc_held(), 2_100_000_000_000_000);
}

#[test]
fn test_pool_state_set_utxo_count() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    pool.set_utxo_count(u16::MAX);
    assert_eq!(pool.utxo_count(), u16::MAX);
}

#[test]
fn test_pool_state_add_utxo_overflow() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    pool.set_total_btc_held(u64::MAX);
    assert!(pool.add_utxo(1).is_err());
}

#[test]
fn test_pool_state_add_utxo_count_overflow() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    pool.set_utxo_count(u16::MAX);
    assert!(pool.add_utxo(1).is_err());
}

#[test]
fn test_pool_state_multiple_utxo_lifecycle() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    // Deposit 3 UTXOs
    pool.add_utxo(10_000).unwrap(); // UTXO 1
    pool.add_utxo(25_000).unwrap(); // UTXO 2
    pool.add_utxo(50_000).unwrap(); // UTXO 3

    assert_eq!(pool.total_btc_held(), 85_000);
    assert_eq!(pool.utxo_count(), 3);

    // Reserve 2 UTXOs for withdrawal (mark_processing)
    pool.remove_utxo(10_000).unwrap();
    pool.remove_utxo(25_000).unwrap();
    assert_eq!(pool.total_btc_held(), 50_000);
    assert_eq!(pool.utxo_count(), 1);

    // Change UTXO comes back (complete_redemption)
    pool.add_utxo(5_000).unwrap();
    assert_eq!(pool.total_btc_held(), 55_000);
    assert_eq!(pool.utxo_count(), 2);
}

#[test]
fn test_pool_state_deposit_withdrawal_fees() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    pool.set_deposit_fee_bps(50); // 0.5%
    pool.set_withdrawal_fee_bps(100); // 1.0%

    assert_eq!(pool.deposit_fee_bps(), 50);
    assert_eq!(pool.withdrawal_fee_bps(), 100);
    assert_eq!(pool.compute_deposit_fee(100_000), 500); // 0.5%
    assert_eq!(pool.compute_withdrawal_fee(100_000), 1000); // 1.0%
}

#[test]
fn test_pool_state_deposit_withdrawal_fees_default_zero() {
    let buf = init_pool();
    let pool = PoolState::from_bytes(&buf).unwrap();
    assert_eq!(pool.deposit_fee_bps(), 0);
    assert_eq!(pool.withdrawal_fee_bps(), 0);
    assert_eq!(pool.compute_deposit_fee(100_000), 0);
    assert_eq!(pool.compute_withdrawal_fee(100_000), 0);
}

#[test]
fn test_pool_state_service_fee_computation() {
    let mut buf = init_pool();
    let pool = PoolState::from_bytes_mut(&mut buf).unwrap();

    pool.set_withdrawal_fee_bps(30);
    pool.set_service_fee_base(1000);

    // UTXO operations should not interfere with fee computation
    pool.add_utxo(100_000).unwrap();

    // fee = 100000 * 30 / 10000 + 1000 = 300 + 1000 = 1300
    assert_eq!(pool.compute_service_fee(100_000), 1300);
}
