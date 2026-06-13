use super::*;

#[test]
fn test_varint() {
    assert_eq!(read_varint(&[0x00]).unwrap(), (0, 1));
    assert_eq!(read_varint(&[0xfc]).unwrap(), (252, 1));
    assert_eq!(read_varint(&[0xfd, 0x00, 0x01]).unwrap(), (256, 3));
}

#[test]
fn test_op_return_detection() {
    let mut script = vec![0x6a, 0x20]; // OP_RETURN + push 32 bytes
    script.extend_from_slice(&[0xAB; 32]);

    let output = TxOutput {
        value: 0,
        script_pubkey: &script,
    };
    assert!(output.is_op_return());
    assert!(output.get_commitment().is_some());
}

#[test]
fn test_deposit_op_return_direct_push() {
    // OP_RETURN (0x6a) + push 73 (0x49) + v1 deposit payload
    let mut script = vec![0x6a, 0x49, 0x53];
    let pool_tag = [0xcc; 8];
    let ephemeral_pubkey = [0xaa; 32];
    let note_public_key = [0xbb; 32];
    script.extend_from_slice(&pool_tag);
    script.extend_from_slice(&ephemeral_pubkey);
    script.extend_from_slice(&note_public_key);

    let output = TxOutput {
        value: 0,
        script_pubkey: &script,
    };
    assert!(output.is_op_return());
    let data = output.get_deposit_op_return().unwrap();
    assert_eq!(data.pool_tag, pool_tag);
    assert_eq!(data.ephemeral_pubkey, ephemeral_pubkey);
    assert_eq!(data.note_public_key, note_public_key);
}

#[test]
fn test_deposit_op_return_pushdata1() {
    // OP_RETURN (0x6a) + PUSHDATA1 (0x4c) + 73 (0x49) + v1 deposit payload
    let mut script = vec![0x6a, 0x4c, 0x49, 0x53];
    script.extend_from_slice(&[0xcc; 8]); // pool tag
    script.extend_from_slice(&[0x11; 32]); // ephemeral_pubkey
    script.extend_from_slice(&[0x22; 32]); // note_public_key

    let output = TxOutput {
        value: 0,
        script_pubkey: &script,
    };
    let data = output.get_deposit_op_return().unwrap();
    assert_eq!(data.pool_tag, [0xcc; 8]);
    assert_eq!(data.ephemeral_pubkey, [0x11; 32]);
    assert_eq!(data.note_public_key, [0x22; 32]);
}

#[test]
fn test_deposit_op_return_wrong_size() {
    // 32-byte OP_RETURN should NOT match deposit format
    let mut script = vec![0x6a, 0x20];
    script.extend_from_slice(&[0xaa; 32]);

    let output = TxOutput {
        value: 0,
        script_pubkey: &script,
    };
    assert!(output.get_deposit_op_return().is_none());
}

/// Build a minimal raw Bitcoin transaction for testing
fn build_test_tx(
    inputs: &[([u8; 32], u32)], // (prev_txid, prev_vout)
    outputs: &[(u64, &[u8])],   // (value, script_pubkey)
) -> Vec<u8> {
    let mut tx = Vec::new();

    // Version (4 bytes)
    tx.extend_from_slice(&1i32.to_le_bytes());

    // Input count
    tx.push(inputs.len() as u8);
    for (prev_txid, prev_vout) in inputs {
        tx.extend_from_slice(prev_txid);
        tx.extend_from_slice(&prev_vout.to_le_bytes());
        tx.push(0); // empty script
        tx.extend_from_slice(&0xffffffffu32.to_le_bytes()); // sequence
    }

    // Output count
    tx.push(outputs.len() as u8);
    for (value, script) in outputs {
        tx.extend_from_slice(&value.to_le_bytes());
        tx.push(script.len() as u8);
        tx.extend_from_slice(script);
    }

    // Locktime
    tx.extend_from_slice(&0u32.to_le_bytes());

    tx
}

#[test]
fn test_parsed_tx_inputs() {
    let prev_txid_1 = [0x11u8; 32];
    let prev_txid_2 = [0x22u8; 32];

    let p2tr_script = {
        let mut s = vec![0x51, 0x20]; // OP_1 + PUSH_32
        s.extend_from_slice(&[0xaa; 32]);
        s
    };

    let raw_tx = build_test_tx(
        &[(prev_txid_1, 0), (prev_txid_2, 1)],
        &[(50000, &p2tr_script)],
    );

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    assert_eq!(parsed.input_count, 2);

    // Verify input iteration
    let inputs: Vec<TxInput> = parsed.inputs().collect();
    assert_eq!(inputs.len(), 2);
    assert_eq!(inputs[0].prev_txid, prev_txid_1);
    assert_eq!(inputs[0].prev_vout, 0);
    assert_eq!(inputs[1].prev_txid, prev_txid_2);
    assert_eq!(inputs[1].prev_vout, 1);

    // Test find_input_with_prev_txid
    assert!(parsed.find_input_with_prev_txid(&prev_txid_1));
    assert!(parsed.find_input_with_prev_txid(&prev_txid_2));
    assert!(!parsed.find_input_with_prev_txid(&[0x33; 32]));

    // Exact outpoint binding must distinguish outputs in the same tx.
    assert!(parsed.find_input_with_prev_outpoint(&prev_txid_1, 0));
    assert!(!parsed.find_input_with_prev_outpoint(&prev_txid_1, 1));
    assert!(parsed.find_input_with_prev_outpoint(&prev_txid_2, 1));
}

#[test]
fn test_parsed_tx_deposit_op_return() {
    let prev_txid = [0x11u8; 32];
    let ephemeral_pubkey = [0xaa; 32];
    let note_public_key = [0xbb; 32];

    // P2TR output
    let p2tr_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xcc; 32]);
        s
    };

    // Deposit OP_RETURN: 0x6a 0x49 + v1 deposit payload
    let pool_tag = [0xcc; 8];
    let mut op_return_script = vec![0x6a, 0x49, 0x53];
    op_return_script.extend_from_slice(&pool_tag);
    op_return_script.extend_from_slice(&ephemeral_pubkey);
    op_return_script.extend_from_slice(&note_public_key);

    let raw_tx = build_test_tx(
        &[(prev_txid, 0)],
        &[(50000, &p2tr_script), (0, &op_return_script)],
    );

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    let deposit_data = parsed.find_deposit_op_return().unwrap();
    assert_eq!(deposit_data.pool_tag, pool_tag);
    assert_eq!(deposit_data.ephemeral_pubkey, ephemeral_pubkey);
    assert_eq!(deposit_data.note_public_key, note_public_key);
}

// =========================================================================
// Tests for find_deposit_output_with_vout
// =========================================================================

#[test]
fn test_find_deposit_output_with_vout_single_output() {
    let p2tr_script = {
        let mut s = vec![0x51, 0x20]; // OP_1 + PUSH_32
        s.extend_from_slice(&[0xaa; 32]);
        s
    };

    let raw_tx = build_test_tx(&[([0x11; 32], 0)], &[(100_000, &p2tr_script)]);

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    let (output, vout) = parsed.find_deposit_output_with_vout().unwrap();
    assert_eq!(vout, 0);
    assert_eq!(output.value, 100_000);
}

#[test]
fn test_find_deposit_output_with_vout_op_return_first() {
    // OP_RETURN at vout=0, deposit output at vout=1
    let mut op_return_script = vec![0x6a, 0x20];
    op_return_script.extend_from_slice(&[0x00; 32]);

    let p2tr_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xbb; 32]);
        s
    };

    let raw_tx = build_test_tx(
        &[([0x11; 32], 0)],
        &[(0, &op_return_script), (50_000, &p2tr_script)],
    );

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    let (output, vout) = parsed.find_deposit_output_with_vout().unwrap();
    assert_eq!(vout, 1); // skips OP_RETURN at vout=0
    assert_eq!(output.value, 50_000);
}

#[test]
fn test_find_deposit_output_with_vout_multiple_outputs() {
    let p2tr_1 = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xaa; 32]);
        s
    };
    let p2tr_2 = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xbb; 32]);
        s
    };

    let raw_tx = build_test_tx(&[([0x11; 32], 0)], &[(75_000, &p2tr_1), (25_000, &p2tr_2)]);

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    let (output, vout) = parsed.find_deposit_output_with_vout().unwrap();
    assert_eq!(vout, 0); // first non-OP_RETURN output
    assert_eq!(output.value, 75_000);
}

#[test]
fn test_find_deposit_output_with_vout_zero_value_skipped() {
    let p2tr_1 = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xaa; 32]);
        s
    };
    let p2tr_2 = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xbb; 32]);
        s
    };

    let raw_tx = build_test_tx(&[([0x11; 32], 0)], &[(0, &p2tr_1), (50_000, &p2tr_2)]);

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    let (output, vout) = parsed.find_deposit_output_with_vout().unwrap();
    assert_eq!(vout, 1); // skips zero-value output
    assert_eq!(output.value, 50_000);
}

#[test]
fn test_find_deposit_output_with_vout_all_op_return() {
    let op_return_1 = {
        let mut s = vec![0x6a, 0x20];
        s.extend_from_slice(&[0x00; 32]);
        s
    };
    let op_return_2 = {
        let mut s = vec![0x6a, 0x20];
        s.extend_from_slice(&[0x11; 32]);
        s
    };

    let raw_tx = build_test_tx(&[([0x11; 32], 0)], &[(0, &op_return_1), (0, &op_return_2)]);

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    assert!(parsed.find_deposit_output_with_vout().is_none());
}

// =========================================================================
// Tests for find_output_by_script
// =========================================================================

#[test]
fn test_find_output_by_script_exact_match() {
    let pool_script = {
        let mut s = vec![0x51, 0x20]; // P2TR
        s.extend_from_slice(&[0xAA; 32]);
        s
    };
    let user_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xBB; 32]);
        s
    };

    let raw_tx = build_test_tx(
        &[([0x11; 32], 0)],
        &[(40_000, &user_script), (60_000, &pool_script)],
    );

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    let (output, vout) = parsed.find_output_by_script(&pool_script).unwrap();
    assert_eq!(vout, 1);
    assert_eq!(output.value, 60_000);
}

#[test]
fn test_find_output_by_script_first_match() {
    let target_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xCC; 32]);
        s
    };

    let raw_tx = build_test_tx(
        &[([0x11; 32], 0)],
        &[(10_000, &target_script), (20_000, &target_script)],
    );

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    let (output, vout) = parsed.find_output_by_script(&target_script).unwrap();
    assert_eq!(vout, 0); // returns first match
    assert_eq!(output.value, 10_000);
}

#[test]
fn test_find_output_by_script_no_match() {
    let pool_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xAA; 32]);
        s
    };
    let other_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xBB; 32]);
        s
    };

    let raw_tx = build_test_tx(&[([0x11; 32], 0)], &[(50_000, &other_script)]);

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    assert!(parsed.find_output_by_script(&pool_script).is_none());
}

#[test]
fn test_find_output_by_script_withdrawal_tx_pattern() {
    // Typical withdrawal tx: vout=0 is user, vout=1 is change to pool
    let user_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0x11; 32]);
        s
    };
    let pool_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0x22; 32]);
        s
    };

    let raw_tx = build_test_tx(
        &[([0xAA; 32], 0), ([0xBB; 32], 1)],
        &[(45_000, &user_script), (53_000, &pool_script)],
    );

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();

    // Find user output
    let (user_out, user_vout) = parsed.find_output_by_script(&user_script).unwrap();
    assert_eq!(user_vout, 0);
    assert_eq!(user_out.value, 45_000);

    // Find pool change output
    let (pool_out, pool_vout) = parsed.find_output_by_script(&pool_script).unwrap();
    assert_eq!(pool_vout, 1);
    assert_eq!(pool_out.value, 53_000);

    // Verify sum_outputs for miner fee computation
    assert_eq!(parsed.sum_outputs(), 98_000);
}

// =========================================================================
// Tests for sum_outputs (used in miner fee computation)
// =========================================================================

#[test]
fn test_sum_outputs_single() {
    let script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xAA; 32]);
        s
    };
    let raw_tx = build_test_tx(&[([0x11; 32], 0)], &[(100_000, &script)]);
    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    assert_eq!(parsed.sum_outputs(), 100_000);
}

#[test]
fn test_sum_outputs_multiple_with_op_return() {
    let script1 = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xAA; 32]);
        s
    };
    let script2 = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0xBB; 32]);
        s
    };
    let mut op_return = vec![0x6a, 0x20];
    op_return.extend_from_slice(&[0x00; 32]);

    let raw_tx = build_test_tx(
        &[([0x11; 32], 0)],
        &[(40_000, &script1), (0, &op_return), (55_000, &script2)],
    );

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    assert_eq!(parsed.sum_outputs(), 95_000); // 40000 + 0 + 55000
}

#[test]
fn test_sum_outputs_miner_fee_computation() {
    // Simulates: 2 inputs totaling 100,000 sats, 2 outputs totaling 98,000 sats
    // miner_fee = 100,000 - 98,000 = 2,000 sats
    let user_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0x11; 32]);
        s
    };
    let change_script = {
        let mut s = vec![0x51, 0x20];
        s.extend_from_slice(&[0x22; 32]);
        s
    };

    let raw_tx = build_test_tx(
        &[([0xAA; 32], 0), ([0xBB; 32], 1)],
        &[(45_000, &user_script), (53_000, &change_script)],
    );

    let parsed = ParsedTransaction::parse(&raw_tx).unwrap();
    let total_input_sats: u64 = 100_000; // from UTXO PDAs
    let miner_fee = total_input_sats.saturating_sub(parsed.sum_outputs());
    assert_eq!(miner_fee, 2_000);
}
