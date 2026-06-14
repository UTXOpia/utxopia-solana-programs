    use super::*;
    use crate::utils::bitcoin::ParsedTransaction;

    fn p2tr(tag: u8) -> Vec<u8> {
        let mut s = vec![0x51u8, 0x20];
        s.extend_from_slice(&[tag; 32]);
        s
    }

    fn op_return() -> Vec<u8> {
        vec![0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef]
    }

    /// Build a minimal legacy tx (1 input, given outputs). Counts assumed < 253.
    fn tx_with_outputs(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
        let mut t = vec![1u8, 0, 0, 0]; // version
        t.push(1); // input count
        t.extend_from_slice(&[0u8; 32]); // prev txid
        t.extend_from_slice(&[0u8; 4]); // prev vout
        t.push(0); // scriptSig len
        t.extend_from_slice(&[0xffu8; 4]); // sequence
        t.push(outputs.len() as u8); // output count
        for (val, script) in outputs {
            t.extend_from_slice(&val.to_le_bytes());
            t.push(script.len() as u8);
            t.extend_from_slice(script);
        }
        t.extend_from_slice(&[0u8; 4]); // locktime
        t
    }

    const RECIPIENT: u8 = 0xAA;
    const POOL: u8 = 0xBB;
    const ATTACKER: u8 = 0xCC;

    #[test]
    fn allows_recipient_only() {
        let tx = tx_with_outputs(&[(100_000, p2tr(RECIPIENT))]);
        let parsed = ParsedTransaction::parse(&tx).unwrap();
        assert!(redemption_outputs_within_policy(
            &parsed,
            &p2tr(RECIPIENT),
            &p2tr(POOL)
        ));
    }

    #[test]
    fn allows_recipient_plus_pool_change_and_op_return() {
        let tx = tx_with_outputs(&[
            (100_000, p2tr(RECIPIENT)),
            (50_000, p2tr(POOL)),
            (0, op_return()),
        ]);
        let parsed = ParsedTransaction::parse(&tx).unwrap();
        assert!(redemption_outputs_within_policy(
            &parsed,
            &p2tr(RECIPIENT),
            &p2tr(POOL)
        ));
    }

    /// The core skim attack: an extra output to an attacker-controlled address must be rejected.
    #[test]
    fn rejects_attacker_skim_output() {
        let tx = tx_with_outputs(&[
            (100_000, p2tr(RECIPIENT)),
            (800_000, p2tr(ATTACKER)), // skim
        ]);
        let parsed = ParsedTransaction::parse(&tx).unwrap();
        assert!(!redemption_outputs_within_policy(
            &parsed,
            &p2tr(RECIPIENT),
            &p2tr(POOL)
        ));
    }

    /// With no pool_script declared, ANY non-recipient/non-OP_RETURN output is a skim.
    #[test]
    fn rejects_change_when_pool_script_absent() {
        let tx = tx_with_outputs(&[
            (100_000, p2tr(RECIPIENT)),
            (50_000, p2tr(POOL)), // would-be change, but pool_script not provided
        ]);
        let parsed = ParsedTransaction::parse(&tx).unwrap();
        assert!(!redemption_outputs_within_policy(
            &parsed,
            &p2tr(RECIPIENT),
            &[]
        ));
    }
