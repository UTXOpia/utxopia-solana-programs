    use super::*;

    #[test]
    fn test_discriminators_unique() {
        let discriminators: &[u8] = &[
            instruction::INITIALIZE,
            instruction::SET_PAUSED,
            instruction::SET_POOL_CONFIG,
            instruction::PROPOSE_POOL_UPDATE,
            instruction::EXECUTE_POOL_UPDATE,
            instruction::CANCEL_POOL_UPDATE,
            instruction::INIT_VK_REGISTRY,
            instruction::UPDATE_VK_REGISTRY,
            instruction::FREEZE_VK_REGISTRY,
            instruction::REGISTER_TOKEN,
            instruction::UPDATE_TOKEN_CONFIG,
            instruction::CLAIM_FEES,
            instruction::COMPLETE_DEPOSIT,
            instruction::SHIELD,
            instruction::TRANSACT,
            instruction::UNSHIELD,
            instruction::REDEEM,
            instruction::COMPLETE_REDEMPTION,
            instruction::MARK_PROCESSING,
            instruction::CANCEL_REDEMPTION,
        ];

        for (i, &d1) in discriminators.iter().enumerate() {
            for (j, &d2) in discriminators.iter().enumerate() {
                if i != j {
                    assert_ne!(d1, d2, "Duplicate at {} and {}", i, j);
                }
            }
        }
    }

    #[test]
    fn test_account_discriminators_unique() {
        use crate::state::commitment_tree::COMMITMENT_TREE_DISCRIMINATOR;
        use crate::state::completion_receipt::COMPLETION_RECEIPT_DISCRIMINATOR;
        use crate::state::deposit_intent::DEPOSIT_INTENT_DISCRIMINATOR;
        use crate::state::deposit_receipt::DEPOSIT_RECEIPT_DISCRIMINATOR;
        use crate::state::nullifier::NULLIFIER_RECORD_DISCRIMINATOR;
        use crate::state::pool::POOL_STATE_DISCRIMINATOR;
        use crate::state::pool_config::POOL_CONFIG_DISCRIMINATOR;
        use crate::state::redemption::REDEMPTION_REQUEST_DISCRIMINATOR;
        use crate::state::token_config::TOKEN_CONFIG_DISCRIMINATOR;
        use crate::state::utxo::UTXO_RECORD_DISCRIMINATOR;
        use crate::state::vk_registry::VK_REGISTRY_DISCRIMINATOR;

        // All UTXOpia-owned account discriminators must be unique
        let discs: &[u8] = &[
            POOL_STATE_DISCRIMINATOR,         // 0x01
            NULLIFIER_RECORD_DISCRIMINATOR,   // 0x03
            REDEMPTION_REQUEST_DISCRIMINATOR, // 0x04
            COMMITMENT_TREE_DISCRIMINATOR,    // 0x05
            DEPOSIT_RECEIPT_DISCRIMINATOR,    // 0x06
            DEPOSIT_INTENT_DISCRIMINATOR,     // 0x07
            COMPLETION_RECEIPT_DISCRIMINATOR, // 0x08
            UTXO_RECORD_DISCRIMINATOR,        // 0x09
            POOL_CONFIG_DISCRIMINATOR,        // 0x0A
            TOKEN_CONFIG_DISCRIMINATOR,       // 0x0B
            VK_REGISTRY_DISCRIMINATOR,        // 0x14
        ];

        for (i, &d1) in discs.iter().enumerate() {
            for (j, &d2) in discs.iter().enumerate() {
                if i != j {
                    assert_ne!(
                        d1, d2,
                        "Duplicate account discriminator at {} (0x{:02x}) and {} (0x{:02x})",
                        i, d1, j, d2
                    );
                }
            }
        }
    }

    #[test]
    fn test_utxo_discriminator_value() {
        use crate::state::utxo::UTXO_RECORD_DISCRIMINATOR;
        assert_eq!(UTXO_RECORD_DISCRIMINATOR, 0x09);
    }
