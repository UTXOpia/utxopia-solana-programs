    use super::*;
    use crate::constants::TARGET_TIMESPAN;

    #[test]
    fn required_bits_mainnet_retargets_at_boundary() {
        let epoch_bits = 0x1d00ffff;
        let required = required_bits_for_next_block(
            false,
            BLOCKS_PER_EPOCH,
            1_500,
            TARGET_TIMESPAN / 2,
            epoch_bits,
            0,
        );

        assert_ne!(required, epoch_bits);
        assert_eq!(
            required,
            calculate_new_bits(epoch_bits, TARGET_TIMESPAN / 2)
        );
    }

    #[test]
    fn required_bits_testnet4_min_difficulty_exception() {
        let epoch_bits = 0x1d00aaaa;
        let required = required_bits_for_next_block(false, 100, 2_001, 0, epoch_bits, 0);
        assert_eq!(required, epoch_bits);

        let testnet4_required = required_bits_for_next_block(true, 100, 2_001, 0, epoch_bits, 0);
        assert_eq!(testnet4_required, MAX_TARGET_BITS);
    }

    #[test]
    fn required_bits_testnet4_boundary_uses_retarget_not_min_difficulty() {
        let epoch_bits = 0x1d00aaaa;
        let required = required_bits_for_next_block(
            true,
            BLOCKS_PER_EPOCH,
            10 * TARGET_TIMESPAN,
            TARGET_TIMESPAN,
            epoch_bits,
            0,
        );

        assert_eq!(required, calculate_new_bits(epoch_bits, TARGET_TIMESPAN));
        assert_ne!(required, MAX_TARGET_BITS);
    }

    // --- Regression tests for the 2026-06-14 consensus hardening ---

    /// C1: an unseeded chain (epoch_bits == 0) yields required_bits == 0. extend_blockchain
    /// now treats 0 as "reject" for mainnet/testnet4 instead of skipping the difficulty check.
    #[test]
    fn unseeded_epoch_bits_returns_zero() {
        assert_eq!(
            required_bits_for_next_block(false, 100, 1_000, 900, 0, 0),
            0
        );
        assert_eq!(required_bits_for_next_block(true, 100, 1_000, 900, 0, 0), 0);
    }

    /// C2 guard: an out-of-order (backwards) timestamp must NOT trip the testnet4
    /// min-difficulty exception. Pre-fix, `timestamp.wrapping_sub(parent)` underflowed to a
    /// huge value > 1200 and returned MAX_TARGET_BITS, easing difficulty for free.
    #[test]
    fn testnet4_backwards_timestamp_does_not_ease_difficulty() {
        let epoch_bits = 0x1d00aaaa;
        // timestamp (100) < parent_timestamp (1000), non-boundary height.
        let required = required_bits_for_next_block(true, 100, 100, 1_000, epoch_bits, 0);
        assert_eq!(required, epoch_bits);
        assert_ne!(required, MAX_TARGET_BITS);
    }

    /// C2 guard: an epoch-boundary retarget with parent_timestamp < epoch_start_time must
    /// saturate the timespan to 0 (→ clamped to the minimum, hardest), never underflow into
    /// the maximum timespan (easiest).
    #[test]
    fn retarget_saturates_on_backwards_epoch_no_easing() {
        let epoch_bits = 0x1b0404cb; // a realistic mid-range difficulty
        let required = required_bits_for_next_block(
            false,
            BLOCKS_PER_EPOCH, // boundary
            5_000,
            100,   // parent_timestamp
            epoch_bits,
            1_000, // epoch_start_time > parent_timestamp → backwards
        );
        // Saturated timespan 0 clamps to TARGET_TIMESPAN/4 (max difficulty increase).
        assert_eq!(required, calculate_new_bits(epoch_bits, TARGET_TIMESPAN / 4));
        // And it is NOT the eased (4x timespan) result.
        assert_ne!(required, calculate_new_bits(epoch_bits, TARGET_TIMESPAN * 4));
    }

    /// calculate_new_bits clamps the timespan to [T/4, T*4]; values outside collapse to the
    /// bounds, capping per-epoch difficulty swings (limits timestamp-manipulation leverage).
    #[test]
    fn calculate_new_bits_clamps_timespan() {
        let b = 0x1b0404cb;
        assert_eq!(calculate_new_bits(b, 1), calculate_new_bits(b, TARGET_TIMESPAN / 4));
        assert_eq!(
            calculate_new_bits(b, u32::MAX),
            calculate_new_bits(b, TARGET_TIMESPAN * 4)
        );
    }
