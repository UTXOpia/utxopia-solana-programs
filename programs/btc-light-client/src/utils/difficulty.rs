use super::pow::target_from_bits;
use super::u256::{
    u256_div_u32, u256_from_le_bytes, u256_gt_bytes, u256_mul_u32, u256_to_le_bytes,
};
use crate::constants::{BLOCKS_PER_EPOCH, TARGET_TIMESPAN};

/// Maximum target (genesis difficulty) in compact bits format
const MAX_TARGET_BITS: u32 = 0x1d00ffff;

/// Calculate new difficulty bits after a retarget epoch.
/// Matches Bitcoin Core's GetNextWorkRequired algorithm.
pub fn calculate_new_bits(old_bits: u32, actual_timespan: u32) -> u32 {
    // Clamp timespan to [TARGET_TIMESPAN/4, TARGET_TIMESPAN*4]
    let clamped = actual_timespan.clamp(TARGET_TIMESPAN / 4, TARGET_TIMESPAN * 4);

    // Expand old_bits to 256-bit target
    let old_target = target_from_bits(old_bits);
    let old_limbs = u256_from_le_bytes(&old_target);

    // new_target = old_target * clamped / TARGET_TIMESPAN
    // Multiply by clamped (fits in u32), then divide by TARGET_TIMESPAN
    let multiplied = u256_mul_u32(old_limbs, clamped);
    let new_target_limbs = u256_div_u32(multiplied, TARGET_TIMESPAN);
    let new_target = u256_to_le_bytes(new_target_limbs);

    // Cap at max target
    let max_target = target_from_bits(MAX_TARGET_BITS);
    let capped = if u256_gt_bytes(&new_target, &max_target) {
        max_target
    } else {
        new_target
    };

    // Re-encode to compact bits format
    bits_from_target(&capped)
}

/// Return the bits a candidate block must use before accepting it.
///
/// Mainnet retargets on 2016-block boundaries using the previous block's
/// timestamp. Testnet4 keeps the BIP94 epoch base difficulty at boundaries and
/// permits the max-target min-difficulty exception after >20 minutes.
pub fn required_bits_for_next_block(
    testnet4: bool,
    block_height: u64,
    timestamp: u32,
    parent_timestamp: u32,
    epoch_bits: u32,
    epoch_start_time: u32,
) -> u32 {
    if epoch_bits == 0 {
        return 0;
    }

    if block_height.is_multiple_of(BLOCKS_PER_EPOCH) {
        // saturating_sub (not wrapping_sub): an out-of-order epoch boundary timestamp would
        // otherwise underflow to a huge timespan and be clamped to MAX, spuriously easing
        // difficulty. Saturating to 0 clamps to the minimum timespan (hardest) — fail-safe.
        let actual_timespan = parent_timestamp.saturating_sub(epoch_start_time);
        return calculate_new_bits(epoch_bits, actual_timespan);
    }

    // Guard the subtraction: without `timestamp > parent_timestamp` an out-of-order
    // timestamp underflows `wrapping_sub` to a huge value and spuriously trips the
    // testnet4 20-minute min-difficulty exception.
    if testnet4 && timestamp > parent_timestamp && timestamp - parent_timestamp > 20 * 60 {
        return MAX_TARGET_BITS;
    }

    epoch_bits
}

/// Encode a 256-bit LE target back to compact bits format
fn bits_from_target(target: &[u8; 32]) -> u32 {
    // Find the highest non-zero byte
    let mut size = 32;
    while size > 0 && target[size - 1] == 0 {
        size -= 1;
    }
    if size == 0 {
        return 0;
    }

    let mut mantissa: u32;
    if size <= 3 {
        // Read up to 3 bytes from the beginning
        mantissa = 0;
        for i in (0..size).rev() {
            mantissa = (mantissa << 8) | target[i] as u32;
        }
        mantissa <<= 8 * (3 - size);
    } else {
        // Read the top 3 bytes
        mantissa = (target[size - 1] as u32) << 16
            | (target[size - 2] as u32) << 8
            | target[size - 3] as u32;
    }

    // If the sign bit (0x800000) is set, shift right and increase size
    if mantissa & 0x00800000 != 0 {
        mantissa >>= 8;
        size += 1;
    }

    (size as u32) << 24 | (mantissa & 0x007fffff)
}

#[cfg(test)]
mod tests {
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
}
