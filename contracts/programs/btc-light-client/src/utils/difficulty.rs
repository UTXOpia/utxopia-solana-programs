use crate::constants::TARGET_TIMESPAN;
use super::pow::target_from_bits;
use super::u256::{u256_from_le_bytes, u256_to_le_bytes, u256_gt_bytes, u256_mul_u32, u256_div_u32};

/// Maximum target (genesis difficulty) in compact bits format
const MAX_TARGET_BITS: u32 = 0x1d00ffff;

/// Calculate new difficulty bits after a retarget epoch.
/// Matches Bitcoin Core's GetNextWorkRequired algorithm.
pub fn calculate_new_bits(old_bits: u32, actual_timespan: u32) -> u32 {
    // Clamp timespan to [TARGET_TIMESPAN/4, TARGET_TIMESPAN*4]
    let clamped = if actual_timespan < TARGET_TIMESPAN / 4 {
        TARGET_TIMESPAN / 4
    } else if actual_timespan > TARGET_TIMESPAN * 4 {
        TARGET_TIMESPAN * 4
    } else {
        actual_timespan
    };

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
