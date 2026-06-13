use super::u256::{u256_add, u256_div, u256_from_le_bytes, u256_to_le_bytes};

/// Check if a hash meets the difficulty target (LE comparison)
pub fn hash_meets_target(hash: &[u8; 32], target: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if hash[i] > target[i] {
            return false;
        }
        if hash[i] < target[i] {
            return true;
        }
    }
    true
}

/// Get difficulty target from compact bits format
pub fn target_from_bits(bits: u32) -> [u8; 32] {
    let mut target = [0u8; 32];
    let exponent = ((bits >> 24) & 0xff) as usize;
    let mantissa = bits & 0x007fffff;

    if exponent <= 3 {
        let shift = 8 * (3 - exponent);
        let value = mantissa >> shift;
        target[0..4].copy_from_slice(&value.to_le_bytes());
    } else {
        let byte_offset = exponent - 3;
        if byte_offset + 3 <= 32 {
            target[byte_offset..byte_offset + 3].copy_from_slice(&mantissa.to_le_bytes()[0..3]);
        }
    }

    target
}

/// Calculate chainwork from difficulty bits: work = 2^256 / (target + 1)
/// Uses 4×u64 limb arithmetic for 256-bit division.
pub fn calculate_chainwork(bits: u32) -> [u8; 32] {
    let target = target_from_bits(bits);

    // target_plus_one = target + 1
    let mut target_plus_one = [0u8; 32];
    let mut carry: u16 = 1;
    for i in 0..32 {
        let sum = target[i] as u16 + carry;
        target_plus_one[i] = sum as u8;
        carry = sum >> 8;
    }

    // If target+1 is zero (overflow), return zero work
    if target_plus_one == [0u8; 32] {
        return [0u8; 32];
    }

    // Compute (~target) / (target + 1) to avoid 2^256 overflow
    // Since 2^256 / (target+1) = (~target / (target+1)) + 1 when target < 2^256 - 1
    let mut not_target = [0u8; 32];
    for i in 0..32 {
        not_target[i] = !target[i];
    }

    // 256-bit division: not_target / target_plus_one using 4×u64 limbs
    let dividend = u256_from_le_bytes(&not_target);
    let divisor = u256_from_le_bytes(&target_plus_one);
    let quotient = u256_div(dividend, divisor);

    // quotient + 1
    let result = u256_add(quotient, [1, 0, 0, 0]);
    u256_to_le_bytes(result)
}

/// Add two 256-bit chainwork values
pub fn add_chainwork(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;

    for i in 0..32 {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }

    result
}
