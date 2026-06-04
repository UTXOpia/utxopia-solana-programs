// --- 256-bit arithmetic helpers (4×u64 limbs, little-endian) ---

pub fn u256_from_le_bytes(bytes: &[u8; 32]) -> [u64; 4] {
    [
        u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
        u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
        u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
        u64::from_le_bytes(bytes[24..32].try_into().unwrap()),
    ]
}

pub fn u256_to_le_bytes(v: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[0..8].copy_from_slice(&v[0].to_le_bytes());
    out[8..16].copy_from_slice(&v[1].to_le_bytes());
    out[16..24].copy_from_slice(&v[2].to_le_bytes());
    out[24..32].copy_from_slice(&v[3].to_le_bytes());
    out
}

pub fn u256_add(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s2, c2) = s1.overflowing_add(carry);
        result[i] = s2;
        carry = (c1 as u64) + (c2 as u64);
    }
    result
}

/// Compare a > b (strictly greater)
pub fn u256_gt_limbs(a: [u64; 4], b: [u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    false // equal
}

/// Compare a >= b
pub fn u256_gte(a: [u64; 4], b: [u64; 4]) -> bool {
    for i in (0..4).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    true // equal
}

pub fn u256_sub(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut result = [0u64; 4];
    let mut borrow = 0u64;
    for i in 0..4 {
        let (s1, c1) = a[i].overflowing_sub(b[i]);
        let (s2, c2) = s1.overflowing_sub(borrow);
        result[i] = s2;
        borrow = (c1 as u64) + (c2 as u64);
    }
    result
}

pub fn u256_shl(v: [u64; 4], shift: u32) -> [u64; 4] {
    if shift >= 256 { return [0; 4]; }
    let limb_shift = (shift / 64) as usize;
    let bit_shift = shift % 64;
    let mut result = [0u64; 4];
    for i in limb_shift..4 {
        result[i] = v[i - limb_shift] << bit_shift;
        if bit_shift > 0 && i > limb_shift {
            result[i] |= v[i - limb_shift - 1] >> (64 - bit_shift);
        }
    }
    result
}

/// Count leading zeros of a 256-bit number
pub fn u256_clz(v: [u64; 4]) -> u32 {
    for i in (0..4).rev() {
        if v[i] != 0 {
            return (3 - i as u32) * 64 + v[i].leading_zeros();
        }
    }
    256
}

/// 256-bit division: a / b (returns quotient only)
pub fn u256_div(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    if b == [0, 0, 0, 0] { return [0; 4]; }
    if !u256_gte(a, b) { return [0; 4]; }

    let a_clz = u256_clz(a);
    let b_clz = u256_clz(b);
    if b_clz < a_clz { return [0; 4]; }

    let shift_max = b_clz - a_clz;
    let mut remainder = a;
    let mut quotient = [0u64; 4];

    for s in (0..=shift_max).rev() {
        let shifted = u256_shl(b, s);
        if u256_gte(remainder, shifted) {
            remainder = u256_sub(remainder, shifted);
            // Set bit s in quotient
            let limb = (s / 64) as usize;
            let bit = s % 64;
            quotient[limb] |= 1u64 << bit;
        }
    }
    quotient
}

/// Multiply 256-bit number by u32
pub fn u256_mul_u32(a: [u64; 4], b: u32) -> [u64; 4] {
    let b = b as u64;
    let mut result = [0u64; 4];
    let mut carry = 0u64;
    for i in 0..4 {
        let product = a[i] as u128 * b as u128 + carry as u128;
        result[i] = product as u64;
        carry = (product >> 64) as u64;
    }
    result
}

/// Divide 256-bit number by u32
pub fn u256_div_u32(a: [u64; 4], b: u32) -> [u64; 4] {
    let b = b as u64;
    let mut result = [0u64; 4];
    let mut remainder = 0u128;
    for i in (0..4).rev() {
        let dividend = (remainder << 64) | a[i] as u128;
        result[i] = (dividend / b as u128) as u64;
        remainder = dividend % b as u128;
    }
    result
}

/// Compare two 256-bit LE byte arrays: a > b
pub fn u256_gt_bytes(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if a[i] > b[i] { return true; }
        if a[i] < b[i] { return false; }
    }
    false
}
