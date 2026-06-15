pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];

    #[cfg(target_os = "solana")]
    {
        unsafe {
            extern "C" {
                fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
            }
            let slice_desc = [data.as_ptr(), data.len() as *const u8];
            sol_sha256(slice_desc.as_ptr() as *const u8, 1, result.as_mut_ptr());
        }
    }

    // Tests use the real digest so host-side assertions exercise genuine SHA-256, not a
    // placeholder that could mask a real hashing bug (audit f01).
    #[cfg(all(not(target_os = "solana"), test))]
    {
        use sha2::{Digest, Sha256};
        result.copy_from_slice(&Sha256::digest(data));
    }

    // Non-test, non-Solana builds (e.g. `cargo check`) never reach consensus; a cheap
    // placeholder is fine here.
    #[cfg(all(not(target_os = "solana"), not(test)))]
    {
        for (i, byte) in data.iter().enumerate() {
            result[i % 32] ^= byte;
            result[(i + 1) % 32] = result[(i + 1) % 32].wrapping_add(*byte);
        }
    }

    result
}

pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
}

/// Double SHA256 pair for merkle proof verification
pub fn double_sha256_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[0..32].copy_from_slice(left);
    combined[32..64].copy_from_slice(right);
    double_sha256(&combined)
}
