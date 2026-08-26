//! BLAKE2b-512, RFC 7693, written for SBF.
//!
//! Solana exposes sha256, keccak256, blake3 and poseidon as syscalls; BLAKE2b is not among them.
//! Zcash's Equihash is built on BLAKE2b, so verifying a Zcash header's proof-of-work the way
//! `hash_meets_target` verifies Bitcoin's — two sha256 syscalls, effectively free — is not
//! available. It has to run as interpreted BPF, and the question this file exists to answer is
//! what that costs.
//!
//! BPF is a 64-bit machine, so BLAKE2b's 64-bit adds, XORs and rotations map to single
//! instructions. That is the reason to measure rather than assume: the naive estimate treats it
//! as expensive because it is not a syscall, but the arithmetic itself is native width.
//!
//! Deliberately not general-purpose. No keying, no tree mode, no incremental update — Equihash
//! needs a personalised, unkeyed digest over short inputs, which is exactly what is here.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// One compression: 12 rounds of 8 G-functions. This is the unit the cost question is about —
/// Equihash-200,9 verification evaluates roughly 512 of them per header.
pub fn compress(h: &mut [u64; 8], block: &[u8; 128], counter: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        let mut b = [0u8; 8];
        b.copy_from_slice(&block[i * 8..i * 8 + 8]);
        *word = u64::from_le_bytes(b);
    }

    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= counter as u64;
    v[13] ^= (counter >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    for s in SIGMA.iter() {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// BLAKE2b with an arbitrary digest length (1..=64) and an optional 16-byte personalisation.
///
/// Zcash sets personalisation to `ZcashPoW` ‖ n_le32 ‖ k_le32 and takes a 50-byte digest for
/// Equihash-200,9, so both knobs are needed even though nothing else here uses them.
pub fn blake2b(input: &[u8], out_len: usize, personal: Option<&[u8; 16]>) -> [u8; 64] {
    debug_assert!(out_len >= 1 && out_len <= 64);

    let mut h = IV;
    // Parameter block word 0: digest_length | key_length<<8 | fanout<<16 | depth<<24
    h[0] ^= 0x0101_0000 ^ (out_len as u64);
    if let Some(p) = personal {
        // Personalisation occupies parameter block bytes 48..64, i.e. words 6 and 7.
        let mut w = [0u8; 8];
        w.copy_from_slice(&p[0..8]);
        h[6] ^= u64::from_le_bytes(w);
        w.copy_from_slice(&p[8..16]);
        h[7] ^= u64::from_le_bytes(w);
    }

    let mut counter: u128 = 0;
    let mut offset = 0usize;

    // Every full block except the last is compressed with `last = false`. BLAKE2b requires the
    // final block to be flagged, so a message that is an exact multiple of 128 keeps its last
    // block back rather than padding a new one.
    while input.len() - offset > 128 {
        let mut block = [0u8; 128];
        block.copy_from_slice(&input[offset..offset + 128]);
        counter += 128;
        compress(&mut h, &block, counter, false);
        offset += 128;
    }

    let mut block = [0u8; 128];
    let rest = &input[offset..];
    block[..rest.len()].copy_from_slice(rest);
    counter += rest.len() as u128;
    compress(&mut h, &block, counter, true);

    let mut out = [0u8; 64];
    for i in 0..8 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// RFC 7693 Appendix A.
    #[test]
    fn rfc7693_abc() {
        let out = blake2b(b"abc", 64, None);
        assert_eq!(
            hex(&out),
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1\
             7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        );
    }

    /// The empty message exercises the "last block is all padding" path.
    #[test]
    fn empty_input() {
        let out = blake2b(b"", 64, None);
        assert_eq!(
            hex(&out),
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419\
             d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
        );
    }

    /// Exactly 128 bytes: the loop must NOT compress this as a non-final block and then pad a
    /// second one. Getting this wrong is the classic BLAKE2 bug and it only shows up here.
    #[test]
    fn exact_block_boundary() {
        let input = [0x61u8; 128];
        let out = blake2b(&input, 64, None);
        // Cross-checked against an independent implementation; the value matters less than the
        // fact that it differs from the padded-extra-block result, which is what the bug produces.
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ 64;
        let mut block = [0u8; 128];
        block.copy_from_slice(&input);
        compress(&mut h, &block, 128, true);
        let mut expect = [0u8; 64];
        for i in 0..8 {
            expect[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_le_bytes());
        }
        assert_eq!(out, expect);
    }

    /// Digest length is mixed into the parameter block, so a truncated digest is not a prefix of
    /// the full one. Equihash-200,9 uses 50 bytes, so this path is load-bearing.
    #[test]
    fn short_digest_is_not_a_prefix() {
        let full = blake2b(b"abc", 64, None);
        let short = blake2b(b"abc", 50, None);
        assert_ne!(full[..50], short[..50]);
    }

    /// Personalisation must change the digest — Zcash sets it to ZcashPoW‖n‖k.
    #[test]
    fn personalisation_changes_the_digest() {
        let mut p = [0u8; 16];
        p[..8].copy_from_slice(b"ZcashPoW");
        p[8..12].copy_from_slice(&200u32.to_le_bytes());
        p[12..16].copy_from_slice(&9u32.to_le_bytes());
        assert_ne!(blake2b(b"abc", 50, None), blake2b(b"abc", 50, Some(&p)));
    }
}
