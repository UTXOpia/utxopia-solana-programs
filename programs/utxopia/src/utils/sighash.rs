//! BIP-341 Taproot key-spend sighash *preimage* reconstruction.
//!
//! Mirrors the backend's `taproot_key_spend_sighash_preimage`
//! (`backend/src/redemption/signer.rs`) byte-for-byte so the on-chain program
//! can re-derive the exact message the Ika dWallet signs and bind redemption
//! approval to the redemption's reserved UTXOs + recipient script. This closes
//! the "unvalidated `btc_sighash`" signing-oracle hole: instead of trusting a
//! caller-supplied sighash, the program reconstructs it.
//!
//! ## Ika semantics
//! Under `SIG_SCHEME_TAPROOT_SHA256`, Ika applies one SHA-256 to the approved
//! message before Schnorr-signing. So the message handed to Ika must be the
//! **tagged TapSighash preimage**, where `sha256(preimage)` equals rust-bitcoin's
//! final BIP-341 key-spend sighash (SIGHASH_DEFAULT). The on-chain
//! `ika_message_digest` the program must match is `keccak256(preimage)`.
//!
//! ## Determinism contract with the backend (`builder.rs`)
//! For the reconstructed sighash to equal the broadcast tx's sighash, the
//! backend MUST construct redemption txs with:
//! - nVersion = 2, nLockTime = 0, per-input nSequence = 0xFFFF_FFFD
//! - inputs ordered by amount descending (canonical), all spending the pool
//!   taproot scriptPubKey `0x5120 || xonly`
//! - output[0] = recipient (`amount_sats - service_fee`, `btc_script`)
//! - output[1] = change to pool spk, present iff `change > DUST (330)`

use crate::utils::bitcoin::{keccak256, sha256};

/// Fixed BIP-341 key-spend preimage length: 64 (tag||tag) + 175 (sigMsg).
pub const TAPROOT_KEYSPEND_PREIMAGE_LEN: usize = 239;

/// A transaction input reference plus its prevout (the spent output).
pub struct SighashInput<'a> {
    /// Txid in internal byte order (as it appears in a raw tx input / as stored
    /// in `UtxoRecord.txid`).
    pub txid: [u8; 32],
    pub vout: u32,
    pub sequence: u32,
    /// Value of the output being spent (satoshis).
    pub amount_sats: u64,
    /// scriptPubKey of the output being spent (for redemption: pool taproot).
    pub script_pubkey: &'a [u8],
}

/// A transaction output.
pub struct SighashOutput<'a> {
    pub amount_sats: u64,
    pub script_pubkey: &'a [u8],
}

/// One reserved pool UTXO: (txid, vout, amount). Used to commit to and then
/// reconstruct the redemption tx's input set deterministically.
#[derive(Clone, Copy)]
pub struct ReservedInput {
    /// Txid in internal byte order (as stored in `UtxoRecord.txid`).
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount_sats: u64,
}

/// Canonical input ordering shared by `mark_processing` (commit) and
/// `approve_redemption_signing` (reconstruct): amount DESCENDING, then txid
/// ascending, then vout ascending. The deterministic tie-break (txid, vout) is
/// REQUIRED — the backend builder must order inputs the same way, else the
/// reconstructed sighash won't match the broadcast tx.
pub fn canonical_sort(items: &mut [ReservedInput]) {
    items.sort_by(|a, b| {
        b.amount_sats
            .cmp(&a.amount_sats)
            .then_with(|| a.txid.cmp(&b.txid))
            .then_with(|| a.vout.cmp(&b.vout))
    });
}

/// Commitment to the canonical-ordered input set:
/// `sha256( for each input: txid(32) || vout(4 LE) || amount(8 LE) )`.
/// Caller must `canonical_sort` first.
pub fn inputs_commitment(ordered: &[ReservedInput]) -> [u8; 32] {
    let mut buf = std::vec::Vec::with_capacity(ordered.len() * 44);
    for it in ordered {
        buf.extend_from_slice(&it.txid);
        buf.extend_from_slice(&it.vout.to_le_bytes());
        buf.extend_from_slice(&it.amount_sats.to_le_bytes());
    }
    sha256(&buf)
}

/// Bitcoin compact-size (varint) encoding. Scripts here are < 0xFD bytes, but we
/// handle the full range to match consensus serialization exactly.
fn push_compact_size(buf: &mut std::vec::Vec<u8>, n: usize) {
    if n < 0xFD {
        buf.push(n as u8);
    } else if n <= 0xFFFF {
        buf.push(0xFD);
        buf.extend_from_slice(&(n as u16).to_le_bytes());
    } else if n <= 0xFFFF_FFFF {
        buf.push(0xFE);
        buf.extend_from_slice(&(n as u32).to_le_bytes());
    } else {
        buf.push(0xFF);
        buf.extend_from_slice(&(n as u64).to_le_bytes());
    }
}

/// Build the 239-byte tagged TapSighash preimage for `input_index`.
///
/// `sha256(returned preimage)` == the BIP-341 key-spend sighash (SIGHASH_DEFAULT)
/// rust-bitcoin would produce for this tx/prevouts/input.
pub fn taproot_keyspend_preimage(
    version: u32,
    locktime: u32,
    inputs: &[SighashInput],
    outputs: &[SighashOutput],
    input_index: u32,
) -> [u8; TAPROOT_KEYSPEND_PREIMAGE_LEN] {
    use std::vec::Vec;

    let mut prevouts_buf = Vec::with_capacity(inputs.len() * 36);
    let mut amounts_buf = Vec::with_capacity(inputs.len() * 8);
    let mut spk_buf = Vec::new();
    let mut seq_buf = Vec::with_capacity(inputs.len() * 4);
    for inp in inputs {
        prevouts_buf.extend_from_slice(&inp.txid);
        prevouts_buf.extend_from_slice(&inp.vout.to_le_bytes());
        amounts_buf.extend_from_slice(&inp.amount_sats.to_le_bytes());
        push_compact_size(&mut spk_buf, inp.script_pubkey.len());
        spk_buf.extend_from_slice(inp.script_pubkey);
        seq_buf.extend_from_slice(&inp.sequence.to_le_bytes());
    }

    let mut out_buf = Vec::new();
    for o in outputs {
        out_buf.extend_from_slice(&o.amount_sats.to_le_bytes());
        push_compact_size(&mut out_buf, o.script_pubkey.len());
        out_buf.extend_from_slice(o.script_pubkey);
    }

    let sha_prevouts = sha256(&prevouts_buf);
    let sha_amounts = sha256(&amounts_buf);
    let sha_spks = sha256(&spk_buf);
    let sha_seqs = sha256(&seq_buf);
    let sha_outputs = sha256(&out_buf);
    let tag = sha256(b"TapSighash");

    let mut p = [0u8; TAPROOT_KEYSPEND_PREIMAGE_LEN];
    let mut o = 0usize;
    let mut put = |o: &mut usize, bytes: &[u8]| {
        p[*o..*o + bytes.len()].copy_from_slice(bytes);
        *o += bytes.len();
    };
    // 64-byte tagged-hash prefix: SHA256("TapSighash") twice.
    put(&mut o, &tag);
    put(&mut o, &tag);
    // sigMsg (175 bytes for key-path, no annex):
    put(&mut o, &[0x00]); // sighash epoch
    put(&mut o, &[0x00]); // hash_type = SIGHASH_DEFAULT
    put(&mut o, &version.to_le_bytes());
    put(&mut o, &locktime.to_le_bytes());
    put(&mut o, &sha_prevouts);
    put(&mut o, &sha_amounts);
    put(&mut o, &sha_spks);
    put(&mut o, &sha_seqs);
    put(&mut o, &sha_outputs);
    put(&mut o, &[0x00]); // spend_type: key-path, no annex
    put(&mut o, &input_index.to_le_bytes());
    debug_assert_eq!(o, TAPROOT_KEYSPEND_PREIMAGE_LEN);
    p
}

/// Final BIP-341 key-spend sighash = `sha256(preimage)`. Equals what Ika derives
/// from the preimage and what `btc_sighash` must be.
pub fn taproot_keyspend_sighash(preimage: &[u8; TAPROOT_KEYSPEND_PREIMAGE_LEN]) -> [u8; 32] {
    sha256(preimage)
}

/// `keccak256(preimage)` — the `ika_message_digest` the approval must match.
pub fn ika_message_digest(preimage: &[u8; TAPROOT_KEYSPEND_PREIMAGE_LEN]) -> [u8; 32] {
    keccak256(preimage)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Ground-truth vectors generated from the backend's own
    // `taproot_key_spend_sighash_preimage` + rust-bitcoin
    // `SighashCache::taproot_key_spend_signature_hash` (oracle), for a 2-input,
    // 2-output redemption-shaped tx:
    //   version=2 locktime=0 seq=0xFFFFFFFD
    //   in0: txid=11..,vout=0,amount=100000,spk=pool   in1: txid=22..,vout=1,amount=50000,spk=pool
    //   out0: 120000 -> dest(0x5120||BB..)   out1: 29000 -> pool(0x5120||AA..)
    fn pool_spk() -> [u8; 34] {
        let mut v = [0xAAu8; 34];
        v[0] = 0x51;
        v[1] = 0x20;
        v
    }
    fn dest_spk() -> [u8; 34] {
        let mut v = [0xBBu8; 34];
        v[0] = 0x51;
        v[1] = 0x20;
        v
    }

    fn hex32(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn matches_backend_and_rustbitcoin() {
        let pool = pool_spk();
        let dest = dest_spk();
        let inputs = [
            SighashInput {
                txid: [0x11; 32],
                vout: 0,
                sequence: 0xFFFF_FFFD,
                amount_sats: 100_000,
                script_pubkey: &pool,
            },
            SighashInput {
                txid: [0x22; 32],
                vout: 1,
                sequence: 0xFFFF_FFFD,
                amount_sats: 50_000,
                script_pubkey: &pool,
            },
        ];
        let outputs = [
            SighashOutput {
                amount_sats: 120_000,
                script_pubkey: &dest,
            },
            SighashOutput {
                amount_sats: 29_000,
                script_pubkey: &pool,
            },
        ];

        // input 0
        let pre0 = taproot_keyspend_preimage(2, 0, &inputs, &outputs, 0);
        assert_eq!(pre0.len(), 239);
        assert_eq!(
            taproot_keyspend_sighash(&pre0),
            hex32("741f7b5822be9747bf87f6289165307f8d2aa0f79ede2d76a6e7da9973248b6e"),
        );
        assert_eq!(
            ika_message_digest(&pre0),
            hex32("5fb4c46677232c49a01a176862c43a9c632db10fc0c3c88445451cc2b938aa1b"),
        );

        // input 1
        let pre1 = taproot_keyspend_preimage(2, 0, &inputs, &outputs, 1);
        assert_eq!(
            taproot_keyspend_sighash(&pre1),
            hex32("e78496e38227bb132f348b9f07498b19832877d8441688b955bd78859036a5bd"),
        );
        assert_eq!(
            ika_message_digest(&pre1),
            hex32("a9da36f088eb1284db2122b2f777e866136bd0edff265c0b91dd6031ef338ffc"),
        );

        // tag-hash sanity: SHA256("TapSighash") is the well-known BIP-341 tag.
        assert_eq!(
            sha256(b"TapSighash"),
            hex32("f40a48df4b2a70c8b4924bf2654661ed3d95fd66a313eb87237597c628e4a031"),
        );
    }
}
