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

/// Key-spend preimage plus the BIP-342 tapleaf extension:
/// `leaf_hash(32) || key_version(1) || codesep_pos(4)`.
pub const TAPROOT_SCRIPTSPEND_PREIMAGE_LEN: usize = TAPROOT_KEYSPEND_PREIMAGE_LEN + 37;

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
    /// Set when this UTXO is a tweak-bound deposit output rather than a coin at
    /// the pool script. Its tapleaf determines both the scriptPubKey that goes
    /// into the sighash and the leaf the signature commits to.
    pub leaf_commitment: Option<[u8; 32]>,
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

/// The five per-transaction midstate hashes both spend paths share.
struct SighashMidstate {
    prevouts: [u8; 32],
    amounts: [u8; 32],
    script_pubkeys: [u8; 32],
    sequences: [u8; 32],
    outputs: [u8; 32],
    tag: [u8; 32],
}

fn sighash_midstate(inputs: &[SighashInput], outputs: &[SighashOutput]) -> SighashMidstate {
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

    SighashMidstate {
        prevouts: sha256(&prevouts_buf),
        amounts: sha256(&amounts_buf),
        script_pubkeys: sha256(&spk_buf),
        sequences: sha256(&seq_buf),
        outputs: sha256(&out_buf),
        tag: sha256(b"TapSighash"),
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
    let m = sighash_midstate(inputs, outputs);

    let mut p = [0u8; TAPROOT_KEYSPEND_PREIMAGE_LEN];
    let mut o = 0usize;
    let mut put = |o: &mut usize, bytes: &[u8]| {
        p[*o..*o + bytes.len()].copy_from_slice(bytes);
        *o += bytes.len();
    };
    // 64-byte tagged-hash prefix: SHA256("TapSighash") twice.
    put(&mut o, &m.tag);
    put(&mut o, &m.tag);
    // sigMsg (175 bytes for key-path, no annex):
    put(&mut o, &[0x00]); // sighash epoch
    put(&mut o, &[0x00]); // hash_type = SIGHASH_DEFAULT
    put(&mut o, &version.to_le_bytes());
    put(&mut o, &locktime.to_le_bytes());
    put(&mut o, &m.prevouts);
    put(&mut o, &m.amounts);
    put(&mut o, &m.script_pubkeys);
    put(&mut o, &m.sequences);
    put(&mut o, &m.outputs);
    put(&mut o, &[0x00]); // spend_type: key-path, no annex
    put(&mut o, &input_index.to_le_bytes());
    debug_assert_eq!(o, TAPROOT_KEYSPEND_PREIMAGE_LEN);
    p
}

/// Build the tagged TapSighash preimage for a BIP-342 script-path spend.
///
/// Deposit UTXOs are spent this way: their key path is a NUMS point and the
/// pool's dWallet key lives in a tapleaf, because Ika's MPC cannot sign for a
/// tweaked key. The preimage differs from the key-path one in exactly two
/// places — `spend_type` gains the tapleaf bit, and the leaf is committed to at
/// the end — and getting either wrong means approving a digest Bitcoin never
/// checks.
pub fn taproot_scriptspend_preimage(
    version: u32,
    locktime: u32,
    inputs: &[SighashInput],
    outputs: &[SighashOutput],
    input_index: u32,
    leaf_hash: &[u8; 32],
) -> [u8; TAPROOT_SCRIPTSPEND_PREIMAGE_LEN] {
    let m = sighash_midstate(inputs, outputs);

    let mut p = [0u8; TAPROOT_SCRIPTSPEND_PREIMAGE_LEN];
    let mut o = 0usize;
    let mut put = |o: &mut usize, bytes: &[u8]| {
        p[*o..*o + bytes.len()].copy_from_slice(bytes);
        *o += bytes.len();
    };
    put(&mut o, &m.tag);
    put(&mut o, &m.tag);
    put(&mut o, &[0x00]); // sighash epoch
    put(&mut o, &[0x00]); // hash_type = SIGHASH_DEFAULT
    put(&mut o, &version.to_le_bytes());
    put(&mut o, &locktime.to_le_bytes());
    put(&mut o, &m.prevouts);
    put(&mut o, &m.amounts);
    put(&mut o, &m.script_pubkeys);
    put(&mut o, &m.sequences);
    put(&mut o, &m.outputs);
    put(&mut o, &[0x02]); // spend_type: tapleaf committed, no annex
    put(&mut o, &input_index.to_le_bytes());
    // BIP-342 tapleaf extension.
    put(&mut o, leaf_hash);
    put(&mut o, &[0x00]); // key_version
    put(&mut o, &0xffff_ffffu32.to_le_bytes()); // no OP_CODESEPARATOR
    debug_assert_eq!(o, TAPROOT_SCRIPTSPEND_PREIMAGE_LEN);
    p
}

/// Final BIP-341 key-spend sighash = `sha256(preimage)`. Equals what Ika derives
/// from the preimage and what `btc_sighash` must be.
/// Takes a slice, not a fixed array: key-path and script-path preimages differ in
/// length and both hash the same way.
pub fn taproot_keyspend_sighash(preimage: &[u8]) -> [u8; 32] {
    sha256(preimage)
}

/// `keccak256(preimage)` — the `ika_message_digest` the approval must match.
pub fn ika_message_digest(preimage: &[u8]) -> [u8; 32] {
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

#[cfg(test)]
mod scriptspend_tests {
    use super::*;

    /// A redemption may spend pool coins and deposit coins in the same transaction.
    /// BIP-341 hashes EVERY input's scriptPubKey into the sighash, so reusing the
    /// pool script for a deposit input produces a digest that does not match the
    /// transaction being signed — the approval succeeds and the broadcast fails.
    #[test]
    fn each_input_contributes_its_own_script_pubkey() {
        static POOL_SPK: [u8; 34] = {
            let mut s = [0x77u8; 34];
            s[0] = 0x51;
            s[1] = 0x20;
            s
        };
        static DEPOSIT_SPK: [u8; 34] = {
            let mut s = [0x88u8; 34];
            s[0] = 0x51;
            s[1] = 0x20;
            s
        };
        static SPK_OUT: [u8; 34] = {
            let mut s = [0xaau8; 34];
            s[0] = 0x51;
            s[1] = 0x20;
            s
        };

        let outputs = std::vec![SighashOutput {
            amount_sats: 90_000,
            script_pubkey: &SPK_OUT,
        }];
        let mk = |second: &'static [u8]| {
            std::vec![
                SighashInput {
                    txid: [0x11u8; 32],
                    vout: 0,
                    sequence: 0xffff_fffd,
                    amount_sats: 50_000,
                    script_pubkey: &POOL_SPK,
                },
                SighashInput {
                    txid: [0x22u8; 32],
                    vout: 1,
                    sequence: 0xffff_fffd,
                    amount_sats: 50_000,
                    script_pubkey: second,
                },
            ]
        };

        let honest = taproot_scriptspend_preimage(2, 0, &mk(&DEPOSIT_SPK), &outputs, 1, &[0xADu8; 32]);
        let wrong = taproot_scriptspend_preimage(2, 0, &mk(&POOL_SPK), &outputs, 1, &[0xADu8; 32]);
        assert_ne!(sha256(&honest), sha256(&wrong));
    }

    fn fixture() -> (std::vec::Vec<SighashInput<'static>>, std::vec::Vec<SighashOutput<'static>>) {
        static SPK_IN: [u8; 34] = {
            let mut s = [0xfeu8; 34];
            s[0] = 0x51;
            s[1] = 0x20;
            s
        };
        static SPK_OUT: [u8; 34] = {
            let mut s = [0xaau8; 34];
            s[0] = 0x51;
            s[1] = 0x20;
            s
        };
        (
            std::vec![SighashInput {
                txid: [0x11u8; 32],
                vout: 0,
                sequence: 0xffff_fffd,
                amount_sats: 50_000,
                script_pubkey: &SPK_IN,
            }],
            std::vec![SighashOutput {
                amount_sats: 45_000,
                script_pubkey: &SPK_OUT,
            }],
        )
    }

    /// Ika signs the preimage; Bitcoin verifies `sha256(preimage)`. A byte wrong
    /// in the BIP-342 extension means the pool approves a digest the network
    /// never checks — the sweep is simply rejected, with nothing readable to say
    /// why. Both vectors come from an independent implementation of BIP-341/342.
    #[test]
    fn preimages_match_independent_bip341_vectors() {
        let (inputs, outputs) = fixture();

        let key = taproot_keyspend_preimage(2, 0, &inputs, &outputs, 0);
        assert_eq!(key.len(), 239);
        assert_eq!(
            sha256(&key),
            [
                0xca, 0xcd, 0xb6, 0x49, 0x0e, 0x45, 0x4a, 0xd3, 0x8b, 0xd9, 0x76, 0xe5, 0x27, 0x27,
                0xb3, 0x76, 0xc4, 0x56, 0x8d, 0x95, 0xa5, 0x56, 0xf5, 0x9c, 0xc8, 0x41, 0xc0, 0x87,
                0x70, 0x7b, 0x81, 0xf0,
            ]
        );

        let script = taproot_scriptspend_preimage(2, 0, &inputs, &outputs, 0, &[0xADu8; 32]);
        assert_eq!(script.len(), 276);
        assert_eq!(
            sha256(&script),
            [
                0x1d, 0xaf, 0x3d, 0x3e, 0x6f, 0xde, 0x78, 0x28, 0x08, 0x4a, 0x06, 0x13, 0xc2, 0x00,
                0xa0, 0x64, 0x48, 0x96, 0xd3, 0xc1, 0xef, 0xdb, 0x23, 0x8c, 0xd7, 0x3d, 0x4a, 0xe5,
                0x5c, 0x89, 0x88, 0xa9,
            ]
        );
    }

    /// The two paths must never produce the same digest: an approval for one
    /// would otherwise authorise the other, and the key path of a deposit address
    /// is a NUMS point nobody should be able to spend through.
    #[test]
    fn the_two_spend_paths_never_share_a_digest() {
        let (inputs, outputs) = fixture();

        let key = taproot_keyspend_preimage(2, 0, &inputs, &outputs, 0);
        let script = taproot_scriptspend_preimage(2, 0, &inputs, &outputs, 0, &[0xADu8; 32]);
        assert_ne!(sha256(&key), sha256(&script));

        // 64 (tag twice) + 2 (epoch, hash_type) + 8 (version, locktime) + 160
        // (five midstate hashes) = 234, where spend_type sits. Everything before
        // it is shared; the leaf is what diverges.
        const SPEND_TYPE: usize = 234;
        assert_eq!(key[..SPEND_TYPE], script[..SPEND_TYPE]);
        assert_eq!(key[SPEND_TYPE], 0x00, "key path");
        assert_eq!(script[SPEND_TYPE], 0x02, "tapleaf committed");
    }

    #[test]
    fn a_different_leaf_is_a_different_digest() {
        let (inputs, outputs) = fixture();
        let a = taproot_scriptspend_preimage(2, 0, &inputs, &outputs, 0, &[0xADu8; 32]);
        let b = taproot_scriptspend_preimage(2, 0, &inputs, &outputs, 0, &[0xAEu8; 32]);
        assert_ne!(sha256(&a), sha256(&b));
    }
}
