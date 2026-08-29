//! Bitcoin utilities for SPV verification
//!
//! Provides SHA256 hashing and Bitcoin transaction parsing.

use crate::pinocchio_compat::ProgramError;

/// OP_RETURN opcode
pub const OP_RETURN: u8 = 0x6a;

/// Deposit OP_RETURN data size: header(1) + pool_tag(8) + ephemeral_pubkey(32) + note_public_key(32) = 73 bytes
const DEPOSIT_OP_RETURN_SIZE: usize = 73;
const DEPOSIT_HEADER_SOLANA_MAINNET: u8 = 0x50;
const DEPOSIT_HEADER_SOLANA_TESTNET4: u8 = 0x52;
const DEPOSIT_HEADER_SOLANA_REGTEST: u8 = 0x53;

/// Parsed deposit OP_RETURN data.
pub struct DepositOpReturn {
    pub pool_tag: [u8; 8],
    pub ephemeral_pubkey: [u8; 32],
    pub note_public_key: [u8; 32],
}

/// Double SHA256 hash (Bitcoin standard)
/// Uses Solana's native SHA256 syscall for efficiency
pub fn double_sha256(data: &[u8]) -> [u8; 32] {
    let first = sha256(data);
    sha256(&first)
}

/// SHA256 over a compile-time-sized set of non-contiguous byte ranges, as if they
/// were concatenated.
///
/// Uses sol_sha256's multi-chunk form so no intermediate buffer is needed
/// on-chain. The descriptor array is sized from the input itself, avoiding a
/// fixed upper bound that can panic when a caller adds another bound field.
pub fn sha256_parts<const N: usize>(parts: [&[u8]; N]) -> [u8; 32] {
    let mut result = [0u8; 32];

    #[cfg(target_os = "solana")]
    {
        unsafe {
            extern "C" {
                fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
            }
            // sol_sha256 expects an array of (ptr, len) descriptors, one per chunk.
            let mut descs = [[core::ptr::null::<u8>(), core::ptr::null::<u8>()]; N];
            for (i, p) in parts.iter().enumerate() {
                descs[i] = [p.as_ptr(), p.len() as *const u8];
            }
            sol_sha256(descs.as_ptr() as *const u8, N as u64, result.as_mut_ptr());
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        let buf = alloc_concat(&parts);
        result.copy_from_slice(&sha256(&buf));
    }

    result
}

#[cfg(not(target_os = "solana"))]
fn alloc_concat(parts: &[&[u8]]) -> std::vec::Vec<u8> {
    let mut v = std::vec::Vec::new();
    for p in parts {
        v.extend_from_slice(p);
    }
    v
}

/// SHA256 hash using Solana's syscall
pub fn sha256(data: &[u8]) -> [u8; 32] {
    // Solana provides sol_sha256 syscall
    let mut result = [0u8; 32];

    #[cfg(target_os = "solana")]
    {
        // Use Solana's hashv syscall via pinocchio
        // Note: pinocchio uses sol_sha256 internally
        unsafe {
            extern "C" {
                fn sol_sha256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
            }

            // Create the slice descriptor that sol_sha256 expects
            let slice_desc = [data.as_ptr(), data.len() as *const u8];
            sol_sha256(slice_desc.as_ptr() as *const u8, 1, result.as_mut_ptr());
        }
    }

    // Real SHA-256 on every host build, matching `keccak256` below. This used to be `test`-only,
    // with an XOR stub standing in otherwise — a stub that still returns 32 plausible-looking
    // bytes, so txid and merkle verification would quietly "pass" against garbage in any host
    // build that was not a test.
    #[cfg(not(target_os = "solana"))]
    {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        result.copy_from_slice(&hash);
    }

    result
}

/// Keccak-256 hash using Solana's syscall.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];

    #[cfg(target_os = "solana")]
    {
        unsafe {
            extern "C" {
                fn sol_keccak256(vals: *const u8, val_len: u64, hash_result: *mut u8) -> u64;
            }

            let slice_desc = [data.as_ptr(), data.len() as *const u8];
            sol_keccak256(slice_desc.as_ptr() as *const u8, 1, result.as_mut_ptr());
        }
    }

    #[cfg(not(target_os = "solana"))]
    {
        use sha3::{Digest, Keccak256};
        let hash = Keccak256::digest(data);
        result.copy_from_slice(&hash);
    }

    result
}

/// Compute a Bitcoin transaction's canonical txid (double SHA256).
///
/// For SegWit transactions the txid is computed over the LEGACY serialization — version, inputs,
/// outputs, locktime — with the marker, flag, and witness data removed. Hashing the raw bytes of a
/// SegWit tx instead yields the wtxid, which does not match the txid committed in block Merkle
/// roots / SPV proofs. Legacy transactions hash their raw bytes directly.
pub fn compute_tx_hash(raw_tx: &[u8]) -> [u8; 32] {
    match segwit_body_end(raw_tx) {
        Some(body_end) if raw_tx.len() >= body_end + 4 => {
            // version[0..4] ++ (inputs ++ outputs)[6..body_end] ++ locktime[len-4..len]
            let version = &raw_tx[0..4];
            let body = &raw_tx[6..body_end];
            let locktime = &raw_tx[raw_tx.len() - 4..];
            let inner = sha256_parts([version, body, locktime]);
            sha256(&inner)
        }
        // Legacy tx (or unparseable as segwit): hash raw bytes as before.
        _ => double_sha256(raw_tx),
    }
}

/// If `raw_tx` is a SegWit transaction, return the offset at which the outputs end (i.e. where the
/// witness section begins). Returns `None` for legacy transactions or on parse failure, so callers
/// fall back to hashing the raw bytes.
fn segwit_body_end(raw_tx: &[u8]) -> Option<usize> {
    if raw_tx.len() < 10 {
        return None;
    }
    let mut offset = 4;
    // SegWit marker (0x00) + flag (0x01)
    if !(raw_tx[offset] == 0x00 && raw_tx[offset + 1] == 0x01) {
        return None;
    }
    offset += 2;

    let (input_count, vi) = read_varint(raw_tx.get(offset..)?).ok()?;
    if input_count == 0 {
        return None; // not consensus-valid; see the note in TransactionView::parse
    }
    offset += vi;
    for _ in 0..input_count {
        offset += 36; // prev outpoint
        let (script_len, vi) = read_varint(raw_tx.get(offset..)?).ok()?;
        // Checked: a malicious 0xff varint script_len (full u64) could otherwise wrap `offset`
        // backwards so the bounds check below passes and the same region is re-parsed (audit f40).
        offset = offset
            .checked_add(vi)?
            .checked_add(script_len as usize)?
            .checked_add(4)?; // script + sequence
        if offset > raw_tx.len() {
            return None;
        }
    }

    let (output_count, vi) = read_varint(raw_tx.get(offset..)?).ok()?;
    offset += vi;
    for _ in 0..output_count {
        offset += 8; // value
        let (script_len, vi) = read_varint(raw_tx.get(offset..)?).ok()?;
        // Checked add to prevent offset wraparound on a malicious script_len (audit f40).
        offset = offset.checked_add(vi)?.checked_add(script_len as usize)?;
        if offset > raw_tx.len() {
            return None;
        }
    }

    Some(offset)
}

/// Parsed Bitcoin transaction output
pub struct TxOutput<'a> {
    /// Output value in satoshis
    pub value: u64,
    /// Script pubkey (locking script)
    pub script_pubkey: &'a [u8],
}

impl<'a> TxOutput<'a> {
    /// Check if this output is an OP_RETURN
    pub fn is_op_return(&self) -> bool {
        !self.script_pubkey.is_empty() && self.script_pubkey[0] == OP_RETURN
    }

    /// Parse deposit OP_RETURN: exactly 73 bytes = header + pool_tag + ephemeral_pubkey + note_public_key.
    /// Handles both direct push (0x6a 0x49 <73 bytes>) and PUSHDATA1 (0x6a 0x4c 0x49 <73 bytes>)
    pub fn get_deposit_op_return(&self) -> Option<DepositOpReturn> {
        if !self.is_op_return() || self.script_pubkey.len() < 2 {
            return None;
        }

        let data_slice = if self.script_pubkey.len() == 2 + DEPOSIT_OP_RETURN_SIZE
            && self.script_pubkey[1] == DEPOSIT_OP_RETURN_SIZE as u8
        {
            &self.script_pubkey[2..2 + DEPOSIT_OP_RETURN_SIZE]
        } else if self.script_pubkey.len() == 3 + DEPOSIT_OP_RETURN_SIZE
            && self.script_pubkey[1] == 0x4c
            && self.script_pubkey[2] == DEPOSIT_OP_RETURN_SIZE as u8
        {
            &self.script_pubkey[3..3 + DEPOSIT_OP_RETURN_SIZE]
        } else {
            return None;
        };

        match data_slice[0] {
            DEPOSIT_HEADER_SOLANA_MAINNET
            | DEPOSIT_HEADER_SOLANA_TESTNET4
            | DEPOSIT_HEADER_SOLANA_REGTEST => {}
            _ => return None,
        }

        let mut pool_tag = [0u8; 8];
        let mut ephemeral_pubkey = [0u8; 32];
        let mut note_public_key = [0u8; 32];
        pool_tag.copy_from_slice(&data_slice[1..9]);
        ephemeral_pubkey.copy_from_slice(&data_slice[9..41]);
        note_public_key.copy_from_slice(&data_slice[41..73]);

        Some(DepositOpReturn {
            pool_tag,
            ephemeral_pubkey,
            note_public_key,
        })
    }
}

/// Parsed Bitcoin transaction (minimal, zero-copy where possible)
pub struct ParsedTransaction<'a> {
    /// Raw inputs data slice
    inputs_data: &'a [u8],
    /// Input count
    input_count: usize,
    /// Raw outputs data slice
    outputs_data: &'a [u8],
    /// Output count
    output_count: usize,
}

impl<'a> ParsedTransaction<'a> {
    /// Parse a raw Bitcoin transaction
    /// Returns parsed transaction with references to output data
    pub fn parse(raw_tx: &'a [u8]) -> Result<Self, ProgramError> {
        if raw_tx.len() < 10 {
            return Err(ProgramError::InvalidInstructionData);
        }

        let mut offset = 4;

        // Check for segwit marker
        let is_segwit =
            raw_tx.len() > offset + 2 && raw_tx[offset] == 0x00 && raw_tx[offset + 1] == 0x01;

        if is_segwit {
            offset += 2;
        }

        // Input count (varint)
        let (input_count, varint_size) = read_varint(&raw_tx[offset..])?;
        // No consensus-valid transaction has zero inputs; rust-bitcoin rejects these and so must
        // we, or a 0-input blob parses cleanly and can be presented as a "transaction" whose
        // txid nothing else constrains. See `parse_rejects_zero_input_transaction`.
        if input_count == 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
        offset += varint_size;

        // Remember where inputs start
        let inputs_start = offset;

        // Skip inputs
        for _ in 0..input_count {
            // Previous output (32 + 4 bytes)
            offset += 36;
            if offset > raw_tx.len() {
                return Err(ProgramError::InvalidInstructionData);
            }

            // Script length (varint)
            let (script_len, varint_size) = read_varint(&raw_tx[offset..])?;
            // Checked for the same reason `segwit_body_end` is: a 0xff varint carries a full
            // u64, which would wrap `offset` backwards so the bounds check below passes and
            // the same region is re-parsed. Today `overflow-checks` catches it, but that lives
            // in Cargo.toml, not here (audit_2 N-8).
            offset = offset
                .checked_add(varint_size)
                .and_then(|o| o.checked_add(script_len as usize))
                .and_then(|o| o.checked_add(4)) // script + sequence
                .ok_or(ProgramError::InvalidInstructionData)?;

            if offset > raw_tx.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
        }

        let inputs_end = offset;

        // Output count (varint)
        let (output_count, varint_size) = read_varint(&raw_tx[offset..])?;
        offset += varint_size;

        // Remember where outputs start
        let outputs_start = offset;

        // Skip outputs to find end
        for _ in 0..output_count {
            offset += 8; // value
            if offset > raw_tx.len() {
                return Err(ProgramError::InvalidInstructionData);
            }

            let (script_len, varint_size) = read_varint(&raw_tx[offset..])?;
            offset = offset
                .checked_add(varint_size)
                .and_then(|o| o.checked_add(script_len as usize))
                .ok_or(ProgramError::InvalidInstructionData)?;

            if offset > raw_tx.len() {
                return Err(ProgramError::InvalidInstructionData);
            }
        }

        Ok(Self {
            inputs_data: &raw_tx[inputs_start..inputs_end],
            input_count: input_count as usize,
            outputs_data: &raw_tx[outputs_start..offset],
            output_count: output_count as usize,
        })
    }

    /// Iterate over outputs
    pub fn outputs(&self) -> OutputIterator<'a> {
        OutputIterator {
            data: self.outputs_data,
            offset: 0,
            remaining: self.output_count,
        }
    }

    /// Sum all output values in the transaction
    pub fn sum_outputs(&self) -> u64 {
        self.outputs()
            .fold(0u64, |total, output| total.saturating_add(output.value))
    }

    /// Find deposit output (non-OP_RETURN with value > 0)
    pub fn find_deposit_output(&self) -> Option<TxOutput<'a>> {
        self.outputs()
            .find(|output| !output.is_op_return() && output.value > 0)
    }

    /// Find deposit output with its vout index (non-OP_RETURN with value > 0)
    pub fn find_deposit_output_with_vout(&self) -> Option<(TxOutput<'a>, u32)> {
        self.outputs()
            .enumerate()
            .find(|(_, output)| !output.is_op_return() && output.value > 0)
            .map(|(i, output)| (output, i as u32))
    }

    /// Find output matching a given scriptPubKey, returning (output, vout_index)
    pub fn find_output_by_script(&self, script: &[u8]) -> Option<(TxOutput<'a>, u32)> {
        self.outputs()
            .enumerate()
            .find(|(_, output)| output.script_pubkey == script)
            .map(|(i, output)| (output, i as u32))
    }

    /// Count positive-value outputs matching a given scriptPubKey.
    pub fn positive_output_count_by_script(&self, script: &[u8]) -> usize {
        self.outputs()
            .filter(|output| output.value > 0 && output.script_pubkey == script)
            .count()
    }

    /// Find deposit OP_RETURN (73-byte v1 payload) from outputs.
    pub fn find_deposit_op_return(&self) -> Option<DepositOpReturn> {
        self.outputs()
            .find_map(|output| output.get_deposit_op_return())
    }

    /// Iterate over inputs
    pub fn inputs(&self) -> InputIterator<'a> {
        InputIterator {
            data: self.inputs_data,
            offset: 0,
            remaining: self.input_count,
        }
    }

    pub fn input_count(&self) -> usize {
        self.input_count
    }

    /// Check if any input spends exactly the given previous outpoint.
    ///
    /// Deposit verification must bind the credited deposit output to the sweep
    /// input. A txid-only check is not enough because a Bitcoin transaction may
    /// contain multiple outputs.
    pub fn find_input_with_prev_outpoint(&self, target_txid: &[u8; 32], target_vout: u32) -> bool {
        self.inputs()
            .any(|input| &input.prev_txid == target_txid && input.prev_vout == target_vout)
    }
}

/// Iterator over transaction outputs
pub struct OutputIterator<'a> {
    data: &'a [u8],
    offset: usize,
    remaining: usize,
}

impl<'a> Iterator for OutputIterator<'a> {
    type Item = TxOutput<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.offset + 8 > self.data.len() {
            return None;
        }

        let value = u64::from_le_bytes(self.data[self.offset..self.offset + 8].try_into().ok()?);
        self.offset += 8;

        let (script_len, varint_size) = read_varint(&self.data[self.offset..]).ok()?;
        self.offset += varint_size;

        let script_end = self.offset.checked_add(script_len as usize)?;
        if script_end > self.data.len() {
            return None;
        }

        let script_pubkey = &self.data[self.offset..script_end];
        self.offset = script_end;
        self.remaining -= 1;

        Some(TxOutput {
            value,
            script_pubkey,
        })
    }
}

/// Parsed Bitcoin transaction input
pub struct TxInput {
    /// Previous transaction hash (internal byte order)
    pub prev_txid: [u8; 32],
    /// Previous output index
    pub prev_vout: u32,
}

/// Iterator over transaction inputs
pub struct InputIterator<'a> {
    data: &'a [u8],
    offset: usize,
    remaining: usize,
}

impl<'a> Iterator for InputIterator<'a> {
    type Item = TxInput;

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.offset + 36 > self.data.len() {
            return None;
        }

        // Previous txid (32 bytes)
        let mut prev_txid = [0u8; 32];
        prev_txid.copy_from_slice(&self.data[self.offset..self.offset + 32]);
        self.offset += 32;

        // Previous vout (4 bytes)
        let prev_vout =
            u32::from_le_bytes(self.data[self.offset..self.offset + 4].try_into().ok()?);
        self.offset += 4;

        // Script length (varint) + script + sequence (4)
        let (script_len, varint_size) = read_varint(&self.data[self.offset..]).ok()?;
        self.offset = self
            .offset
            .checked_add(varint_size)?
            .checked_add(script_len as usize)?
            .checked_add(4)?;

        if self.offset > self.data.len() {
            return None;
        }

        self.remaining -= 1;

        Some(TxInput {
            prev_txid,
            prev_vout,
        })
    }
}

/// Read a Bitcoin varint
fn read_varint(data: &[u8]) -> Result<(u64, usize), ProgramError> {
    if data.is_empty() {
        return Err(ProgramError::InvalidInstructionData);
    }

    match data[0] {
        0..=0xfc => Ok((data[0] as u64, 1)),
        0xfd => {
            if data.len() < 3 {
                return Err(ProgramError::InvalidInstructionData);
            }
            Ok((u16::from_le_bytes(data[1..3].try_into().unwrap()) as u64, 3))
        }
        0xfe => {
            if data.len() < 5 {
                return Err(ProgramError::InvalidInstructionData);
            }
            Ok((u32::from_le_bytes(data[1..5].try_into().unwrap()) as u64, 5))
        }
        0xff => {
            if data.len() < 9 {
                return Err(ProgramError::InvalidInstructionData);
            }
            Ok((u64::from_le_bytes(data[1..9].try_into().unwrap()), 9))
        }
    }
}

#[cfg(test)]
mod txid_tests {
    use super::*;

    #[test]
    fn parse_rejects_zero_input_transaction() {
        // version(4) | vin_count = 0 | vout_count = 0 | locktime(4). Structurally well-formed
        // and consensus-invalid; rust-bitcoin rejects it, so this parser must too.
        let mut raw = Vec::new();
        raw.extend_from_slice(&1u32.to_le_bytes());
        raw.push(0); // vin_count
        raw.push(0); // vout_count
        raw.extend_from_slice(&0u32.to_le_bytes());

        assert!(ParsedTransaction::parse(&raw).is_err());
    }

    /// A `0xff` varint carries a full u64, so `offset + varint + script_len + 4` wraps to a
    /// small value and the `offset > raw_tx.len()` guard below it passes — the parser then
    /// re-reads the same region as if it were a later field. `segwit_body_end` was hardened
    /// against this (F-BTC-06); these four sites were not (audit_2 N-8).
    ///
    /// Before the fix this panics under `overflow-checks` rather than returning, so the test
    /// fails either way — which is the point: the invariant was living in Cargo.toml.
    #[test]
    fn parse_rejects_an_overflowing_script_length() {
        for site in ["input", "output"] {
            let mut raw = Vec::new();
            raw.extend_from_slice(&1u32.to_le_bytes()); // version
            raw.push(1); // vin_count
            raw.extend_from_slice(&[0u8; 32]); // prev txid
            raw.extend_from_slice(&0u32.to_le_bytes()); // prev vout
            if site == "input" {
                raw.push(0xff); // script_len varint: next 8 bytes are a u64
                raw.extend_from_slice(&u64::MAX.to_le_bytes());
            } else {
                raw.push(0); // empty input script
                raw.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
                raw.push(1); // vout_count
                raw.extend_from_slice(&0u64.to_le_bytes()); // value
                raw.push(0xff);
                raw.extend_from_slice(&u64::MAX.to_le_bytes());
            }
            assert!(
                ParsedTransaction::parse(&raw).is_err(),
                "{site} script_len overflow must be rejected, not wrapped"
            );
        }
    }

    #[test]
    fn sha256_is_a_real_digest_on_host_builds() {
        // Guards the removed XOR stub: it was order-insensitive per 32-byte lane, so these two
        // inputs collided under it while differing under SHA-256.
        assert_ne!(sha256(&[1u8, 2]), sha256(&[2u8, 1]));
        // NIST vector for "abc".
        assert_eq!(
            sha256(b"abc")[..4],
            [0xba, 0x78, 0x16, 0xbf],
            "sha256 must be a genuine digest on host builds"
        );
    }

    #[test]
    fn hashes_six_non_contiguous_parts_without_a_fixed_descriptor_limit() {
        let parts: [&[u8]; 6] = [
            b"utxopia-policy-request-v1",
            &[1u8; 32],
            &[2u8; 32],
            &[3u8; 32],
            &[23],
            b"permissioned-shield-payload",
        ];
        let expected = sha256(&parts.concat());
        assert_eq!(sha256_parts(parts), expected);
    }

    // Build a 1-in/1-out transaction body shared by the legacy and segwit encodings.
    // version(4) | [marker|flag] | vin_count | input(prevout36 + scriptlen + script + seq4)
    //   | vout_count | output(value8 + scriptlen + script) | [witness] | locktime(4)
    fn parts() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let version = vec![2u8, 0, 0, 0];
        let mut vin = vec![1u8]; // 1 input
        vin.extend_from_slice(&[0x11u8; 32]); // prev txid
        vin.extend_from_slice(&[0u8; 4]); // prev vout
        vin.push(0); // empty scriptSig (segwit)
        vin.extend_from_slice(&[0xffu8; 4]); // sequence
        let mut vout = vec![1u8]; // 1 output
        vout.extend_from_slice(&50_000u64.to_le_bytes());
        let spk = vec![0x51u8, 0x20, 0xAA]; // dummy-ish script (len 3 via varint below)
        vout.push(spk.len() as u8);
        vout.extend_from_slice(&spk);
        let locktime = vec![0u8; 4];
        ([version, vin, vout].concat(), locktime, {
            // a witness: 1 stack item of 4 bytes
            vec![0x01, 0x04, 0xde, 0xad, 0xbe, 0xef]
        })
    }

    #[test]
    fn segwit_txid_matches_legacy_serialization() {
        let (body, locktime, witness) = parts();

        // Legacy serialization = body || locktime
        let mut legacy = body.clone();
        legacy.extend_from_slice(&locktime);

        // Segwit serialization = version || 0x00 0x01 || vin || vout || witness || locktime
        let mut segwit = Vec::new();
        segwit.extend_from_slice(&body[0..4]); // version
        segwit.extend_from_slice(&[0x00, 0x01]); // marker+flag
        segwit.extend_from_slice(&body[4..]); // vin + vout
        segwit.extend_from_slice(&witness);
        segwit.extend_from_slice(&locktime);

        let legacy_txid = compute_tx_hash(&legacy);
        let segwit_txid = compute_tx_hash(&segwit);

        // The canonical txid of the segwit tx must equal the legacy serialization's hash,
        // i.e. the witness/marker/flag are excluded.
        assert_eq!(legacy_txid, segwit_txid);

        // And it must NOT equal the wtxid (raw double-sha of the full segwit bytes).
        assert_ne!(segwit_txid, double_sha256(&segwit));
    }

    #[test]
    fn counts_positive_outputs_matching_script() {
        let script = vec![0x51u8, 0x20, 0xAA];
        let other = vec![0x51u8, 0x20, 0xBB];
        let mut tx = Vec::new();
        tx.extend_from_slice(&2u32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&[0x11u8; 32]);
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.push(0);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        tx.push(4);
        for (value, spk) in [
            (50_000u64, script.as_slice()),
            (0u64, script.as_slice()),
            (25_000u64, other.as_slice()),
            (10_000u64, script.as_slice()),
        ] {
            tx.extend_from_slice(&value.to_le_bytes());
            tx.push(spk.len() as u8);
            tx.extend_from_slice(spk);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());

        let parsed = ParsedTransaction::parse(&tx).unwrap();
        assert_eq!(parsed.positive_output_count_by_script(&script), 2);
        assert_eq!(parsed.positive_output_count_by_script(&other), 1);
    }
}
