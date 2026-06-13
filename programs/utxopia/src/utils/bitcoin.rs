//! Bitcoin utilities for SPV verification
//!
//! Provides SHA256 hashing and Bitcoin transaction parsing.

use pinocchio::program_error::ProgramError;

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

    #[cfg(all(not(target_os = "solana"), test))]
    {
        use sha2::{Digest, Sha256};
        let hash = Sha256::digest(data);
        result.copy_from_slice(&hash);
    }

    #[cfg(all(not(target_os = "solana"), not(test)))]
    {
        // Fallback XOR hash for non-test, non-Solana builds (e.g. cargo check)
        for (i, byte) in data.iter().enumerate() {
            result[i % 32] ^= byte;
            result[(i + 1) % 32] = result[(i + 1) % 32].wrapping_add(*byte);
        }
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

/// Compute Bitcoin transaction hash (double SHA256)
pub fn compute_tx_hash(raw_tx: &[u8]) -> [u8; 32] {
    double_sha256(raw_tx)
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
            offset += varint_size + script_len as usize + 4; // script + sequence

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
            offset += varint_size + script_len as usize;

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

        let script_end = self.offset + script_len as usize;
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
        self.offset += varint_size + script_len as usize + 4;

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
