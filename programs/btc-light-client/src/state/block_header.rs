/// Bitcoin block header account (zero-copy layout)
/// Must match utxopia's BlockHeader exactly.
#[repr(C)]
pub(crate) struct BlockHeader {
    pub discriminator: u8,
    pub _padding: [u8; 3],
    pub version: [u8; 4],
    pub prev_block_hash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub timestamp: [u8; 4],
    pub bits: [u8; 4],
    pub nonce: [u8; 4],
    pub block_hash: [u8; 32],
    pub chainwork: [u8; 32],
    pub height: [u8; 8],
    pub submitted_at: [u8; 8],
    pub _reserved: [u8; 32],
}

impl BlockHeader {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn height(&self) -> u64 {
        u64::from_le_bytes(self.height)
    }

    pub fn epoch_bits(&self) -> u32 {
        u32::from_le_bytes([
            self._reserved[0],
            self._reserved[1],
            self._reserved[2],
            self._reserved[3],
        ])
    }

    pub fn epoch_start_time(&self) -> u32 {
        u32::from_le_bytes([
            self._reserved[4],
            self._reserved[5],
            self._reserved[6],
            self._reserved[7],
        ])
    }

    pub fn set_epoch_bits(&mut self, value: u32) {
        self._reserved[0..4].copy_from_slice(&value.to_le_bytes());
    }

    pub fn set_epoch_start_time(&mut self, value: u32) {
        self._reserved[4..8].copy_from_slice(&value.to_le_bytes());
    }

    /// Chain-instance epoch this header was written under (mirrors
    /// BitcoinLightClient.reinit_epoch). Binds the header to the current chain instance so a
    /// stale pre-reinitialization header cannot be used as an extension parent (audit f07/f08).
    pub fn reinit_epoch(&self) -> u32 {
        u32::from_le_bytes([
            self._reserved[8],
            self._reserved[9],
            self._reserved[10],
            self._reserved[11],
        ])
    }

    pub fn set_reinit_epoch(&mut self, value: u32) {
        self._reserved[8..12].copy_from_slice(&value.to_le_bytes());
    }
}
