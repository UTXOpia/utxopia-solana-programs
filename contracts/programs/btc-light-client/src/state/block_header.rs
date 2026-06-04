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
}
