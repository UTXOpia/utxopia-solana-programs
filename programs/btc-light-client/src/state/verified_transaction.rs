/// Verified Transaction PDA — proves a Bitcoin tx exists in a confirmed block
/// PDA seeds: ["verified_tx", block_hash(32), txid(32)]
#[repr(C)]
pub(crate) struct VerifiedTransaction {
    pub discriminator: u8,
    pub bump: u8,
    pub _padding: [u8; 2],
    pub block_height: [u8; 4],
    pub block_hash: [u8; 32],
    pub txid: [u8; 32],
    pub verified_at: [u8; 8],
    pub tx_index: [u8; 4],
    pub _reserved: [u8; 4],
    pub _reserved2: [u8; 32],
}

impl VerifiedTransaction {
    pub const LEN: usize = core::mem::size_of::<Self>(); // 120 bytes
}
