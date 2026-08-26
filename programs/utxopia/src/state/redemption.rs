//! Redemption request account (zero-copy)

use crate::pinocchio_compat::ProgramError;

use crate::constants::MAX_BTC_SCRIPT_LEN;

/// Discriminator for RedemptionRequest account
pub const REDEMPTION_REQUEST_DISCRIMINATOR: u8 = 0x04;

/// Redemption status enum
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RedemptionStatus {
    /// Request created, waiting for processing
    Pending = 0,
    /// Being processed by relayer (blocks cancel)
    Processing = 1,
    /// Failed
    Failed = 2,
}

/// Redemption request - pending BTC withdrawal (zero-copy layout)
///
/// Layout (178 bytes):
/// - discriminator:     1 byte
/// - status:            1 byte
/// - btc_script_len:    1 byte
/// - _padding1:         1 byte
/// - processing_slot:   4 bytes (u32 LE, slot when mark_processing was called, 0 if Pending)
/// - request_id:        8 bytes
/// - requester:         32 bytes
/// - amount_sats:       8 bytes
/// - service_fee:       8 bytes (locked at request time from pool config)
/// - total_input_sats:  8 bytes (sum of BTC input UTXOs, set at mark_processing by backend)
/// - btc_script:        34 bytes (raw scriptPubKey for BTC withdrawal, not bech32 string)
/// - token_id:          32 bytes (the redeemed token, recorded at redeem; cancel re-mints the same token)
/// - reserved_count:    1 byte  (number of UTXOs reserved at mark_processing; 0 until Processing)
/// - approved_inputs:   4 bytes (u32 LE bitset; one bit per Ika-approved BTC input)
/// - approval_miner_fee: 3 bytes (u24 LE; miner fee pinned by the FIRST signing approval)
/// - inputs_commitment: 32 bytes (sha256 over canonical-ordered reserved inputs; binds the BTC
///                                spend's input set so approve_redemption_signing can reconstruct
///                                the exact sighash from trusted state)
#[repr(C)]
pub struct RedemptionRequest {
    /// Account discriminator
    pub discriminator: u8,

    /// Current status
    pub status: u8,

    /// BTC scriptPubKey length
    pub btc_script_len: u8,

    /// Set to 1 once Ika signing has been approved (approve_redemption_signing). Once set,
    /// cancel_redemption is permanently blocked — even after the processing timeout — because
    /// a signed BTC payout may already be broadcastable, so re-minting the note would allow a
    /// cross-chain double-spend.
    signing_approved: u8,

    /// Slot when mark_processing was called (0 = not yet processing).
    /// Used for timeout: if current_slot - processing_slot > TIMEOUT_SLOTS, user can cancel.
    processing_slot: [u8; 4],

    /// Unique request ID (incrementing)
    request_id: [u8; 8],

    /// User who requested the redemption
    pub requester: [u8; 32],

    /// Amount to withdraw (satoshis)
    amount_sats: [u8; 8],

    /// Service fee in satoshis — locked at request time from pool's compute_service_fee().
    /// complete_redemption uses this instead of re-reading pool config.
    service_fee: [u8; 8],

    /// Total BTC input UTXO value in satoshis — set by backend at mark_processing.
    /// Used by complete_redemption to compute miner_fee = total_input_sats - sum(tx_outputs).
    total_input_sats: [u8; 8],

    /// Bitcoin scriptPubKey for withdrawal (fixed buffer)
    pub btc_script: [u8; MAX_BTC_SCRIPT_LEN],

    /// Token id of the redeemed note, recorded at redeem; cancel_redemption
    /// re-mints with this and rejects a token_config whose token_id differs.
    pub token_id: [u8; 32],

    /// Number of pool UTXOs reserved for this redemption at mark_processing.
    /// 0 while Pending. approve_redemption_signing requires exactly this many
    /// reserved UTXO accounts so the reconstructed BTC tx has the right inputs.
    reserved_count: u8,

    /// Per-input signing approval bitset. The global `signing_approved` flag is set only after
    /// every reserved input has an approval, so a failed multi-input approval can still time out
    /// and be cancelled safely.
    approved_inputs: [u8; 4],

    /// Miner fee in satoshis, u24 LE, pinned by the FIRST approve_redemption_signing call.
    ///
    /// The fee is a caller-supplied scalar that feeds the change output and therefore the
    /// TapSighash. Left unpinned, each input of a multi-input redemption could be approved
    /// under a different fee, so the Ika approvals would cover mutually incompatible
    /// transactions and no valid BTC spend could ever be assembled — while the full bitset
    /// sets `signing_approved`, which permanently blocks `cancel_redemption`. The reserved
    /// UTXOs would be unspendable through every path in the program.
    ///
    /// Three bytes is deliberate, not a squeeze: `MAX_MINER_FEE_SATS` is 50_000 and
    /// `check_redemption_signing` rejects anything above it, so u24 (16_777_215) has ~300x
    /// headroom. Reusing the old `_padding2` keeps `LEN` at 178, which matters because
    /// off-chain readers filter these accounts by dataSize — see `len_is_pinned` below.
    approval_miner_fee: [u8; 3],

    /// sha256 over the canonical-ordered reserved input set
    /// (for each input in canonical order: txid(32) || vout(4 LE) || amount(8 LE)).
    /// Set at mark_processing; checked at approve to prove the supplied UTXO set
    /// is exactly the reserved set, in the order the sighash is computed over.
    inputs_commitment: [u8; 32],
}

impl RedemptionRequest {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = b"redemption";

    /// Parse from account data
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != REDEMPTION_REQUEST_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Parse as mutable from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != REDEMPTION_REQUEST_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Initialize a new redemption request in the given buffer
    pub fn init(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        data[..Self::LEN].fill(0);
        data[0] = REDEMPTION_REQUEST_DISCRIMINATOR;
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    // Getters
    pub fn get_status(&self) -> RedemptionStatus {
        match self.status {
            0 => RedemptionStatus::Pending,
            1 => RedemptionStatus::Processing,
            2 => RedemptionStatus::Failed,
            _ => RedemptionStatus::Pending,
        }
    }

    pub fn request_id(&self) -> u64 {
        u64::from_le_bytes(self.request_id)
    }

    pub fn amount_sats(&self) -> u64 {
        u64::from_le_bytes(self.amount_sats)
    }

    pub fn service_fee(&self) -> u64 {
        u64::from_le_bytes(self.service_fee)
    }

    pub fn processing_slot(&self) -> u32 {
        u32::from_le_bytes(self.processing_slot)
    }

    pub fn total_input_sats(&self) -> u64 {
        u64::from_le_bytes(self.total_input_sats)
    }

    pub fn get_btc_script(&self) -> &[u8] {
        &self.btc_script[..self.btc_script_len as usize]
    }

    pub fn token_id(&self) -> &[u8; 32] {
        &self.token_id
    }

    pub fn reserved_count(&self) -> u8 {
        self.reserved_count
    }

    pub fn inputs_commitment(&self) -> &[u8; 32] {
        &self.inputs_commitment
    }

    pub fn is_signing_approved(&self) -> bool {
        self.signing_approved != 0
    }

    pub fn is_input_signing_approved(&self, input_index: u32) -> bool {
        input_index < 32 && (u32::from_le_bytes(self.approved_inputs) & (1u32 << input_index)) != 0
    }

    /// True once any input has been approved — i.e. the miner fee is already pinned.
    pub fn has_any_input_approved(&self) -> bool {
        u32::from_le_bytes(self.approved_inputs) != 0
    }

    /// Miner fee pinned by the first approval. Meaningless unless `has_any_input_approved()`.
    pub fn approval_miner_fee_sats(&self) -> u64 {
        let [a, b, c] = self.approval_miner_fee;
        u64::from(u32::from_le_bytes([a, b, c, 0]))
    }

    // Setters
    pub fn set_status(&mut self, status: RedemptionStatus) {
        self.status = status as u8;
    }

    pub fn set_signing_approved(&mut self) {
        self.signing_approved = 1;
    }

    pub fn mark_input_signing_approved(&mut self, input_index: u32) -> Result<(), ProgramError> {
        if input_index >= 32 || input_index >= self.reserved_count as u32 {
            return Err(ProgramError::InvalidArgument);
        }
        let mask = u32::from_le_bytes(self.approved_inputs) | (1u32 << input_index);
        self.approved_inputs = mask.to_le_bytes();
        if self.all_inputs_signing_approved() {
            self.set_signing_approved();
        }
        Ok(())
    }

    pub fn all_inputs_signing_approved(&self) -> bool {
        if self.reserved_count == 0 || self.reserved_count > 32 {
            return false;
        }
        let required = if self.reserved_count == 32 {
            u32::MAX
        } else {
            (1u32 << self.reserved_count) - 1
        };
        u32::from_le_bytes(self.approved_inputs) & required == required
    }

    /// Pin the miner fee. Callers must only invoke this on the first approval.
    /// Errors rather than truncating if the value exceeds u24 — unreachable while
    /// `check_redemption_signing` caps the fee at `MAX_MINER_FEE_SATS`, but the store is
    /// lossy and a silent wrap here would unpin the very thing this field exists to pin.
    pub fn set_approval_miner_fee_sats(&mut self, value: u64) -> Result<(), ProgramError> {
        if value > 0x00ff_ffff {
            return Err(ProgramError::InvalidArgument);
        }
        let b = (value as u32).to_le_bytes();
        self.approval_miner_fee = [b[0], b[1], b[2]];
        Ok(())
    }

    pub fn set_request_id(&mut self, value: u64) {
        self.request_id = value.to_le_bytes();
    }

    pub fn set_amount_sats(&mut self, value: u64) {
        self.amount_sats = value.to_le_bytes();
    }

    pub fn set_service_fee(&mut self, value: u64) {
        self.service_fee = value.to_le_bytes();
    }

    pub fn set_processing_slot(&mut self, value: u32) {
        self.processing_slot = value.to_le_bytes();
    }

    pub fn set_total_input_sats(&mut self, value: u64) {
        self.total_input_sats = value.to_le_bytes();
    }

    pub fn set_btc_script(&mut self, script: &[u8]) -> Result<(), ProgramError> {
        if script.len() > MAX_BTC_SCRIPT_LEN {
            return Err(ProgramError::InvalidArgument);
        }
        self.btc_script[..script.len()].copy_from_slice(script);
        self.btc_script_len = script.len() as u8;
        Ok(())
    }

    pub fn set_token_id(&mut self, token_id: &[u8; 32]) {
        self.token_id = *token_id;
    }

    pub fn set_reserved_count(&mut self, value: u8) {
        self.reserved_count = value;
    }

    pub fn set_inputs_commitment(&mut self, commitment: &[u8; 32]) {
        self.inputs_commitment = *commitment;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_input_approval_sets_global_flag_only_when_complete() {
        let mut data = vec![0u8; RedemptionRequest::LEN];
        let redemption = RedemptionRequest::init(&mut data).unwrap();
        redemption.set_reserved_count(3);

        redemption.mark_input_signing_approved(1).unwrap();
        assert!(!redemption.is_signing_approved());
        redemption.mark_input_signing_approved(0).unwrap();
        assert!(!redemption.is_signing_approved());
        redemption.mark_input_signing_approved(2).unwrap();
        assert!(redemption.is_signing_approved());
        assert!(redemption.all_inputs_signing_approved());
    }

    #[test]
    fn input_approval_rejects_out_of_range_index() {
        let mut data = vec![0u8; RedemptionRequest::LEN];
        let redemption = RedemptionRequest::init(&mut data).unwrap();
        redemption.set_reserved_count(2);
        assert!(redemption.mark_input_signing_approved(2).is_err());
    }
}

#[cfg(test)]
mod size_tests {
    use super::RedemptionRequest;

    #[test]
    fn len_is_pinned() {
        // Off-chain readers filter these accounts by dataSize, so a struct change is a silent
        // break for them, not a compile error: @utxopia/sdk sat on 138 (this struct before
        // reserved_count/approved_inputs/inputs_commitment were added) and matched nothing.
        // If this fails, update the SDK's REDEMPTION_REQUEST_SIZE in the same change.
        assert_eq!(RedemptionRequest::LEN, 178);
    }

    /// The pinned miner fee reuses the old `_padding2`, so prove the u24 store is lossless
    /// across the whole range the fee cap admits, and that it refuses to truncate above it.
    #[test]
    fn approval_miner_fee_round_trips_and_refuses_truncation() {
        use crate::utils::policy::MAX_MINER_FEE_SATS;
        let mut buf = [0u8; RedemptionRequest::LEN];
        buf[0] = super::REDEMPTION_REQUEST_DISCRIMINATOR;
        let r = RedemptionRequest::from_bytes_mut(&mut buf).unwrap();

        // Unset reads as 0, and nothing is pinned until an input is approved.
        assert_eq!(r.approval_miner_fee_sats(), 0);
        assert!(!r.has_any_input_approved());

        for v in [0u64, 1, 330, MAX_MINER_FEE_SATS, 0x00ff_ffff] {
            r.set_approval_miner_fee_sats(v).unwrap();
            assert_eq!(r.approval_miner_fee_sats(), v, "round-trip failed for {v}");
        }

        // One past u24 must error, not wrap to 0.
        assert!(r.set_approval_miner_fee_sats(0x0100_0000).is_err());
        assert_eq!(r.approval_miner_fee_sats(), 0x00ff_ffff);

        // Writing the fee must not disturb the neighbouring bitset or commitment.
        assert_eq!(r.reserved_count(), 0);
        assert!(!r.has_any_input_approved());
        assert_eq!(r.inputs_commitment(), &[0u8; 32]);
    }
}
