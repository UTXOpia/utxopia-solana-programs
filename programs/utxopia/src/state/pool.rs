//! Pool state account (zero-copy)

use pinocchio::program_error::ProgramError;

/// Discriminator for PoolState account
pub const POOL_STATE_DISCRIMINATOR: u8 = 0x01;

/// Main pool state account (zero-copy layout)
/// All multi-byte integers stored as little-endian byte arrays for alignment safety
#[repr(C)]
pub struct PoolState {
    /// Account discriminator (1 byte)
    pub discriminator: u8,

    /// Bump seed for PDA derivation
    pub bump: u8,

    /// Flags: bit 0 = paused, bit 1 = permissioned, bit 2 = auditor_frozen
    pub flags: u8,

    /// Padding for alignment
    _padding: u8,

    /// Authority that can update pool state
    pub authority: [u8; 32],

    /// zkBTC Token-2022 mint address
    pub zkbtc_mint: [u8; 32],

    /// Pool vault that holds zkBTC (PDA-controlled)
    pub pool_vault: [u8; 32],

    /// Deposit vault used by the bridge flow
    pub deposit_vault: [u8; 32],

    /// Total number of deposits recorded (u64 as bytes)
    deposit_count: [u8; 8],

    /// Total zkBTC minted (in satoshis)
    total_minted: [u8; 8],

    /// Total zkBTC burned (in satoshis)
    total_burned: [u8; 8],

    /// Number of pending redemption requests
    pending_redemptions: [u8; 8],

    /// Timestamp of last update
    last_update: [u8; 8],

    /// Minimum deposit amount (satoshis)
    min_deposit: [u8; 8],

    /// Maximum deposit amount (satoshis)
    max_deposit: [u8; 8],

    /// Total zkBTC in shielded pool (users hold commitments, not public tokens)
    total_shielded: [u8; 8],

    /// Base service fee per BTC withdrawal (satoshis) — combined with service_fee_bps
    /// for percentage + base fee model. Protocol revenue goes to pool.
    service_fee_base: [u8; 8],

    /// Cumulative protocol revenue collected from withdrawal service fees (satoshis).
    /// fee_pool = sum(service_fee - miner_fee) across all completed withdrawals.
    fee_pool: [u8; 8],

    /// Pending timelock: proposed min_deposit (satoshis)
    pending_min_deposit: [u8; 8],

    /// Pending timelock: proposed max_deposit (satoshis)
    pending_max_deposit: [u8; 8],

    /// Pending timelock: proposed service_fee_base (satoshis)
    pending_service_fee: [u8; 8],

    /// Pending timelock: unix timestamp after which the proposal can be executed.
    /// 0 means no active proposal.
    pending_execute_after: [u8; 8],

    /// Percentage fee on all deposits (basis points, u16 LE). E.g., 50 = 0.5%.
    deposit_fee_bps: [u8; 2],

    /// Percentage fee on all withdrawals (basis points, u16 LE). E.g., 100 = 1.0%.
    withdrawal_fee_bps: [u8; 2],

    /// Sum of all Unspent UTXO amounts (satoshis).
    total_btc_held: [u8; 8],

    /// Number of Unspent UTXOs — LOW 16 bits (kept at this offset for backward compat).
    /// Combined with `utxo_count_hi` into a u32 so permissionless deposits can't saturate the
    /// counter at 65535 and brick add_utxo / core flows (audit f34).
    utxo_count: [u8; 2],

    /// Active commitment tree index for tree rotation.
    /// When the current tree fills (65536 leaves), authority calls rotate_tree
    /// to increment this and create a new tree PDA.
    active_tree_index: [u8; 4],

    /// HIGH 16 bits of the UTXO count (carved from former _reserved; zero in legacy accounts,
    /// so existing pools decode identically). See `utxo_count` / `utxo_count()`.
    utxo_count_hi: [u8; 2],

    /// Auditor public key (ed25519 / Solana pubkey). Zero = no auditor assigned.
    auditor: [u8; 32],

    /// Auditor viewing public key (e.g. for encrypted-memo decryption). Zero = not set.
    auditor_viewing_pubkey: [u8; 32],

    /// Reserved for future use
    _reserved: [u8; 4],
}

impl PoolState {
    pub const LEN: usize = core::mem::size_of::<Self>();
    pub const SEED: &'static [u8] = b"pool_state";

    const FLAG_PAUSED: u8 = 1 << 0;
    const FLAG_PERMISSIONED: u8 = 1 << 1;
    const FLAG_AUDITOR_FROZEN: u8 = 1 << 2;

    /// Parse from account data
    pub fn from_bytes(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != POOL_STATE_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        // Safe: PoolState is repr(C) with all byte-aligned fields
        Ok(unsafe { &*(data.as_ptr() as *const Self) })
    }

    /// Parse as mutable from account data
    pub fn from_bytes_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        if data[0] != POOL_STATE_DISCRIMINATOR {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    /// Initialize a new pool state in the given buffer
    pub fn init(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() < Self::LEN {
            return Err(ProgramError::InvalidAccountData);
        }
        // Zero initialize
        data[..Self::LEN].fill(0);
        data[0] = POOL_STATE_DISCRIMINATOR;
        Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
    }

    // Getters
    pub fn is_paused(&self) -> bool {
        self.flags & Self::FLAG_PAUSED != 0
    }

    pub fn permissioned(&self) -> bool {
        self.flags & Self::FLAG_PERMISSIONED != 0
    }

    pub fn auditor_is_frozen(&self) -> bool {
        self.flags & Self::FLAG_AUDITOR_FROZEN != 0
    }

    pub fn auditor(&self) -> &[u8; 32] {
        &self.auditor
    }

    pub fn auditor_viewing_pubkey(&self) -> &[u8; 32] {
        &self.auditor_viewing_pubkey
    }

    pub fn deposit_count(&self) -> u64 {
        u64::from_le_bytes(self.deposit_count)
    }

    pub fn total_minted(&self) -> u64 {
        u64::from_le_bytes(self.total_minted)
    }

    pub fn total_burned(&self) -> u64 {
        u64::from_le_bytes(self.total_burned)
    }

    pub fn pending_redemptions(&self) -> u64 {
        u64::from_le_bytes(self.pending_redemptions)
    }

    pub fn last_update(&self) -> i64 {
        i64::from_le_bytes(self.last_update)
    }

    pub fn min_deposit(&self) -> u64 {
        u64::from_le_bytes(self.min_deposit)
    }

    pub fn max_deposit(&self) -> u64 {
        u64::from_le_bytes(self.max_deposit)
    }

    pub fn total_shielded(&self) -> u64 {
        u64::from_le_bytes(self.total_shielded)
    }

    pub fn service_fee_base(&self) -> u64 {
        u64::from_le_bytes(self.service_fee_base)
    }

    pub fn deposit_fee_bps(&self) -> u16 {
        u16::from_le_bytes(self.deposit_fee_bps)
    }

    pub fn withdrawal_fee_bps(&self) -> u16 {
        u16::from_le_bytes(self.withdrawal_fee_bps)
    }

    /// Compute deposit fee: amount * deposit_fee_bps / 10000
    pub fn compute_deposit_fee(&self, amount: u64) -> u64 {
        let bps = self.deposit_fee_bps() as u128;
        ((amount as u128 * bps) / 10_000).min(u64::MAX as u128) as u64
    }

    /// Compute withdrawal fee: amount * withdrawal_fee_bps / 10000
    pub fn compute_withdrawal_fee(&self, amount: u64) -> u64 {
        let bps = self.withdrawal_fee_bps() as u128;
        ((amount as u128 * bps) / 10_000).min(u64::MAX as u128) as u64
    }

    /// Compute BTC withdrawal service fee: amount * withdrawal_fee_bps / 10000
    /// + service_fee_base.
    pub fn compute_service_fee(&self, amount: u64) -> u64 {
        let base = self.service_fee_base();
        let pct_fee = self.compute_withdrawal_fee(amount);
        pct_fee.saturating_add(base)
    }

    pub fn fee_pool(&self) -> u64 {
        u64::from_le_bytes(self.fee_pool)
    }

    pub fn pending_min_deposit(&self) -> u64 {
        u64::from_le_bytes(self.pending_min_deposit)
    }

    pub fn pending_max_deposit(&self) -> u64 {
        u64::from_le_bytes(self.pending_max_deposit)
    }

    pub fn pending_service_fee(&self) -> u64 {
        u64::from_le_bytes(self.pending_service_fee)
    }

    pub fn pending_execute_after(&self) -> i64 {
        i64::from_le_bytes(self.pending_execute_after)
    }

    pub fn has_pending_proposal(&self) -> bool {
        self.pending_execute_after() != 0
    }

    pub fn total_btc_held(&self) -> u64 {
        u64::from_le_bytes(self.total_btc_held)
    }

    pub fn utxo_count(&self) -> u32 {
        (u16::from_le_bytes(self.utxo_count) as u32)
            | ((u16::from_le_bytes(self.utxo_count_hi) as u32) << 16)
    }

    pub fn active_tree_index(&self) -> u32 {
        u32::from_le_bytes(self.active_tree_index)
    }

    // Setters
    pub fn set_paused(&mut self, paused: bool) {
        if paused {
            self.flags |= Self::FLAG_PAUSED;
        } else {
            self.flags &= !Self::FLAG_PAUSED;
        }
    }

    pub fn set_permissioned(&mut self, permissioned: bool) {
        if permissioned {
            self.flags |= Self::FLAG_PERMISSIONED;
        } else {
            self.flags &= !Self::FLAG_PERMISSIONED;
        }
    }

    pub fn set_auditor_frozen(&mut self, frozen: bool) {
        if frozen {
            self.flags |= Self::FLAG_AUDITOR_FROZEN;
        } else {
            self.flags &= !Self::FLAG_AUDITOR_FROZEN;
        }
    }

    pub fn set_auditor(&mut self, pubkey: &[u8; 32]) {
        self.auditor.copy_from_slice(pubkey);
    }

    pub fn set_auditor_viewing_pubkey(&mut self, pubkey: &[u8; 32]) {
        self.auditor_viewing_pubkey.copy_from_slice(pubkey);
    }

    pub fn set_deposit_count(&mut self, value: u64) {
        self.deposit_count = value.to_le_bytes();
    }

    pub fn set_total_minted(&mut self, value: u64) {
        self.total_minted = value.to_le_bytes();
    }

    pub fn set_total_burned(&mut self, value: u64) {
        self.total_burned = value.to_le_bytes();
    }

    pub fn set_pending_redemptions(&mut self, value: u64) {
        self.pending_redemptions = value.to_le_bytes();
    }

    pub fn set_last_update(&mut self, value: i64) {
        self.last_update = value.to_le_bytes();
    }

    pub fn set_min_deposit(&mut self, value: u64) {
        self.min_deposit = value.to_le_bytes();
    }

    pub fn set_max_deposit(&mut self, value: u64) {
        self.max_deposit = value.to_le_bytes();
    }

    pub fn set_total_shielded(&mut self, value: u64) {
        self.total_shielded = value.to_le_bytes();
    }

    pub fn set_service_fee_base(&mut self, value: u64) {
        self.service_fee_base = value.to_le_bytes();
    }

    pub fn set_deposit_fee_bps(&mut self, value: u16) {
        self.deposit_fee_bps = value.to_le_bytes();
    }

    pub fn set_withdrawal_fee_bps(&mut self, value: u16) {
        self.withdrawal_fee_bps = value.to_le_bytes();
    }

    pub fn set_fee_pool(&mut self, value: u64) {
        self.fee_pool = value.to_le_bytes();
    }

    pub fn set_pending_min_deposit(&mut self, value: u64) {
        self.pending_min_deposit = value.to_le_bytes();
    }

    pub fn set_pending_max_deposit(&mut self, value: u64) {
        self.pending_max_deposit = value.to_le_bytes();
    }

    pub fn set_pending_service_fee(&mut self, value: u64) {
        self.pending_service_fee = value.to_le_bytes();
    }

    pub fn set_pending_execute_after(&mut self, value: i64) {
        self.pending_execute_after = value.to_le_bytes();
    }

    pub fn set_total_btc_held(&mut self, value: u64) {
        self.total_btc_held = value.to_le_bytes();
    }

    pub fn set_utxo_count(&mut self, value: u32) {
        self.utxo_count = ((value & 0xFFFF) as u16).to_le_bytes();
        self.utxo_count_hi = ((value >> 16) as u16).to_le_bytes();
    }

    pub fn set_active_tree_index(&mut self, value: u32) {
        self.active_tree_index = value.to_le_bytes();
    }

    /// Clear all pending timelock fields
    pub fn clear_pending_proposal(&mut self) {
        self.pending_min_deposit = [0u8; 8];
        self.pending_max_deposit = [0u8; 8];
        self.pending_service_fee = [0u8; 8];
        self.pending_execute_after = [0u8; 8];
        // Note: withdrawal_fee_bps is no longer a pending field (was pending_service_fee_bps).
        // It's now active config, so we don't clear it here.
    }

    // Increment helpers with overflow check
    pub fn increment_deposit_count(&mut self) -> Result<(), ProgramError> {
        let count = self.deposit_count();
        self.set_deposit_count(
            count
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn add_minted(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.total_minted();
        self.set_total_minted(
            total
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn add_burned(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.total_burned();
        self.set_total_burned(
            total
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn add_shielded(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.total_shielded();
        self.set_total_shielded(
            total
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn sub_shielded(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.total_shielded();
        self.set_total_shielded(
            total
                .checked_sub(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    pub fn add_fee_pool(&mut self, amount: u64) -> Result<(), ProgramError> {
        let total = self.fee_pool();
        self.set_fee_pool(
            total
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    /// Add a UTXO to the pool's BTC tracking
    pub fn add_utxo(&mut self, amount: u64) -> Result<(), ProgramError> {
        let held = self.total_btc_held();
        self.set_total_btc_held(
            held.checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        let count = self.utxo_count();
        self.set_utxo_count(
            count
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }

    /// Restore `count` UTXOs totalling `amount` in one call. Used when a redemption is cancelled
    /// and N reserved UTXOs return to the pool: `remove_utxo` decremented the count once per UTXO
    /// at mark_processing, so the restore must re-increment by the same N. A single `add_utxo`
    /// (count += 1) would drift the counter down by N-1 per multi-input cancel and eventually
    /// underflow `remove_utxo`, bricking withdrawals (audit f13).
    pub fn add_utxos(&mut self, amount: u64, count: u32) -> Result<(), ProgramError> {
        let held = self.total_btc_held();
        self.set_total_btc_held(
            held.checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        let c = self.utxo_count();
        self.set_utxo_count(c.checked_add(count).ok_or(ProgramError::ArithmeticOverflow)?);
        Ok(())
    }

    /// Remove a UTXO from the pool's BTC tracking
    pub fn remove_utxo(&mut self, amount: u64) -> Result<(), ProgramError> {
        let held = self.total_btc_held();
        self.set_total_btc_held(
            held.checked_sub(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        let count = self.utxo_count();
        self.set_utxo_count(
            count
                .checked_sub(1)
                .ok_or(ProgramError::ArithmeticOverflow)?,
        );
        Ok(())
    }
}
