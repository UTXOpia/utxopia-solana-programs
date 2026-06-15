# Permissioned Pool — Solana implementation plan

Parity with the Sui implementation (auditor-controlled pool: additions to the commitment
tree require auditor authorization). Mirror of `utxopia-sui-programs`
`docs/superpowers/specs/2026-06-15-permissioned-pool-design.md`.

**Design (locked):** a permissioned pool gates value-entry (`complete_deposit`, `shield`)
behind the pool's `auditor` signer. Public entries assert `!permissioned`. No on-chain
allowlist. Auditor holds viewing keys (Method-Y `auditor_viewing_pubkey` +
`auditor_ciphertext` on the deposit event). Fresh deploy + re-init (state layout change;
no in-place migration — same as the Sui fresh-deploy).

**Verify:** `cargo build-sbf --features devnet` (build) and `cargo test` (unit) after each
task; integration via `bun test tests/unit` / `tests/integration` where relevant.

**Reference patterns (from code map):**
- Authority signer gate: `programs/utxopia/src/instructions/admin_update_pool.rs:91-117`
  (`process_execute_pool_update`: account[1] `is_signer()` + `key() == pool.authority`).
- `PoolState`: `programs/utxopia/src/state/pool.rs:11-135` (repr(C) zero-copy, `flags` bit0
  = paused, `_reserved[4]`, `LEN`, `from_bytes`/`from_bytes_mut`/`init`).
- Deposit: `instructions/complete_deposit.rs:127` (disc 11, authority signer at idx 5,
  commitment insert ~449-461). Shield: `instructions/shield.rs:29` (disc 12, user signer idx 0,
  insert ~157-165). Instruction enum/dispatch: `lib.rs:48-177`. Init: `instructions/initialize.rs:83-201`.
  Events: `utils/events.rs` (`sol_log_data`).

---

### Task 1: PoolState — auditor fields
**File:** `programs/utxopia/src/state/pool.rs`
- Add `permissioned` and `auditor_frozen` as bits in the existing `flags` byte
  (bit1 = permissioned, bit2 = auditor_frozen) with getter/setter helpers mirroring the
  existing `paused`/`set_paused` (bit0).
- Add fields `auditor: [u8; 32]` and `auditor_viewing_pubkey: [u8; 32]` (consume the
  `_reserved[4]` and grow the struct; keep repr(C); update `LEN`). Add getters/setters
  (`auditor()`, `set_auditor()`, etc.) mirroring `authority`.
- `init()` already zeroes the whole buffer, so new fields default to `permissioned=false`,
  zero auditor — fine.
- Build: `cargo build-sbf --features devnet`. Run `cargo test` (existing pool-state tests).
- Commit: `solana: PoolState auditor fields (permissioned/frozen flags + auditor pubkeys)`.

### Task 2: Errors + instruction discriminants + dispatch
**Files:** `programs/utxopia/src/error.rs` (or wherever `UTXOpiaError` lives), `lib.rs`
- Add errors: `NotPermissioned`, `AuditorFrozen` (reuse `Unauthorized` for wrong auditor).
- Add discriminants in `lib.rs` instruction block (free slots): `INITIALIZE_PERMISSIONED = 21`,
  `COMPLETE_DEPOSIT_PERMISSIONED = 22`, `SHIELD_PERMISSIONED = 23`, `SET_AUDITOR_FROZEN = 28`,
  `SET_AUDITOR_VIEWING_PUBKEY = 29`.
- Add the match arms in `process_instruction` calling the new handlers (created next tasks).
- Build + `cargo test`. Commit: `solana: permissioned-pool errors + instruction discriminants`.
- NOTE: do this together with Task 3-6 stubs OR add the arms as each handler lands so the
  crate always compiles. Recommended: add discriminant consts here; wire match arms in the
  task that adds each handler.

### Task 3: initialize_permissioned
**File:** new `programs/utxopia/src/instructions/initialize_permissioned.rs` (or extend
`initialize.rs`); wire into `instructions/mod.rs` + dispatch.
- Same accounts/logic as `process_initialize`, plus instruction data carries `auditor: [u8;32]`
  and `auditor_viewing_pubkey: [u8;32]`. After the standard init, set `permissioned=true`,
  `auditor`, `auditor_viewing_pubkey`, `auditor_frozen=false`.
- Build + a `cargo test` unit test that inits a permissioned pool and asserts the fields.
- Commit: `solana: initialize_permissioned`.

### Task 4: complete_deposit — public guard + permissioned variant
**File:** `programs/utxopia/src/instructions/complete_deposit.rs`
- Extract the deposit core into a private fn `complete_deposit_inner(...)` (everything after
  the signer/authority gate). Add an `auditor_ciphertext: &[u8]` passthrough emitted in the
  deposit event.
- `process_complete_deposit` (public, disc 11): assert `!pool.permissioned` (else
  `NotPermissioned`), keep the existing authority-signer behavior, then call inner.
- `process_complete_deposit_permissioned` (disc 22): require an auditor signer
  (`is_signer()` + `key() == pool.auditor`, f11 pattern) + `!auditor_frozen`, then call inner.
  Account layout: append the auditor signer (and keep the existing payer/authority as needed).
- Events: add `auditor_ciphertext` via a new `sol_log_data` discriminant in `utils/events.rs`
  (`emit_auditor_ciphertext(commitment, ciphertext)`), emitted by the permissioned path.
- Build + `cargo test`/svm test: permissioned deposit with auditor signer succeeds; without
  the auditor (or wrong auditor) fails `Unauthorized`/`MissingRequiredSignature`; public
  deposit on a permissioned pool fails `NotPermissioned`; frozen fails `AuditorFrozen`.
- Commit: `solana: auditor-gated complete_deposit_permissioned`.

### Task 5: shield — public guard + permissioned variant (two signers)
**File:** `programs/utxopia/src/instructions/shield.rs`
- Extract `shield_inner(...)`. Public `process_shield` (disc 12): assert `!permissioned`,
  keep user signer, call inner. `process_shield_permissioned` (disc 23): require BOTH the
  user signer (token transfer authority, existing idx 0) AND an auditor signer
  (`key() == pool.auditor`) + `!auditor_frozen`, then inner. Emit `auditor_ciphertext`.
- Build + tests mirroring Task 4 (auditor+user succeed; missing auditor fails; public on
  permissioned fails; frozen fails).
- Commit: `solana: auditor-gated shield_permissioned (user + auditor signers)`.

### Task 6: set_auditor_frozen + set_auditor_viewing_pubkey
**File:** new `programs/utxopia/src/instructions/admin_auditor.rs`; wire dispatch.
- Both require the auditor signer (`is_signer()` + `key() == pool.auditor`, else
  `Unauthorized`). `set_auditor_frozen` sets the flag bit; `set_auditor_viewing_pubkey`
  copies 32 bytes. Emit a small event each.
- Build + `cargo test`: auditor toggles frozen / sets viewing key; non-auditor fails.
- Commit: `solana: auditor setters (frozen / viewing pubkey)`.

### Task 7: regression + docs
- Full `cargo build-sbf --features devnet` + `cargo test` + `bun test tests/unit` green.
- Confirm public-pool deposit/shield tests unchanged.
- Note the fresh-deploy + re-init requirement in the program README/runbook.
- Commit: `solana: permissioned-pool regression + deploy note`.

## Notes
- Two-signer permissioned shield is intentional: the user authorizes their own SPL token
  transfer; the auditor authorizes admission.
- State layout change ⇒ fresh program deploy + re-init (no migration), per testnet practice.
