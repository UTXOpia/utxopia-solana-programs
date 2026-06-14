# Solana Programs — Audit Remediation (report 2026-06-14, 56 findings)

Source report: `utxopia-utxopia-solana-programs-main.json` (exported 2026-06-14T10:31Z, received via Tailscale).
Baseline: `main` @ `0f2febd` (post security/remediation-2026-06-14 merge). Build clean; **77 unit tests pass**.

Scope agreed with maintainer: **fix the 17 confirmed Critical/Major/Medium/Minor findings, then triage the 39 Info/Discussion** (fix real ones, document the rest).

## Fixed (confirmed findings)

| # | Sev | Finding | File(s) | Fix |
|---|-----|---------|---------|-----|
| 0 | CRIT | Recipient payout validated against one output, not the total | `complete_redemption.rs` | `actual_received` now **sums all** recipient-script outputs; require sum ≥ `min_amount`. |
| 1 | MAJ | Stale VerifiedTransaction proofs valid across LC reinit | `light_client.rs`, `reinitialize.rs`, `verify_transaction.rs`, `verified_tx_reader.rs`, `complete_deposit.rs`, `verify_deposit.rs`, `complete_redemption.rs` | Added **reinit-epoch** (u32 in LC `_reserved`); incremented on reinitialize, stamped onto each VerifiedTransaction at creation, checked equal to LC epoch at every utxopia consumption site. |
| 2 | MAJ | Batched-sweep amount extraction over-credits | `complete_deposit.rs` | Credited amount capped at the claimant's **traced deposit output value** (`min(deposit_value, pool_output_value)`) in two-step sweep mode. |
| 3 | MAJ | Non-zero OP_RETURN bypasses burn accounting | `complete_redemption.rs` | Policy rejects OP_RETURN outputs with `value != 0`. |
| 4 | MAJ | Fee-on-transfer deposits over-credit shielded balance | `shield.rs` | Credit the **measured vault balance delta** across the transfer, not the nominal `amount`; fee/shielded/cap derived from actual receipt. |
| 5 | MED | Prune rent-receiver aliasing tombstones PDA | `prune_obsolete_blocks.rs` | Reject `rent_receiver == block_header_info`. |
| 6 | MED | claim_fees vault==dest self-transfer burns counter | `claim_fees.rs` | Reject `vault == admin_token_account`. |
| 7 | MED | Multiple pool change outputs, only first tracked | `complete_redemption.rs` | Policy rejects >1 pool-change output. |
| 8 | MED | Reserved UTXOs not bound to a request | `utxo.rs`, `mark_processing.rs`, `complete_redemption.rs` | Added `reserved_for_request_id` to `UtxoRecord`; set at reservation, enforced at completion (UTXO LEN 48→56). |
| 9 | MED | Redeem proof not bound to signer (orderflow theft) | `crypto.rs`, `redeem.rs` | `compute_bound_params_hash_redeem` now binds `requester` (accounts[3]). **Requires coordinated SDK prover change** (see below). |
| 10 | MED | Deposit receipt keyed by txid only → under-credit | `verify_deposit.rs` | Receipt PDA re-keyed by **(txid, vout)**; created after the npk-bound output is identified. **Requires SDK PDA-derivation change** (add vout to seeds). |
| 12/15 | MED/MIN | Timed-out cancel re-mints after BTC signing approved | `redemption.rs`, `approve_redemption_signing.rs`, `cancel_redemption.rs` | Added `signing_approved` flag (repurposed padding byte); set on approval; `cancel_redemption` refuses once set, even after timeout. |
| 16 | MIN | SegWit hashed as wtxid, not canonical txid | `bitcoin.rs` | `compute_tx_hash` is now SegWit-aware: strips marker/flag/witness and hashes the legacy serialization (version‖vin‖vout‖locktime) via multi-chunk `sol_sha256`. |
| 13 | MED | Tree rotation strands previous-tree notes | `joinsplit_common.rs`, `validation.rs`, `transact.rs`, `unshield.rs`, `redeem.rs` | Spends accept an **optional frozen source tree** (a rotated-out `CommitmentTree`) for the membership-root check while new outputs still insert into the active tree. Detected by identity (program-owned tree discriminator), appended just before the optional proof_buffer — backward compatible (no extra account in the common case). **SDK must append the frozen tree when the note predates a rotation** (see below). |

Tests added: 5 redemption-policy cases (`complete_redemption_skim_tests.rs`), UtxoRecord layout (`utxo_tests.rs`), SegWit txid equivalence (`bitcoin.rs::txid_tests`).

## Info/Discussion hardening (2nd pass — verified each against current code)

| # | Finding | Verdict / Fix |
|---|---------|---------------|
| 53 | `reduce_to_field` bitwise mask ≠ modular reduction | **Fixed** — on-chain Poseidon now uses exact `val mod Fr` (matches circuit/SDK); non-canonical inputs no longer diverge. + test. |
| 54/24 | Non-canonical `commitments_out` pass verification | **Fixed** — `parse_prefix` rejects non-canonical commitments (mirrors the nullifier check); on-chain leaf/event == proved commitment. |
| 23 | VK/tree account substitution (proof forgery) | **Fixed** — `vk_registry` pinned to `["vk_registry", n_in, n_out]` PDA; tree already pinned via `validate_active_tree_pda`/`validate_frozen_tree`. (Not exploitable anyway — VK accounts are admin-only + frozen — but now defense-in-depth.) |
| 36/37 | Digest/scheme overrides = generic dWallet signing oracle | **Fixed** — `approve_redemption_signing` rejects both overrides; signing fixed to `keccak256(btc_sighash)` under Taproot-SHA256. Backend never set them. |
| 43 | Reorg can move `finalized_height` backward | **Fixed** — `finalized_height` is now monotonic. |
| 44 | testnet4 min-difficulty timestamp exploit | **Fixed** — headers >2h in the future are rejected (Solana-clock bound). |
| 35 | Unshield amounts not bound (fund reallocation) | **Non-issue** — amounts bound via burn commitments `Poseidon(0, token_id, amount)` checked against proof public inputs (`unshield.rs:209`). |

Deployed in-place to `G1bj9`/`C8Jo` (sigs `51if3n7…` / `gQpBPpp…`).

### Accepted with rationale (not fixed)

- **#50 Unauthenticated sender memos** (Low): memos are an optional, event-only convenience; a relayer stripping them only griefs the sender who chose that relayer, and **no protocol state depends on them**. Authenticating them needs a coordinated bound-params/circuit change disproportionate to the value. Accepted.
- **#36 (deep half) sighash not reconstructed at approval**: override removal closes the oracle; fully *binding* the approved sighash to the redemption's reserved UTXOs + script would require on-chain BIP-341 sighash reconstruction. The authority is a trusted role and the broadcast tx is still policy-checked at `complete_redemption`. Deferred as a larger design item.
- **#13 frozen-tree client wiring**: on-chain is complete + tested; the web-relay/client piece can't trigger until a 65,536-leaf tree rotation and is a strict no-op until then. Deferred (documented trigger) to avoid shipping untestable account-ordering to the live spend path.

## Triaged — no change required (already safe)

- **#11 utxo_count u16 overflow**: `add_utxo` already uses `checked_add(1)` (errors, never wraps); release profile has `overflow-checks = true`. Reaching 65 535 on-chain UTXOs is impractical.
- **#14 cancel deflates total_shielded**: `redeem` only calls `pool.sub_shielded`, **not** `tc.sub_shielded`; `cancel` mirrors it (`pool.add_shielded` only). Symmetric — the finding's premise does not hold here.
- **#29 / #31 re-initialization / data erasure**: `register_token` uses `create_pda_account` (CreateAccount fails on an existing account); `init_vk_registry` has an explicit already-initialized guard. Both `init()`s are only reachable via account creation.

## Deferred — needs a design decision (documented, not blindly patched)

- **Token-2022 transfer-fee on the withdrawal side (#38/#41, Info)**: deposit side is hardened (#4); the unshield/claim side and registration should **reject fee-on-transfer mints at `register_token`** (parse the mint's `TransferFeeConfig` extension). Recommended as a follow-up.

## Required coordinated client changes (breaking)

These on-chain fixes change values the SDK/prover must match in lockstep before deploy:

1. **#9** — SDK must include `requester` in the redeem bound-params-hash preimage: `sha256( [0;4] ‖ 0x02 ‖ sha256(scripts) ‖ chain_id_le ‖ stealth_data_hash ‖ requester32 )`.
2. **#10** — SDK/backend must derive the deposit-receipt PDA from seeds `["deposit_receipt", deposit_txid, deposit_vout_le]`.
3. **#13** — when a spent note was committed before a tree rotation, the SDK must (a) prove its merkle path against the frozen tree's root and (b) append that frozen `CommitmentTree` account to `transact`/`unshield`/`redeem` **immediately before** the optional proof_buffer (or last, if the proof is inline). No change needed for notes in the active tree.

Account-size changes (fresh accounts only; safe on devnet which is recreated): `UtxoRecord` 48→56 bytes.

## Remaining Info/Discussion (25 + the rest of 14)

Not individually patched this pass — they are design/operational tradeoffs (testnet4 difficulty edge cases, host-build SHA256 stub, static-PDA pre-funding DoS, non-canonical commitment encodings, policy signing-oracle scope) or duplicates of the fixes above. Recommend a dedicated follow-up pass with maintainer input.
