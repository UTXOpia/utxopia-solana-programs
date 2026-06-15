# Audit Remediation — `utxopia-solana.json` (2026-06-14, 43 findings)

Disposition of every finding in the 2026-06-14 audit report. Status set 2026-06-15.
Verification was done with parallel triage agents against the working tree; fixes are on
branch `audit-2026-06-14-fixes` (commits `214069d`, `5467f0d`) plus the backend branch
`audit-2026-06-14-f12-alignment`.

## Summary

| Severity   | Count | Fixed | Accepted/Doc | Already-fixed/FP | Deferred (planned) |
|------------|-------|-------|--------------|------------------|--------------------|
| Critical   | 1     | 1     | 0            | 0                | 0                  |
| Major      | 4     | 4     | 0            | 0                | 0                  |
| Medium     | 9     | 7     | 0            | 2                | 0                  |
| Minor      | 4     | 4     | 0            | 0                | 0                  |
| Info       | 13    | 2     | 4            | 7                | 0                  |
| Discussion | 12    | 9     | 1            | 0                | 2                  |
| **Total**  | 43    | **27**| **5**        | **9**            | **2**              |

Deferred (f03, f32) are documented with concrete remediation plans below; they require
consensus-reorg design / cross-component coordination and should be scheduled as reviewed work,
not rushed into consensus code.

## Fixed (on-chain)

| ID  | Sev | Title (short) | Fix |
|-----|-----|---------------|-----|
| f12 | crit | Unvalidated `btc_sighash` signing oracle | On-chain BIP-341 sighash reconstruction (`utils/sighash.rs`) bound to reserved UTXOs + recipient; approves only program-derived digest. |
| f04 | major | Prefund DoS (BlockHeader/HeightIndex) | `create_or_claim_pda` prefund-resistant create. |
| f24 | major | Prefund DoS (`create_pda_account`) | Transfer+Allocate+Assign fallback. |
| f14 | major | Incomplete cancellation strands UTXOs | `utxo_count == reserved_count` completeness. |
| f15 | major | Unbacked bridge fee claims | Mint gross `amount_sats` so accumulated_fees is backed. |
| f05 | med | Genesis prefund DoS | shared prefund-resistant create. |
| f09 | med | VerifiedTransaction prefund DoS | shared prefund-resistant create. |
| f10 | med | Valid merkle proofs wrongly rejected | removed `sibling == current` rejection. |
| f18 | med | Subset-UTXO redemption completion | `consumed_count == reserved_count`. |
| f19 | med | Dust recipient redemption | recipient tolerance floored at 1%. |
| f29 | med | unshield recipient == vault | reject self-transfer. |
| f36 | med | bridge bypasses deposit_cap | enforce cap in both bridge paths. |
| f34 | med | u16 UTXO counter saturation | widened to u32 (migration-free). |
| f02 | minor | root-history eviction | ROOT_HISTORY_SIZE 100→256. |
| f13 | minor | cancel utxo_count drift | `add_utxos(amount, count)` symmetric restore. |
| f26 | minor | non-unique request_id reservations | bind reservation to unique redemption PDA. |
| f30 | minor | per-output fee truncation bypass | floor fee to 1 sat. |
| f06 | disc | reinit prefund DoS | shared prefund-resistant create. |
| f07 | info | stale-parent extension after reinit | `BlockHeader.reinit_epoch` binding (also closes f08). |
| f23 | disc | O(N) `validate_frozen_tree` | stored `tree_index`, O(1) check. |
| f40 | disc | `segwit_body_end` overflow | checked arithmetic. |
| f37 | info | TokenConfig re-init wipe | `AlreadyInitialized` guard. |
| f01 | disc | native SHA-256 fallback | host tests now use the real `sha2` digest (dev-dep). |
| f27 | disc | vault not pool-controlled | `register_token` asserts vault authority == pool PDA. |
| f11 | disc | timelocked bounds strand deposits | `process_execute_pool_update` is now authority-only (removes third-party activation timing); min/max kept as admission policy, `deposit_cap` is the hard invariant. |

## Accepted-by-design / documented (no code change)

- **f00 (info) — regtest chainwork grindable.** Regtest deliberately skips PoW/difficulty
  (matches Bitcoin Core regtest). Not a production-bearing mode. Production networks
  (mainnet/testnet4) enforce PoW + difficulty continuity.
- **f16 (info) — sweep binds to first deposit output.** The deposit output value is used only as
  a `min()` cap; the credited amount is bound to the pool-script sweep output. User can only ever
  be under-credited, never over-credited — no theft.
- **f33 (info) — bridge uses pool-level (not per-token) min/max.** Bridge is BTC/zkBTC-only and
  authority-gated; pool-level bounds are operative. Per-token bounds are an SPL-shield concern.
- **f38 (info) — reorged-out VerifiedTransaction proofs.** A VT can only be minted at
  `height <= finalized_height` (monotonic), so orphaning one requires out-PoW past the finality
  horizon — infeasible on mainnet. Shares the regtest-insecure assumption (f00).
- **f28 (disc) — unauthenticated sender memos.** Confirmed disposition (product decision): memos
  are best-effort, NON-authoritative metadata. Change-note recovery does not depend on them
  (commitment + leaf_index are emitted via the stealth announcement). No wire/circuit change; the
  SDK should document memos as non-authoritative.

## Already-fixed / false-positive (verified)

- **f08** — residual closed by f07 (epoch binding).
- **f17** — batched sweep: per-deposit credit binding + `min()` cap already present.
- **f22** — VK registry PDA squatting: resolved by prefund-resistant `create_pda_account`.
- **f25** — `commitment_tree_info` forgery: every caller runs `validate_active_tree_pda` first.
- **f31** — multiple deposits to same NPK: receipts keyed by `(txid, vout)`.
- **f35** — RedemptionRequest re-init: call site guards + PDA pinning.
- **f39** — OP_RETURN hijack: credited amount bound to traced deposit output + pool_tag check.
- **f41** — `find_output_by_script` first-match: recipient sum iterates all outputs; residual is
  f20 (fixed).
- **f42** — opaque sighash: closed by f12 (amount/fee now bound to the reconstructed sighash).

## Requires coordinated / consensus work (not fixed in this pass)

These two are real but unsafe to rush; each needs cross-component design. **Disposition
accepted by the maintainer on 2026-06-15** as planned, review-gated work items (not landed
blind into consensus/custody code). f32 additionally needs a sweep-fee accounting decision +
a new instruction account (backend/SDK) + a deposit→redemption integration test; f03 needs a
reviewed consensus-reorg change with tests.

- **f03 (disc) — multi-batch reorg HeightIndex corruption.** When a fork is built across several
  `extend_blockchain` calls and only later overtakes, only the final batch's `HeightIndex` entries
  are reindexed; ancestor heights from earlier non-canonical batches keep pointing at the old
  chain. **Impact is finality/PoW-gated** (a stale entry must be at a height `<= finalized_height`,
  which on mainnet requires out-PoW past finality; cheap only on regtest, cf. f00). **Plan:**
  enforce the invariant that promotion to canonical leaves every `HeightIndex` in
  `[divergence_height ..= tip_height]` pointing at the canonical fork — i.e. require the caller to
  pass (and the program to rewrite) the full HeightIndex range from the divergence point, or
  forbid promoting a fork in a call that doesn't itself reindex every height since divergence.
  Consensus-critical; needs dedicated review + tests before landing.

- **f32 (disc) — missing UtxoRecord in `process_verify_deposit`.** The DepositIntent path mints a
  shielded note but creates no `UtxoRecord` and never calls `pool.add_utxo`, so the corresponding
  BTC is a minted liability invisible to the redemption asset set (custody understated). Note:
  verify_deposit verifies a SWEEP that spends the NPK-tweaked deposit output, so the recordable
  UTXO is the sweep's POOL-address output — spendable by the pool main key, **no signer tweak
  needed**. **Plan:** mirror `complete_deposit`'s record creation — `find_output_by_script(pool_
  script)` on the sweep, create `UtxoRecord[sweep_txid, sweep_vout]`, `pool.add_utxo` — with an
  extra writable account. The care required (why it's deferred, not blind-edited): it must
  **coordinate dedup with `complete_deposit`** so a sweep output isn't recorded twice and
  `total_btc_held` isn't double-counted (which would over-credit redemptions → insolvency the
  other direction). Needs the deposit/sweep architecture confirmed + the backend to pass the
  account. Tractable but must be reviewed against the full deposit flow before landing.
