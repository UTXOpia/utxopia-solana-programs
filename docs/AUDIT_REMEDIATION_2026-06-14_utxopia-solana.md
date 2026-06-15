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
| Discussion | 12    | 10    | 1            | 0                | 1                  |
| **Total**  | 43    | **28**| **5**        | **9**            | **1**              |

Only f03 remains deferred (documented with a concrete remediation plan below); it requires a
reviewed consensus-reorg change and should not be rushed into consensus code.

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
| f32 | disc | verify_deposit missing UtxoRecord | `verify_deposit` now records the sweep's pool output as a `UtxoRecord` + `pool.add_utxo` (idempotent for batched sweeps), via an OPTIONAL trailing account so rollout is non-breaking. Mirrors `complete_deposit`. The active deposit path (`complete_deposit`) already did this; the verify_deposit-intent backend caller is dormant/incompatible and annotated for revival. |

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

One item remains, **unsafe to rush** — it needs a reviewed consensus-reorg change with tests
(maintainer-accepted as planned work on 2026-06-15, not landed blind into consensus code).
(f32 was fixed; see the Fixed table.)

- **f03 (disc) — multi-batch reorg HeightIndex corruption.** When a fork is built across several
  `extend_blockchain` calls and only later overtakes, only the final batch's `HeightIndex` entries
  are reindexed; ancestor heights from earlier non-canonical batches keep pointing at the old
  chain. **Impact is finality/PoW-gated** (a stale entry must be at a height `<= finalized_height`,
  which on mainnet requires out-PoW past finality; cheap only on regtest, cf. f00).

  **Recommended plan (require canonical parent — simplest correct fix):** add the parent's
  `HeightIndex` account to `extend_blockchain` and assert it is canonical
  (`HeightIndex[parent_height].block_hash == parent_hash`) before processing. This forbids the
  only vulnerable pattern — building a detached fork incrementally across multiple calls (the
  non-canonical `else` branch) — because a later batch's parent (a not-yet-canonical fork tip)
  would fail the check. Under this rule a promotion's batch always spans exactly
  `[parent_height+1 ..= new_tip]`, so the existing per-batch HeightIndex reindex is *complete*:
  no ancestor height can keep a stale entry. Stale entries above `new_tip` are harmless (they're
  `> finalized_height`, so `verify_transaction` rejects them).
  - Trade-off: reorgs must be submitted in a single call from a canonical common ancestor
    (bounded by `n` headers/call); incremental multi-batch fork building is no longer allowed.
    Acceptable for realistic (shallow) reorgs; confirm against the backend's submission strategy.
  - Adds one account (parent HeightIndex) → backend coordination.
  - **Why still deferred:** consensus-critical with a catastrophic failure mode (a wrong canonical
    check could reject all valid extensions → halt header ingestion → bridge stops). MUST land
    with reorg integration tests, which don't exist in this repo yet. Do not merge blind.

> **f32 update (FIXED 2026-06-15):** implemented by mirroring `complete_deposit` — `verify_deposit`
> now records the sweep's pool output as a `UtxoRecord` + `pool.add_utxo`, idempotent for batched
> sweeps, via an OPTIONAL trailing account (non-breaking rollout). Records the pool output's actual
> value, so no double-count. The active deposit path (`complete_deposit`) already did this; the
> dormant/incompatible verify_deposit-intent backend caller is annotated for revival. Residual
> (separate, minor): verify_deposit credits the gross deposit while the recorded UTXO is the
> post-sweep-fee pool output, so tracked BTC trails minted zkBTC by the sweep fee — same class as
> the (accepted) deposit-fee handling, bounded and tiny.
