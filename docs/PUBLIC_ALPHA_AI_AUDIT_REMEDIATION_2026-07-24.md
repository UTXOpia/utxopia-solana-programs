# Public Alpha AI Scan Remediation

Date: 2026-07-24

Source: `public-alpha.md` (CertiK AI-generated advisory scan). This is an internal
triage record, not a claim that the protocol has completed a CertiK security audit.

## Outcome

All Critical and Major findings were addressed. The actionable Medium findings were
also addressed. One Minor finding about optional sender memos remains open because a
correct fix requires moving memo construction before proof generation and versioning
the bound-parameter hash.

| Finding | Result | Remediation |
| --- | --- | --- |
| 1 | Accepted design | A relayer can submit only the exact proof-bound transfer. Nullifiers make submission idempotent; recipient and value cannot be changed. |
| 2 | Open (Minor) | Sender memos remain best-effort and are not proof-bound. Bind a versioned memo hash before proof generation in the next circuit/client revision. |
| 3 | Fixed | Registration rejects Token-2022 `PermanentDelegate`. |
| 4 | Fixed | Registration rejects Token-2022 `TransferHook`; unsupported hook semantics cannot block or alter pool transfers. |
| 5 | Fixed | Redemption requests track approvals per BTC input. Cancellation is blocked only after every input is approved. |
| 6 | Fixed | Dust change omitted from the BTC transaction is included in the effective miner-fee cap. |
| 7 | Fixed | UTXO records are keyed by the actual pool outpoint and created idempotently. Batched sweeps are now rejected. |
| 8 | Fixed | BTC bridge completion rejects disabled `TokenConfig` accounts. |
| 9 | Fixed before this pass | Deposit receipts use one canonical PDA seed scheme. |
| 10 | Fixed | Pool UTXOs store the full spendable output and are recorded once. Batched sweeps are rejected. |
| 11 | Fixed | Permissioned initialization rejects zero auditor and viewing keys. |
| 12 | Fixed | Initialization requires an initialized 8-decimal Token-2022 zkBTC mint controlled by the pool PDA, with safe authorities and extensions. |
| 13 | Obsolete | The reported legacy `verify_deposit` path was removed by the current deposit refactor. |
| 14 | Mitigated | Sweep mode is one-input/one-deposit only and credits exactly the BTC received by the pool, including sweep-fee effects. |
| 15 | Obsolete | The reported legacy permissioned-pool bypass path was removed. Permissioned completion uses the auditor-gated entry point. |
| 16 | Fixed | `RedemptionCompleted` documentation now includes `burn_amount` and `protocol_revenue` in the serialized layout. |
| 17 | Fixed | A full active commitment tree can be rotated permissionlessly; the transition remains restricted to the canonical full tree and next PDA. |
| 18 | Fixed | Retained BTC redemption revenue is credited to zkBTC `TokenConfig.accumulated_fees`, making it claimable through the existing fee path. |
| 19 | Fixed | Sweep deposits locate the unique P2TR output cryptographically derived from the OP_RETURN NPK and Ika internal key. |
| 20 | Fixed | Same remediation as finding 19; output order is no longer used for attribution. |
| 21 | Fixed | `redeem` decrements per-token shielded accounting. |
| 22 | Fixed | `cancel_redemption` restores per-token shielded accounting. |
| 23 | Fixed | A pool-level permanent VK freeze blocks initialization or update of every circuit variant after finalization. |

## Compatibility changes

- `redeem` now requires the zkBTC `TokenConfig` account to be writable.
- `complete_redemption` requires the zkBTC `TokenConfig` after the variable consumed-UTXO accounts.
- VK update now uses `[pool_state, vk_registry, authority]`.
- VK freeze now uses `[writable pool_state, writable vk_registry, authority]` and permanently freezes all variants.
- Batched BTC sweeps are no longer accepted; use direct-to-pool deposits or one-to-one sweeps.

The web relay, backend redemption client, ops VK scripts, redemption E2E script, and
fresh-devnet mint setup were updated with these account and authority requirements.

## Verification

- `cargo test -p utxopia --lib`: 103 passed
- `cargo check --workspace`: passed
- `cargo build-sbf --manifest-path programs/utxopia/Cargo.toml`: passed
- Backend `cargo check`: passed
- Web TypeScript and relay-route ESLint: passed
- Updated ops scripts bundle successfully with Bun

Before a public mainnet release, commission a manual audit and close finding 2 with a
versioned cross-client/circuit migration.
