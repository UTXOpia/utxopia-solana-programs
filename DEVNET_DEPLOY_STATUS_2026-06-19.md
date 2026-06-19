# Devnet deploy status — 2026-06-19

## TL;DR
The audit-fix programs are **validated end-to-end on localnet** (surfpool + real Bitcoin
regtest): deposit → shield → transfer → unshield → multi-output redeem all pass, exercising
both fixes (#3 MTP and #4 length-prefixed redeem bound-params).

A devnet **upgrade is currently blocked by devnet itself**, not by our code/toolchain.

## Proof that the block is on devnet's side (not ours)
- The local toolchain (`solana 3.1.15` / platform-tools `v1.52`) was installed **2026-05-12** —
  i.e. it is the **same toolchain** used for the working greenfield devnet deploy on 2026-06-15.
- A clean default `cargo build-sbf` of btc-light-client produces `e_flags=0` (SBPFv0), the same
  version as the program currently running on devnet.
- Deploying with a **brand-new buffer** (no resume possible) still fails with
  `Detected sbpf_version required by the executable which are not enabled`.
- **Definitive test:** dumping the binary devnet is *currently running* (`8hCSNKf…`) and trying
  to redeploy that exact binary back to its own program id is **also rejected** with the same
  error. Devnet refuses to (re)deploy the very program it is executing.

Conclusion: between 2026-06-15 and 2026-06-19 devnet changed its deployment rules — it still
*executes* existing SBPFv0 programs but no longer *accepts deploying/upgrading* them. This is a
cluster-side feature/policy change, outside this repo.

## Feature-gate state (devnet and mainnet, checked via `solana feature status`)
- `SIMD-0178/0179/0189` (enable deployment+execution of **SBPFv3**): **inactive** on both
  devnet and mainnet.
- `SIMD-0161` (disable SBPFv0 execution): inactive (so existing v0 still runs).

So devnet is in a transition window: old-version *deployment* is being phased out while SBPFv3
is **not yet activated** — temporarily, nothing in this version range deploys.

## Path forward (when devnet reopens deploys)
1. When devnet activates SBPFv3, build normally with the current toolchain
   (`cargo build-sbf --features devnet-regtest`, which emits v3) and upgrade:
   - `solana program extend <program-id> <bytes>` (the MTP code grew btc-lc 79600 → ~81904;
     its devnet ProgramData was already extended +60000 on 2026-06-19).
   - `solana program deploy … --program-id … --upgrade-authority ~/.config/solana/id.json`.
   - Upgrade authority `uFBMJSx…` (id.json) controls utxopia `E1CGHUi…`, btc-lc `8hCSNKf…`,
     and ChadBuffer `C5Rpjt…`, with ample devnet SOL.
2. No code/toolchain changes are needed for the upgrade itself.

## This commit
- `is_multiple_of` → `% == 0` in `difficulty.rs` and `commitment_tree.rs` — equivalent rewrite
  that also lets older (pre-Rust-1.87) platform-tools compile the programs, removing one
  obstacle if an older toolchain is ever needed for a lagging cluster.
- This status doc.

NOT included (intentionally left in the working tree): the deposit-path-consolidation WIP, and
the local-only ChadBuffer constant override in `chadbuffer.rs` used for the localnet e2e (the
real devnet ChadBuffer id `C5Rpjt…` must be restored before any devnet build).
