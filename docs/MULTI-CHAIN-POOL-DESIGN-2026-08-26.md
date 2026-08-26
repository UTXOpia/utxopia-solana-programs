# Multi-chain pools: BTC + ZEC

**Status:** design note, nothing built.
**Question it answers:** can one pool bridge more than one chain, with assets kept apart by `token_id`?
**Short answer:** the shielded half already does this. The bridging half does not, and ZEC's
proof-of-work is the thing that decides whether it ever can at Bitcoin's security level.

---

## 1. What already works

Multi-asset support inside a pool is **done**, and it is worth being precise about how much:

| Instruction | zkBTC-specific? | Evidence |
|---|---|---|
| `transact` | **no** — fully asset-agnostic | zero references to `pool.zkbtc_mint` |
| `shield` / `unshield` | mostly no | references are for native-SOL and vault selection, not asset identity |
| `redeem` / `complete_redemption` | **yes, deliberately** | `redeem.rs:169` rejects any token whose mint ≠ `pool.zkbtc_mint` |

`token_id = Poseidon(reduce_to_field(mint), 0)` (`register_token.rs:114`) — derived from the
Solana mint address, so every asset already needs an SPL/Token-2022 representation regardless.

In the circuit, `token` is a **single private signal shared by every input and output**, so a
JoinSplit cannot mix assets: the separation is enforced in-circuit, not by convention. All assets
share one commitment tree, i.e. **one anonymity set** — which is the desirable direction, and the
same choice Railgun makes.

**Consequence:** any asset that already has a wrapped SPL representation can be `register_token`'d
into an existing pool today and gets shield / transfer / unshield with its own `token_id`, no code
changes. What is missing is UTXOpia acting as the bridge itself rather than depending on someone
else's wrapper.

---

## 2. What forces the current shape

### 2.1 Two Solana programs, for one constant

`--features devnet` and `--features devnet-regtest` differ in exactly two places:

- `constants.rs:33` — `BTC_LIGHT_CLIENT_PROGRAM_ID`
- `lib.rs:258` + `instructions/mod.rs:74,85` — `DEVNET_CLOSE`, present only in regtest builds

Everything else is identical. `devnet-regtest = ["devnet"]`, so both builds get
`DEMO_REQUIRED_CONFIRMATIONS = 1` and the same ChadBuffer id. The two artifacts differ by **720
bytes**. A whole second program deployment exists because one 32-byte constant is compile-time.

That constant being compile-time is not an accident, and it buys something real: **no pool,
however it was initialized, can point at a light client the attacker deployed.** `INITIALIZE` is
permissionless (audit_1 F-AC-08), so if the light-client id were an account field, anyone could
stand up a pool naming a fake chain. It would only damage their own pool — mint→pool is injective
— but that is the exact shape of C-2 and F-BC-01: consensus rules decided by data.

### 2.2 The real blocker is the accounting, not the constant

`PoolState` carries the bridge ledger, and it is Bitcoin-shaped and **pool-level, not per-token**:

```
zkbtc_mint          [u8; 32]   the single "native asset" of this pool
total_btc_held      [u8; 8]
utxo_count          [u8; 2]
utxo_count_hi       [u8; 2]
pending_redemptions [u8; 8]
```

The comment above `redeem.rs:169` says why the restriction exists: *"otherwise another registered
token could be redeemed against the shared pool BTC accounting."* The guard is not conservatism —
it is load-bearing, because `total_btc_held` cannot simultaneously mean BTC and ZEC.

This shared state is also where audit_1 F-AR-04 lives (`pending_redemptions` uses saturating
arithmetic and can desynchronise permanently). Making the ledger per-asset fixes a real bug and
unblocks multi-chain in the same change.

---

## 3. ZEC: the part that decides everything

### 3.1 Only transparent ZEC is bridgeable at all

Shielded ZEC (Sapling/Orchard) hides value and recipient by construction, so there is nothing for
an SPV proof to attest. Bridging it would require the depositor to disclose to the bridge, which
defeats the point. **Scope is ZEC transparent (t-addr) only.** That is fine — it is a UTXO chain
with merkle-committed transactions, structurally the same as Bitcoin.

### 3.2 Equihash cannot be verified with the syscalls Solana has

Bitcoin's PoW check is two SHA-256 syscalls. `hash_meets_target` is effectively free.

Zcash uses **Equihash (200,9)**, whose hash function is **Blake2b**. The syscall surface Solana
exposes is:

```
sol_sha256   sol_keccak256   sol_blake3   sol_poseidon
sol_alt_bn128_*   sol_big_mod_exp   sol_curve_*
```

**There is no `blake2b` syscall.** `sol_blake3` is a different function and does not substitute.
So Equihash verification would run as pure BPF: 512 Blake2b-512 compressions per header, plus the
2^9 index sort and XOR-collision checks.

For scale, the most expensive thing this program does today is Groth16 verification, **measured at
97,159 CU** (2026-08-25, mollusk-svm 0.15, sbpf v3; ~98% of that is fixed-price syscalls). A
Blake2b compression is 12 rounds of 8 G-functions; 512 of them in interpreted BPF is a
**rough estimate of 700k–1M+ CU** before the sort — i.e. at or over the 1.4M per-instruction limit,
for a single header.

> **This estimate is not measured.** Before any of the work in §4 is scheduled, write the Blake2b
> compression in BPF and benchmark 512 iterations under mollusk. That one number decides the
> design. Everything below is contingent on it.

### 3.3 Three ways out, none free

| Option | Trust model | Cost |
|---|---|---|
| **A. Skip Equihash.** Verify chain linkage, difficulty and a compiled-in checkpoint only. | Not PoW. Whoever relays first, bounded by checkpoints. | Cheap, and honest only if labelled as a checkpointed bridge |
| **B. Prove PoW off-chain.** Relayer submits a Groth16 proof that the header's Equihash solution is valid. | Full PoW, if the circuit is right | ~97k CU to verify — **we already run this**. But an Equihash circuit is a very large build and its own trusted setup |
| **C. Attested.** N-of-M relayer signatures over the header. | Federated | Small; a different product |

Option B is unusually attractive here *only* because the Groth16 verifier is already deployed and
measured. It is still the largest single piece of work in this note.

### 3.4 Two more ZEC differences worth pricing

- **Retargeting.** Zcash adjusts difficulty **every block** (DigiShield-style), not every 2016.
  `required_bits_for_next_block` is Bitcoin's epoch model and would need a parallel implementation,
  not a parameter.
- **Header size.** A Zcash header carries the Equihash solution and is ~1487 bytes, against
  Bitcoin's 80. `MAX_BATCH_SIZE = 10` becomes ~14.8 KB of instruction data, past the transaction
  limit — header submission would have to go through ChadBuffer or shrink the batch. Note that
  under option A the solution does not need to be stored at all, which changes this number.

---

## 4. Phased plan

Each phase is independently valuable; nothing here is all-or-nothing.

**Phase 0 — measure Equihash (blocking).** Benchmark 512 Blake2b compressions in BPF. If it fits
under ~400k CU, ZEC gets Bitcoin's security model. If not, choose A or B in §3.3 *before* building
any abstraction, because A and B are not the same interface and abstracting over both is how you
get a leaky one.

**Phase 1 — per-asset bridge accounting.** Move `total_btc_held`, `utxo_count`,
`pending_redemptions` out of `PoolState` and into `TokenConfig`. Replace `pool.zkbtc_mint` with a
`TokenConfig.bridge` discriminant (`none` / `btc_spv` / …). `redeem.rs:169` relaxes from "must be
the pool's zkBTC" to "must be a token with a bridge". Fixes F-AR-04 on the way. **No new chain
required to justify this.**

**Phase 2 — light client id from a compile-time allowlist.** Keep the ids in the binary, but as an
array; `TokenConfig` stores an index, written once at registration. A pool can then choose its
chain, but only from a set fixed at build time, so a fabricated light client still cannot get in.
This collapses "support a new network" from *deploy a second program* to *add one constant and
upgrade* — and would have removed the need for two programs today.

**Phase 3 — extract a bridge adapter.** `utils/bitcoin.rs` (parsing) and `utils/sighash.rs`
(withdrawal construction) become a trait with BTC as the first implementation. Only worth doing
once Phase 0 has told us whether ZEC fits the same trait.

**Phase 4 — ZEC.** Header parser, DigiShield retarget, PoW per Phase 0's answer, t-addr script
matching, and an Ika dWallet for ZEC custody (secp256k1 signing already exists; ZEC t-addr
signing is P2PKH-shaped, so `sighash.rs` gains a variant rather than a rewrite).

---

## 5. Recommendation

**Do Phase 1 now, regardless of ZEC.** It is a real bug fix (F-AR-04), it removes a load-bearing
restriction that exists only because of a data-model limitation, and it is the prerequisite for
everything else.

**Do Phase 0 before promising ZEC to anyone.** The whole proposition — "one pool, several chains,
same security model" — rests on whether Equihash fits in a Solana instruction. If it does not, ZEC
is a *checkpointed* bridge next to a *proof-of-work* bridge in the same anonymity set, and that
difference has to be surfaced to users rather than hidden behind a shared `token_id`.

**One thing to keep in view.** audit_1 established that minting requires the pool authority's
signature (`complete_deposit.rs:141,163` — `mint_zkbtc` has exactly one call site). So the light
client is not the sole trust root; it is what stops *the operator* from minting unbacked tokens. A
weaker ZEC verifier therefore does not open the bridge to the public — it increases how much users
must trust the operator. That is a product decision, and it should be made deliberately rather than
inherited from a CU limit.

**XRP is out of scope, and should stay out.** XRPL has no proof-of-work to verify — consensus is
validator signatures — and no UTXOs, so `UtxoRecord`, `ReservedInput` and the taproot sighash path
have no analogue. It is a second kind of bridge (attestation), not a parameterisation of this one.
Adding it would mean the adapter trait in Phase 3 abstracts over two genuinely different trust
models, which is worse than having two explicit bridges.

---

## Appendix: evidence

Everything numeric above was checked on 2026-08-26 against `security/audit-1-remediation @ 01eec3e`:

- `transact.rs` references to `pool.zkbtc_mint`: 0 (grep)
- `--features devnet` vs `--features devnet-regtest`: 391,152 vs 391,872 bytes; the full cfg
  divergence is the three sites listed in §2.1 (grep over `programs/utxopia/src/`)
- Solana syscall surface: `solana-program` `syscalls/definitions.rs` — no `blake2b`
- Groth16 verify 97,159 CU: benchmarked 2026-08-25, joinsplit_1x2, 5 public inputs
- Deployed testnet4 and regtest programs both verified byte-identical to `01eec3e`
  (`bun run verify:deployed`)

Zcash protocol facts (Equihash 200,9 over Blake2b, per-block DigiShield retarget, ~1487-byte
header) are from the protocol spec, not measured here — confirm against the spec before Phase 4.
