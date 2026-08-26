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

**Measured 2026-08-26** (mollusk-svm 0.11, sbpf v3, `programs/equihash-bench`, cost isolated by
differencing 101 compressions against 1 so the entrypoint and loop setup cancel):

```
per BLAKE2b compression        5,380 CU
Equihash-200,9  (~512)     2,754,560 CU
transaction limit          1,400,000 CU     -> 197% of budget
Groth16 verify (2026-08-25)   97,159 CU     -> 28.4x
```

So Equihash verification **does not fit in one transaction**. It is about 2x over. Note the limit
is per *transaction*, not per instruction — splitting into several instructions inside one
transaction shares the same 1.4M ceiling and buys nothing.

My pre-measurement estimate in the first draft of this note was 700k–1M CU. It was low by ~3x,
which is the reason the measurement was made blocking rather than assumed.

### 3.3 What the number allows

| Option | Trust model | Verdict |
|---|---|---|
| **A. Verification resumed across transactions.** Partial BLAKE2b state in a PDA; ~3 transactions per header. | **Full proof-of-work** | **Viable, and the recommendation** |
| B. Prove Equihash off-chain with Groth16. | Full PoW | **Not viable — see below** |
| C. Skip Equihash; chain linkage + difficulty + compiled-in checkpoint. | Checkpointed, not PoW | Cheap; honest only if labelled as such |
| D. N-of-M relayer attestation. | Federated | Small; a different product |

**A is the answer, and it was missing from the first draft.** 2.75M CU is roughly two
transactions' worth, and Zcash blocks are ~75 seconds apart — three transactions per header is a
trivial ongoing cost. The pattern already exists in this codebase: ChadBuffer stages oversized
transaction data across calls for exactly this reason. A resumable Equihash verifier holds its
BLAKE2b state and index cursor in a PDA and finishes on the third call. Moderate build, full
Bitcoin-equivalent security, no new cryptography and no ceremony.

**B is dead, and the first draft was wrong to call it attractive.** It looked cheap because the
Groth16 verifier is already deployed at 97k CU — but that is the *verification* side. The circuit
is the problem. BLAKE2b is 64-bit adds, XORs and rotations; over a prime field each 64-bit XOR
costs a bit decomposition, so one compression is on the order of 10^5 constraints and 512 of them
lands near **50 million**. That needs a ptau beyond any public ceremony, hundreds of GB of RAM and
hours per proof, against a chain producing a block every 75 seconds. Proposing it was an error of
not costing the prover side; recorded here so it is not re-proposed.

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

**Phase 0 — measure Equihash. DONE, 2026-08-26.** 5,380 CU per compression, 2.75M for a header,
197% of a transaction. Implementation and benchmark in `programs/equihash-bench` (workspace-
excluded; delete once this note is settled). BLAKE2b is validated against RFC 7693 Appendix A.
Answer: native verification is possible but must be **resumed across ~3 transactions**, so ZEC can
have Bitcoin's trust model. Option A in §3.3.

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

**ZEC can have the same trust model as BTC.** That was the open question and it is now closed:
2.75M CU is expensive but not prohibitive, and resuming across three transactions costs a few
thousand lamports per 75-second block. There is no need to put a checkpointed bridge and a
proof-of-work bridge in the same anonymity set, which is the outcome the first draft was braced
for. Phase 4 should build the resumable verifier rather than reach for options C or D.

The one thing to size before committing: a resumable verifier means a PDA holding partial
consensus state between transactions, and partial state that an attacker can also write to is its
own risk surface. It needs the same treatment `extend_blockchain` got in F-BTC-03 — the
continuation must be bound to the batch that started it, not merely "some state that exists".

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
