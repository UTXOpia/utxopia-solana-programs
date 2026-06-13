# SDK and Frontend VK Registry Migration

This guide covers the migration from hardcoded JoinSplit Groth16 verification
keys to on-chain `VkRegistry` accounts. It applies to SDKs, frontends, relayers,
admin scripts, and deployment operators.

## Summary

- JoinSplit VKs are no longer embedded in the program binary.
- `VkRegistry` now stores the full verifier material: `vk_hash`, `delta_g2`,
  and IC points.
- `VkRegistry` account size changed from `256` bytes to `1060` bytes.
- `init_vk_registry` and `update_vk_registry` now accept full VK material, not
  only `vk_hash`.
- `transact`, `unshield`, and `redeem` must pass the matching `VkRegistry` PDA
  for the selected `(n_inputs, n_outputs)` proof shape.

## PDA Derivation

Each JoinSplit shape has one registry PDA:

```ts
export function deriveVkRegistryPDA(
  programId: PublicKey,
  nInputs: number,
  nOutputs: number,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("vk_registry"), Buffer.from([nInputs]), Buffer.from([nOutputs])],
    programId,
  );
}
```

Do not use a global VK account. Always derive the registry from the exact proof
shape used in the instruction.

## Registry Payload

`init_vk_registry` (`disc = 6`) and `update_vk_registry` (`disc = 7`) use the
same data layout:

```ts
disc(1)
+ n_inputs(1)
+ n_outputs(1)
+ vk_hash(32)
+ delta_g2(128)
+ ic_len(1)
+ ic_points(64 * ic_len)
```

Validation rules:

- `n_inputs >= 1`
- `n_outputs >= 1`
- `n_inputs + n_outputs <= 10`
- `ic_len === 3 + n_inputs + n_outputs`
- `vk_hash` is 32 bytes
- `delta_g2` is 128 bytes
- every IC point is 64 bytes
- no trailing bytes

Builder example:

```ts
export type JoinSplitVkMaterial = {
  nInputs: number;
  nOutputs: number;
  vkHash: Buffer;
  deltaG2: Buffer;
  ic: Buffer[];
};

export function buildVkRegistryData(
  discriminator: 6 | 7,
  vk: JoinSplitVkMaterial,
): Buffer {
  if (vk.nInputs < 1 || vk.nOutputs < 1 || vk.nInputs + vk.nOutputs > 10) {
    throw new Error("JoinSplit dimensions must satisfy nInputs + nOutputs <= 10");
  }
  if (vk.vkHash.length !== 32) throw new Error("vkHash must be 32 bytes");
  if (vk.deltaG2.length !== 128) throw new Error("deltaG2 must be 128 bytes");

  const expectedIcLen = 3 + vk.nInputs + vk.nOutputs;
  if (vk.ic.length !== expectedIcLen) {
    throw new Error(`expected ${expectedIcLen} IC points`);
  }
  for (const [i, point] of vk.ic.entries()) {
    if (point.length !== 64) throw new Error(`IC[${i}] must be 64 bytes`);
  }

  return Buffer.concat([
    Buffer.from([discriminator, vk.nInputs, vk.nOutputs]),
    vk.vkHash,
    vk.deltaG2,
    Buffer.from([vk.ic.length]),
    ...vk.ic,
  ]);
}
```

## Admin Instructions

Initialize a registry:

```ts
const [vkRegistry] = deriveVkRegistryPDA(programId, nInputs, nOutputs);

const keys = [
  { pubkey: poolState, isSigner: false, isWritable: false },
  { pubkey: vkRegistry, isSigner: false, isWritable: true },
  { pubkey: authority, isSigner: true, isWritable: true },
  { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
];

const data = buildVkRegistryData(6, vk);
```

Update an existing registry:

```ts
const keys = [
  { pubkey: vkRegistry, isSigner: false, isWritable: true },
  { pubkey: authority, isSigner: true, isWritable: false },
];

const data = buildVkRegistryData(7, vk);
```

Only the pool authority can initialize registries. Only the registry authority
can update them. `init_vk_registry` creates the PDA when it does not exist.

## JoinSplit Builders

All JoinSplit instructions must pass the registry at account index `2`.

Applies to:

```ts
TRANSACT = 13
UNSHIELD = 14
REDEEM = 15
```

Base account order:

```ts
[
  poolState,
  commitmentTree,
  deriveVkRegistryPDA(programId, nInputs, nOutputs)[0],
  user,
  systemProgram,
  // remaining instruction-specific accounts...
]
```

Before creating a user transaction, fetch the registry and fail early if:

- the account does not exist
- the owner is not the UTXOpia program
- discriminator is not `0x14`
- `nInputs` or `nOutputs` do not match the proof shape
- `icLen !== 3 + nInputs + nOutputs`

Frontend routing should hide or disable JoinSplit shapes whose registry has not
been initialized and verified.

## Account Parser

New `VkRegistry` layout:

```ts
const VK_REGISTRY_LEN = 1060;
const VK_REGISTRY_DISCRIMINATOR = 0x14;
const MAX_IC_POINTS = 13;

type VkRegistry = {
  discriminator: number;       // offset 0
  nInputs: number;             // offset 2
  nOutputs: number;            // offset 3
  authority: PublicKey;        // offset 4
  vkHash: Buffer;              // offset 36, 32 bytes
  deltaG2: Buffer;             // offset 68, 128 bytes
  icLen: number;               // offset 196
  ic: Buffer[];                // offset 228, 64 bytes each
};
```

Parser example:

```ts
export function parseVkRegistry(data: Buffer): VkRegistry {
  if (data.length < VK_REGISTRY_LEN) throw new Error("VkRegistry account too small");
  if (data[0] !== VK_REGISTRY_DISCRIMINATOR) {
    throw new Error("Invalid VkRegistry discriminator");
  }

  const nInputs = data[2];
  const nOutputs = data[3];
  const icLen = data[196];
  const expectedIcLen = 3 + nInputs + nOutputs;
  if (icLen !== expectedIcLen || icLen > MAX_IC_POINTS) {
    throw new Error("Invalid VkRegistry IC length");
  }

  const ic: Buffer[] = [];
  for (let i = 0; i < icLen; i++) {
    const start = 228 + i * 64;
    ic.push(data.subarray(start, start + 64));
  }

  return {
    discriminator: data[0],
    nInputs,
    nOutputs,
    authority: new PublicKey(data.subarray(4, 36)),
    vkHash: data.subarray(36, 68),
    deltaG2: data.subarray(68, 196),
    icLen,
    ic,
  };
}
```

## Ops Rollout

For each supported JoinSplit shape:

1. Load the VK artifact for that `(n_inputs, n_outputs)` shape.
2. Convert it into `vkHash`, `deltaG2`, and ordered IC points.
3. Derive `["vk_registry", n_inputs, n_outputs]`.
4. Send `init_vk_registry` from the pool authority.
5. Fetch and parse the created account.
6. Compare `vkHash`, `deltaG2`, and every IC point against the source artifact.
7. Enable that shape in SDK/frontend config only after verification passes.

For VK rotation, send `update_vk_registry` and repeat the same fetch-and-compare
verification. User JoinSplit flows should be paused or shape-gated while a
registry is missing or being rotated.

## SDK Checklist

- Add full `init_vk_registry` and `update_vk_registry` data builders.
- Update `VkRegistry` parser size from `256` to `1060`.
- Add `deltaG2`, `icLen`, and `ic` parser fields.
- Derive `vkRegistry` from `(nInputs, nOutputs)` in every JoinSplit builder.
- Validate registry existence before submitting `transact`, `unshield`, or
  `redeem`.
- Remove any dependency on hardcoded Rust VK module names such as
  `joinsplit_1x2_vk`.
- Remove any SDK call path that expects `load_joinsplit_vk` to exist.

## Frontend Checklist

- Gate each JoinSplit shape on a verified registry account.
- Show a clear setup error when the required registry is missing.
- Disable unsupported shapes instead of letting the transaction fail on-chain.
- Refresh admin/ops UI to upload or select full VK material, not only `vk_hash`.
- Show registry authority, VK hash, dimensions, and IC length in admin screens.

## Verification Commands

After updating SDK/frontend code:

```bash
rg "load_joinsplit_vk|joinsplit_.*_vk|VkRegistry.*256" .
bun run check:scripts
bun test tests/**/*.test.ts
cargo test --workspace
cargo build-sbf --features devnet
cargo build-sbf --features mainnet
```
