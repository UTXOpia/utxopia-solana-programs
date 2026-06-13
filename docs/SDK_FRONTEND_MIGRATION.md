# SDK and Frontend Migration

This guide covers the client-facing changes from the pre-launch Pinocchio cleanup.
It applies to SDKs, frontends, relayers, scripts, and indexers that build UTXOpia
instructions or parse UTXOpia accounts.

## Summary

- `PoolConfig` is now Ika-only and is `129` bytes.
- `set_pool_config` now requires all Ika custody fields in one strict payload.
- `complete_deposit` and `verify_deposit` require `PoolConfig`.
- `init_tree` and `set_pool_script` were removed from the program router.
- `PoolState.frost_vault` was renamed to `deposit_vault`.
- Discriminator `16` is no longer listed as a reserved SDK instruction.

## Instruction Changes

### `initialize` (`disc = 0`)

The account order is unchanged, but rename account 4 in clients:

```ts
[
  poolState,
  commitmentTree,
  zkbtcMint,
  poolVault,
  depositVault,
  authority,
  systemProgram,
]
```

The instruction data remains:

```ts
disc(1) + pool_bump(1) + tree_bump(1) + deposit_fee_bps(2 LE) + withdrawal_fee_bps(2 LE)
```

Builder example:

```ts
const data = Buffer.alloc(7);
data[0] = 0;
data[1] = poolBump;
data[2] = treeBump;
data.writeUInt16LE(depositFeeBps, 3);
data.writeUInt16LE(withdrawalFeeBps, 5);
```

### `set_pool_config` (`disc = 2`)

Old clients may have sent only `pool_script`, or `pool_script + group_pub_key`.
That is no longer valid.

New payload:

```ts
disc(1)
+ pool_script_len(1)
+ pool_script(N, 1..=34)
+ ika_dwallet(32)
+ ika_dwallet_xonly_pubkey(32)
+ cpi_authority_bump(1)
```

Builder example:

```ts
export function buildSetPoolConfigData(args: {
  poolScript: Buffer;
  ikaDwallet: PublicKey;
  ikaDwalletXonlyPubkey: Buffer;
  cpiAuthorityBump: number;
}): Buffer {
  if (args.poolScript.length < 1 || args.poolScript.length > 34) {
    throw new Error("poolScript length must be 1..=34");
  }
  if (args.ikaDwalletXonlyPubkey.length !== 32) {
    throw new Error("ikaDwalletXonlyPubkey must be 32 bytes");
  }

  return Buffer.concat([
    Buffer.from([2, args.poolScript.length]),
    args.poolScript,
    args.ikaDwallet.toBuffer(),
    args.ikaDwalletXonlyPubkey,
    Buffer.from([args.cpiAuthorityBump]),
  ]);
}
```

### `complete_deposit` (`disc = 11`)

`PoolConfig` is now required. Do not omit this account.

Account 14:

```ts
{ pubkey: poolConfig, isSigner: false, isWritable: false }
```

The credited Bitcoin output must match `PoolConfig.pool_script`; clients should
show a clear setup error if `PoolConfig` has not been initialized before deposit
completion.

### `verify_deposit` (`disc = 25`)

`PoolConfig` is now required. Do not omit this account.

Account 13:

```ts
{ pubkey: poolConfig, isSigner: false, isWritable: false }
```

The program verifies the user's Taproot deposit output using
`PoolConfig.ika_dwallet_xonly_pubkey`, so SDK deposit address derivation must use
the same x-only internal key.

### Removed Instructions

Remove SDK/frontend builders, routes, admin buttons, and docs for:

```ts
INIT_TREE = 28
SET_POOL_SCRIPT = 29
```

Do not expose discriminator `16` as a supported or reserved SDK action.
Proof-checked BTC withdrawals start at `REDEEM = 15`.

## Account Parser Changes

### `PoolConfig`

New layout:

```ts
const POOL_CONFIG_LEN = 129;

type PoolConfig = {
  discriminator: number;              // offset 0
  poolScriptLen: number;              // offset 1
  poolScript: Buffer;                 // offset 2, max 34 bytes
  ikaDwallet: PublicKey;              // offset 36
  ikaDwalletXonlyPubkey: Buffer;      // offset 68, 32 bytes
  cpiAuthorityBump: number;           // offset 100
};
```

Parser example:

```ts
export function parsePoolConfig(data: Buffer): PoolConfig {
  if (data.length < 129) throw new Error("PoolConfig account too small");
  if (data[0] !== 0x0a) throw new Error("Invalid PoolConfig discriminator");

  const poolScriptLen = data[1];
  if (poolScriptLen > 34) throw new Error("Invalid pool script length");

  return {
    discriminator: data[0],
    poolScriptLen,
    poolScript: data.subarray(2, 2 + poolScriptLen),
    ikaDwallet: new PublicKey(data.subarray(36, 68)),
    ikaDwalletXonlyPubkey: data.subarray(68, 100),
    cpiAuthorityBump: data[100],
  };
}
```

Remove parser fields for:

```ts
group_pub_key
groupPubKey
hasGroupPubKey
```

### `PoolState`

The byte layout did not move, but rename the field at offset `100..132`:

```ts
depositVault = new PublicKey(data.subarray(100, 132));
```

Remove public SDK naming for `frostVault`.

## Deposit Address Derivation

For OP_RETURN-free deposits, derive the user's Taproot deposit address using:

```ts
internalKey = poolConfig.ikaDwalletXonlyPubkey
tweak = TapTweak(internalKey || npk)
outputKey = internalKey + tweak * G
```

The same `npk` must be stored in `DepositIntent`; `verify_deposit` checks that
the raw deposit transaction contains an output for this tweaked key.

## Frontend Checklist

- Require PoolConfig setup before enabling deposit flows.
- Show configured pool script, Ika dWallet, and x-only key in admin screens.
- Remove UI for FROST group key setup.
- Remove UI/actions for tree migration and pool-script migration.
- Rename labels from `Frost Vault` to `Deposit Vault`.
- Update generated TypeScript account types and constants.
- Update any hardcoded `PoolConfig` size from `161` to `129`.
- Make deposit completion fail early client-side when `PoolConfig` is missing.

## Regeneration Checklist

After updating SDK/frontend code:

```bash
bun run check:scripts
bun test tests/**/*.test.ts
cargo test --workspace
cargo build-sbf --features devnet
cargo build-sbf --features mainnet
```
