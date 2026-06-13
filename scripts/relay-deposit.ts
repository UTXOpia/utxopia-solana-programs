#!/usr/bin/env bun
/**
 * BTC deposit relay CLI entrypoint.
 *
 * Keep relay behavior in scripts/test-flow/deposit.ts so this file stays thin.
 */

import { relayDepositCli } from "./test-flow/deposit";

function readArgs() {
  const args = new Map<string, string>();
  for (let i = 2; i < process.argv.length; i++) {
    const key = process.argv[i];
    if (!key?.startsWith("--")) {
      throw new Error("Usage: bun scripts/relay-deposit.ts --txid <txid> --zkbtc-mint <mint> --pool-vault <vault> --sweep-vout <n> [--submit-headers]");
    }
    if (key === "--submit-headers") {
      args.set("submit-headers", "true");
      continue;
    }
    const value = process.argv[++i];
    if (value === undefined) throw new Error(`Missing value for ${key}`);
    args.set(key.slice(2), value);
  }

  return {
    mode: args.get("mode") as "complete" | "verify" | undefined,
    txid: args.get("txid"),
    sweepTxid: args.get("sweep-txid"),
    depositTxid: args.get("deposit-txid"),
    blockHash: args.get("block-hash"),
    blockHeight: args.get("block-height") ? Number(args.get("block-height")) : undefined,
    sweepVout: args.get("sweep-vout") ? Number(args.get("sweep-vout")) : undefined,
    zkbtcMint: args.get("zkbtc-mint"),
    poolVault: args.get("pool-vault"),
    tokenProgram: args.get("token-program"),
    poolConfig: args.get("pool-config"),
    depositIntent: args.get("deposit-intent"),
    npk: args.get("npk"),
    ephemeralPubkey: args.get("ephemeral-pubkey"),
    esploraUrl: args.get("esplora-url"),
    submitHeaders: args.get("submit-headers") === "true",
  };
}

async function main(): Promise<void> {
  await relayDepositCli(readArgs());
}

main().catch((err) => {
  console.error("\nRelay deposit failed");
  console.error(err);
  process.exit(1);
});
