#!/usr/bin/env bun
/**
 * Localnet Setup — Fresh validator + build + deploy + Bitcoin regtest
 *
 * Kills existing validator, rebuilds contracts with --features localnet,
 * starts a fresh solana-test-validator with BN254 support, starts Bitcoin
 * regtest Docker, and deploys all programs.
 *
 * Run:
 *   bun run setup:localnet
 *
 * After this, run the flow tests:
 *   bun run test:flows
 */

import { Connection, LAMPORTS_PER_SOL, Keypair } from "@solana/web3.js";
import { execSync } from "child_process";
import * as path from "path";
import * as fs from "fs";
import { fileURLToPath } from "url";
import { setupRegtest, fetchBlockHash } from "./regtest-helpers.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT = path.join(__dirname, "..");

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";

async function main() {
  console.log("============================================================");
  console.log("UTXOpia Localnet Setup (with Bitcoin regtest)");
  console.log("============================================================");

  // 1. Kill existing validator
  console.log("\n1. Killing existing solana-test-validator...");
  try { execSync("pkill -f solana-test-validator", { stdio: "ignore" }); } catch {}
  await new Promise(r => setTimeout(r, 2000));
  console.log("   Done");

  // 2. Build contracts with localnet feature
  console.log("\n2. Building contracts with --features localnet...");
  execSync("cargo build-sbf --features localnet", {
    cwd: ROOT,
    stdio: "inherit",
  });

  // 3. Start fresh validator with BN254 pairing support
  console.log("\n3. Starting fresh solana-test-validator...");
  const validatorProc = Bun.spawn(
    ["solana-test-validator", "--clone-feature-set", "--url", "devnet", "--reset"],
    { stdout: "ignore", stderr: "ignore" },
  );

  // Wait for validator to be ready
  const conn = new Connection(RPC_URL, "confirmed");
  for (let i = 0; i < 30; i++) {
    try {
      await conn.getSlot();
      console.log("   Validator ready");
      break;
    } catch {
      if (i === 29) throw new Error("Validator failed to start in 30s");
      await new Promise(r => setTimeout(r, 1000));
    }
  }

  // 4. Start Bitcoin regtest Docker
  const deployEnv: Record<string, string> = { ...process.env as Record<string, string> };
  console.log("\n4a. Setting up Bitcoin regtest Docker...");
  const regtest = await setupRegtest();

  // Fetch block hash at the tip height for light client init
  const startHeight = regtest.tipHeight;
  const startHash = await fetchBlockHash(startHeight);
  console.log(`   Using BTC start height=${startHeight}, hash=${startHash.slice(0, 32)}...`);

  deployEnv.BTC_NETWORK = "regtest";
  deployEnv.BTC_START_HEIGHT = String(startHeight);
  deployEnv.BTC_START_HASH = startHash;
  deployEnv.BITCOIN_API_URL = "http://localhost:3000/regtest/api";

  // 5. Deploy programs + initialize (skip demo notes for clean tree)
  console.log("\n4b. Deploying programs...");
  execSync("bun run scripts/deploy-localnet.ts --skip-demo", {
    cwd: ROOT,
    stdio: "inherit",
    env: deployEnv,
  });

  // 6. Airdrop to authority
  console.log("\n5. Ensuring authority has SOL...");
  const keypairPath = process.env.KEYPAIR || `${process.env.HOME}/.config/solana/id.json`;
  const authority = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(keypairPath, "utf-8"))),
  );
  const balance = await conn.getBalance(authority.publicKey);
  if (balance < 2 * LAMPORTS_PER_SOL) {
    const sig = await conn.requestAirdrop(authority.publicKey, 10 * LAMPORTS_PER_SOL);
    await conn.confirmTransaction(sig);
    console.log(`   Airdropped 10 SOL to ${authority.publicKey.toBase58()}`);
  } else {
    console.log(`   Authority has ${(balance / LAMPORTS_PER_SOL).toFixed(1)} SOL`);
  }

  console.log("\n============================================================");
  console.log("SETUP COMPLETE — Validator running, programs deployed");
  console.log("Bitcoin regtest Docker running (Esplora at http://localhost:3000/regtest/api)");
  console.log("============================================================");
  console.log("\nNow run:  bun run test:flows");
}

main().catch((err) => {
  console.error("Setup failed:", err);
  process.exit(1);
});
