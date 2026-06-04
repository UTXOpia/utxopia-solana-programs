#!/usr/bin/env bun
/**
 * Verify Devnet Setup
 *
 * Quick verification of all account owners on devnet
 */

import { Connection, PublicKey } from "@solana/web3.js";

const RPC_URL = "https://api.devnet.solana.com";

// Expected addresses from .devnet-config.json (fresh deployment 2026-02-01)
const UTXOPIA_PROGRAM = new PublicKey("Hcqp9b83Hh2gN1bFWydZWJmpYQceo3PZCXobamSEj3bt");
const TOKEN_2022 = new PublicKey("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb");

const ACCOUNTS = {
  poolState: new PublicKey("DfUsWNKFfYZyEkupTpq5PEvxB1aQ8Wg2ZWVNeFuRvFcJ"),
  commitmentTree: new PublicKey("FdS67pn6wXCzjQ9Kc8asXMADEtHD1qZigbQ2i4wpbPKh"),
  zkbtcMint: new PublicKey("Bz4B3TYBEJigE9xLxQArbDH96LEZJ7Dj1AGL9BiQU63r"),
  poolVault: new PublicKey("5hsETnbpmDrewrhjuo9f6JjL9E4qjJqoR7U8XSTArLLw"),
};

async function main() {
  console.log("=".repeat(60));
  console.log("Devnet Setup Verification");
  console.log("=".repeat(60));

  const connection = new Connection(RPC_URL, "confirmed");

  console.log(`\nExpected UTXOpia program: ${UTXOPIA_PROGRAM.toBase58()}`);
  console.log(`Expected Token-2022: ${TOKEN_2022.toBase58()}\n`);

  // Check program exists
  const programInfo = await connection.getAccountInfo(UTXOPIA_PROGRAM);
  if (programInfo) {
    console.log(`✓ UTXOpia program exists`);
    console.log(`  Owner: ${programInfo.owner.toBase58()}`);
    console.log(`  Executable: ${programInfo.executable}`);
    console.log(`  Size: ${programInfo.data.length} bytes`);
  } else {
    console.log(`✗ UTXOpia program NOT FOUND`);
    return;
  }

  console.log("\n--- Account Owners ---\n");

  for (const [name, pubkey] of Object.entries(ACCOUNTS)) {
    const info = await connection.getAccountInfo(pubkey);
    if (info) {
      const owner = info.owner.toBase58();
      let status = "?";
      let expectedOwner = "";

      if (name === "poolState" || name === "commitmentTree") {
        expectedOwner = UTXOPIA_PROGRAM.toBase58();
        status = owner === expectedOwner ? "✓" : "✗";
      } else if (name === "zkbtcMint" || name === "poolVault") {
        expectedOwner = TOKEN_2022.toBase58();
        status = owner === expectedOwner ? "✓" : "✗";
      }

      console.log(`${status} ${name}`);
      console.log(`  Address: ${pubkey.toBase58()}`);
      console.log(`  Owner: ${owner}`);
      console.log(`  Expected: ${expectedOwner}`);
      console.log(`  Size: ${info.data.length} bytes`);

      // For pool state, check discriminator and authority
      if (name === "poolState" && info.data.length >= 68) {
        const discriminator = info.data[0];
        const version = info.data[1];
        const authority = new PublicKey(info.data.slice(4, 36));
        const mint = new PublicKey(info.data.slice(36, 68));
        console.log(`  Discriminator: ${discriminator}`);
        console.log(`  Version: ${version}`);
        console.log(`  Authority: ${authority.toBase58()}`);
        console.log(`  Mint: ${mint.toBase58()}`);
      }

      console.log();
    } else {
      console.log(`✗ ${name} NOT FOUND: ${pubkey.toBase58()}\n`);
    }
  }

  console.log("=".repeat(60));
  console.log("Verification Complete");
  console.log("=".repeat(60));
}

main().catch(console.error);
