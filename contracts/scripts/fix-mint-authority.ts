#!/usr/bin/env bun
/**
 * Transfer mint authority to pool PDA
 */

import { Connection, Keypair, PublicKey, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID, createSetAuthorityInstruction, AuthorityType } from "@solana/spl-token";
import { derivePoolStatePDA } from "@utxopia/sdk";
import * as fs from "fs";

const RPC_URL = "https://api.devnet.solana.com";

function loadKeypair(keyPath: string): Keypair {
  const absolutePath = keyPath.replace("~", process.env.HOME || "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

async function main() {
  console.log("=".repeat(60));
  console.log("Transfer Mint Authority to Pool PDA");
  console.log("=".repeat(60));

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = loadKeypair("~/.config/solana/johnny.json");

  const zkbtcMint = new PublicKey("BdUFQhqKpzYVHVg8cQoh7JdpSoHFtwKM4A48AFAjKFAK");
  const [poolStatePDA] = await derivePoolStatePDA();

  console.log(`\nMint: ${zkbtcMint.toBase58()}`);
  console.log(`Current Authority: ${authority.publicKey.toBase58()}`);
  console.log(`New Authority (Pool PDA): ${poolStatePDA}`);

  // Create set authority instruction
  const ix = createSetAuthorityInstruction(
    zkbtcMint,
    authority.publicKey,
    AuthorityType.MintTokens,
    new PublicKey(poolStatePDA as string),
    [],
    TOKEN_2022_PROGRAM_ID
  );

  const tx = new Transaction().add(ix);

  console.log("\nTransferring mint authority...");

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
      commitment: "confirmed",
    });
    console.log(`\n✓ Mint authority transferred!`);
    console.log(`Signature: ${sig}`);
  } catch (err: any) {
    console.error(`\n✗ Failed:`, err.message);
  }
}

main().catch(console.error);
