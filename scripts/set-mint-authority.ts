#!/usr/bin/env bun
/**
 * Transfer zkBTC mint authority to Pool State PDA
 */

import { Connection, Keypair, PublicKey, Transaction, sendAndConfirmTransaction } from "@solana/web3.js";
import { AuthorityType, createSetAuthorityInstruction, TOKEN_2022_PROGRAM_ID } from "@solana/spl-token";
import * as fs from "fs";

const RPC_URL = "https://api.devnet.solana.com";

function loadKeypair(keyPath: string): Keypair {
  const absolutePath = keyPath.replace("~", process.env.HOME || "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

async function main() {
  console.log("=".repeat(60));
  console.log("Transfer zkBTC Mint Authority to Pool State PDA");
  console.log("=".repeat(60));

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = loadKeypair("~/.config/solana/johnny.json");

  // Load config
  const devnetConfig = JSON.parse(fs.readFileSync(".devnet-config.json", "utf-8"));
  const zkbtcMint = new PublicKey(devnetConfig.accounts.zkbtcMint);
  const poolStatePDA = new PublicKey(devnetConfig.accounts.poolState);

  console.log(`\nCurrent Authority: ${authority.publicKey.toBase58()}`);
  console.log(`zkBTC Mint: ${zkbtcMint.toBase58()}`);
  console.log(`New Authority (Pool State PDA): ${poolStatePDA.toBase58()}`);

  // Create set authority instruction
  const ix = createSetAuthorityInstruction(
    zkbtcMint,                    // mint
    authority.publicKey,         // current authority
    AuthorityType.MintTokens,    // authority type
    poolStatePDA,                // new authority
    [],                          // multi signers
    TOKEN_2022_PROGRAM_ID        // program id
  );

  const tx = new Transaction().add(ix);

  console.log("\nSending transaction...");

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
      commitment: "confirmed",
    });
    console.log(`\n✓ Mint authority transferred successfully!`);
    console.log(`Signature: ${sig}`);
    console.log(`\nView on Solscan: https://solscan.io/tx/${sig}?cluster=devnet`);
  } catch (err: any) {
    console.error(`\n✗ Transaction failed:`, err.message);
    if (err.logs) {
      console.error("Logs:", err.logs);
    }
  }
}

main().catch(console.error);
