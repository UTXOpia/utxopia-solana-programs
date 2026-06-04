#!/usr/bin/env bun
/**
 * Test Name Registry
 */

import { Connection, Keypair, PublicKey, Transaction, TransactionInstruction, SystemProgram, sendAndConfirmTransaction } from "@solana/web3.js";
import {
  UTXOPIA_PROGRAM_ID,
  buildRegisterNameData,
  hashName,
} from "@utxopia/sdk";
import * as fs from "fs";

const RPC_URL = "https://api.devnet.solana.com";

function loadKeypair(keyPath: string): Keypair {
  const absolutePath = keyPath.replace("~", process.env.HOME || "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

async function main() {
  console.log("=".repeat(60));
  console.log("Test Name Registry");
  console.log("=".repeat(60));

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = loadKeypair("~/.config/solana/id.json");

  console.log(`\nAuthority: ${authority.publicKey.toBase58()}`);
  console.log(`Program: ${UTXOPIA_PROGRAM_ID}`);

  // Test name
  const testName = "test_user_" + Date.now().toString().slice(-6);
  console.log(`\nRegistering name: ${testName}.zkey`);

  // Generate fake spending/viewing keys for testing
  const spendingPubKey = new Uint8Array(33);
  const viewingPubKey = new Uint8Array(33);
  spendingPubKey[0] = 0x02; // compressed point prefix
  viewingPubKey[0] = 0x02;
  crypto.getRandomValues(spendingPubKey.subarray(1));
  crypto.getRandomValues(viewingPubKey.subarray(1));

  // Build instruction data
  const instructionData = buildRegisterNameData(testName, spendingPubKey, viewingPubKey);
  console.log(`Instruction data length: ${instructionData.length} bytes`);

  // Derive name registry PDA
  const nameHash = hashName(testName);
  const [nameRegistryPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("zkey"), Buffer.from(nameHash)],
    new PublicKey(UTXOPIA_PROGRAM_ID as string)
  );
  console.log(`Name Registry PDA: ${nameRegistryPDA.toBase58()}`);

  // Build transaction
  const ix = new TransactionInstruction({
    keys: [
      { pubkey: nameRegistryPDA, isSigner: false, isWritable: true },
      { pubkey: authority.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: new PublicKey(UTXOPIA_PROGRAM_ID as string),
    data: Buffer.from(instructionData),
  });

  const tx = new Transaction().add(ix);

  console.log("\nSending transaction...");

  try {
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
      commitment: "confirmed",
    });
    console.log(`\n✓ Name registration successful!`);
    console.log(`Name: ${testName}.zkey`);
    console.log(`Signature: ${sig}`);
    console.log(`\nView on Solscan: https://solscan.io/tx/${sig}?cluster=devnet`);

    // Verify the name was registered
    const nameInfo = await connection.getAccountInfo(nameRegistryPDA);
    if (nameInfo) {
      console.log(`\n✓ Name Registry account created (${nameInfo.data.length} bytes)`);
      console.log(`  Discriminator: 0x${nameInfo.data[0].toString(16).padStart(2, '0')}`);
    }

  } catch (err: any) {
    console.error(`\n✗ Transaction failed:`, err.message);
    if (err.logs) {
      console.error("Logs:", err.logs.slice(-10));
    }
  }
}

main().catch(console.error);
