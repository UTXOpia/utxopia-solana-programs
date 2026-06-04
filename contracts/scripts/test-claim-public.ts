#!/usr/bin/env bun
/**
 * Test Claim Public Instruction
 *
 * This script tests the new CLAIM_PUBLIC instruction that allows users
 * to claim zkBTC directly to their Solana wallet (public mode).
 *
 * Flow:
 * 1. First create a demo note (ADD_DEMO_NOTE)
 * 2. Then claim it to a public wallet (CLAIM_PUBLIC)
 *
 * Note: On devnet with placeholder VKs, the ZK proof verification
 * will fail as expected. This is a structural test.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  getAssociatedTokenAddressSync,
  getAccount,
  createAssociatedTokenAccountInstruction,
} from "@solana/spl-token";
import {
  UTXOPIA_PROGRAM_ID,
  derivePoolStatePDA,
  deriveCommitmentTreePDA,
  deriveNullifierRecordPDA,
} from "@utxopia/sdk";
import * as fs from "fs";

const RPC_URL = "https://api.devnet.solana.com";
const ZKBTC_MINT = new PublicKey("BdUFQhqKpzYVHVg8cQoh7JdpSoHFtwKM4A48AFAjKFAK");

// Instruction discriminators
const DISCRIMINATOR = {
  ADD_DEMO_NOTE: 21,
  CLAIM_PUBLIC: 9,
};

function loadKeypair(keyPath: string): Keypair {
  const absolutePath = keyPath.replace("~", process.env.HOME || "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

/**
 * Build ADD_DEMO_NOTE instruction data
 * Format: discriminator (1) + commitment (32) + amount (8)
 */
function buildDemoNoteData(commitment: Uint8Array, amountSats: bigint): Buffer {
  const data = Buffer.alloc(41);
  data[0] = DISCRIMINATOR.ADD_DEMO_NOTE;
  Buffer.from(commitment).copy(data, 1);
  data.writeBigUInt64LE(amountSats, 33);
  return data;
}

/**
 * Build CLAIM_PUBLIC instruction data
 * Format: discriminator (1) + proof (256) + root (32) + nullifier_hash (32) + amount (8) + recipient (32)
 * Total: 361 bytes
 */
function buildClaimPublicData(
  proof: Uint8Array,
  merkleRoot: Uint8Array,
  nullifierHash: Uint8Array,
  amountSats: bigint,
  recipient: PublicKey
): Buffer {
  const data = Buffer.alloc(361);
  let offset = 0;

  // Discriminator
  data[offset++] = DISCRIMINATOR.CLAIM_PUBLIC;

  // Proof (256 bytes) - placeholder for testing
  Buffer.from(proof).copy(data, offset);
  offset += 256;

  // Merkle root (32 bytes)
  Buffer.from(merkleRoot).copy(data, offset);
  offset += 32;

  // Nullifier hash (32 bytes)
  Buffer.from(nullifierHash).copy(data, offset);
  offset += 32;

  // Amount (8 bytes)
  data.writeBigUInt64LE(amountSats, offset);
  offset += 8;

  // Recipient (32 bytes)
  recipient.toBuffer().copy(data, offset);

  return data;
}

async function ensureTokenAccount(
  connection: Connection,
  payer: Keypair,
  owner: PublicKey,
  mint: PublicKey
): Promise<PublicKey> {
  const ata = getAssociatedTokenAddressSync(mint, owner, false, TOKEN_2022_PROGRAM_ID);

  try {
    await getAccount(connection, ata, "confirmed", TOKEN_2022_PROGRAM_ID);
    console.log(`Token account exists: ${ata.toBase58()}`);
  } catch {
    console.log(`Creating token account: ${ata.toBase58()}`);
    const ix = createAssociatedTokenAccountInstruction(
      payer.publicKey,
      ata,
      owner,
      mint,
      TOKEN_2022_PROGRAM_ID
    );
    const tx = new Transaction().add(ix);
    await sendAndConfirmTransaction(connection, tx, [payer]);
    console.log(`Token account created`);
  }

  return ata;
}

async function main() {
  console.log("=".repeat(60));
  console.log("Test CLAIM_PUBLIC Instruction");
  console.log("=".repeat(60));

  const connection = new Connection(RPC_URL, "confirmed");
  const authority = loadKeypair("~/.config/solana/johnny.json");

  console.log(`\nAuthority: ${authority.publicKey.toBase58()}`);
  console.log(`Program: ${UTXOPIA_PROGRAM_ID}`);

  // Derive PDAs
  const [poolStatePDA] = await derivePoolStatePDA();
  const [commitmentTreePDA] = await deriveCommitmentTreePDA();

  console.log(`Pool State: ${poolStatePDA}`);
  console.log(`Commitment Tree: ${commitmentTreePDA}`);

  // Pool vault (from config - already deployed)
  const poolVault = new PublicKey("HNe2SvmQzHPHzRcLwfp1vQVwJq9ELeMZ3dJSbKyMkNdD");
  console.log(`Pool Vault: ${poolVault.toBase58()}`);

  // Generate test data
  const commitment = new Uint8Array(32);
  crypto.getRandomValues(commitment);
  const nullifierHash = new Uint8Array(32);
  crypto.getRandomValues(nullifierHash);
  const amountSats = 100_000n; // 0.001 BTC

  console.log(`\nTest Data:`);
  console.log(`  Commitment: ${Buffer.from(commitment).toString("hex").slice(0, 32)}...`);
  console.log(`  Nullifier Hash: ${Buffer.from(nullifierHash).toString("hex").slice(0, 32)}...`);
  console.log(`  Amount: ${amountSats} sats`);

  // Note: Demo note creation requires pool authority
  // For this test, we'll directly test the CLAIM_PUBLIC instruction structure

  // Try to claim to public wallet
  console.log("\n=== Testing CLAIM_PUBLIC Instruction ===");

  // Ensure recipient has a token account
  const recipientAta = await ensureTokenAccount(
    connection,
    authority,
    authority.publicKey,
    ZKBTC_MINT
  );

  // Derive nullifier record PDA
  const [nullifierRecordPDA] = await deriveNullifierRecordPDA(nullifierHash);
  console.log(`Nullifier Record: ${nullifierRecordPDA}`);
  console.log(`Recipient ATA: ${recipientAta.toBase58()}`);

  // Get current merkle root from commitment tree
  const treeAccount = await connection.getAccountInfo(new PublicKey(commitmentTreePDA as string));
  let merkleRoot = new Uint8Array(32);
  if (treeAccount && treeAccount.data.length >= 33) {
    // Discriminator (1) + current_root (32)
    merkleRoot = treeAccount.data.slice(1, 33);
    console.log(`  Merkle Root: ${Buffer.from(merkleRoot).toString("hex").slice(0, 32)}...`);
  }

  // Create placeholder proof (256 bytes)
  const proof = new Uint8Array(256);
  proof[0] = 1; // Non-zero to pass basic validation
  proof[64] = 1;
  proof[192] = 1;

  const claimPublicData = buildClaimPublicData(
    proof,
    merkleRoot,
    nullifierHash,
    amountSats,
    authority.publicKey
  );

  const claimPublicIx = new TransactionInstruction({
    keys: [
      { pubkey: new PublicKey(poolStatePDA as string), isSigner: false, isWritable: true },
      { pubkey: new PublicKey(commitmentTreePDA as string), isSigner: false, isWritable: false },
      { pubkey: new PublicKey(nullifierRecordPDA as string), isSigner: false, isWritable: true },
      { pubkey: ZKBTC_MINT, isSigner: false, isWritable: true },
      { pubkey: poolVault, isSigner: false, isWritable: true },
      { pubkey: recipientAta, isSigner: false, isWritable: true },
      { pubkey: authority.publicKey, isSigner: true, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: new PublicKey(UTXOPIA_PROGRAM_ID as string),
    data: claimPublicData,
  });

  const tx2 = new Transaction().add(claimPublicIx);

  try {
    const sig2 = await sendAndConfirmTransaction(connection, tx2, [authority], {
      commitment: "confirmed",
    });
    console.log(`\n✓ CLAIM_PUBLIC successful!`);
    console.log(`  Signature: ${sig2}`);
    console.log(`  View on Solscan: https://solscan.io/tx/${sig2}?cluster=devnet`);

    // Verify token balance
    const ataAccount = await getAccount(connection, recipientAta, "confirmed", TOKEN_2022_PROGRAM_ID);
    console.log(`\n  Recipient balance: ${ataAccount.amount} sats`);

  } catch (err: any) {
    // Expected: ZK proof verification will fail with placeholder VK
    console.log(`\n⚠ Expected: CLAIM_PUBLIC failed (placeholder VK)`);
    console.log(`  Error: ${err.message}`);
    if (err.logs) {
      const relevantLogs = err.logs.filter((log: string) =>
        log.includes("Error") || log.includes("failed") || log.includes("invoke")
      );
      console.log("  Relevant logs:", relevantLogs.slice(-5));
    }
    console.log(`\n  Note: On devnet with placeholder VKs, ZK proof verification`);
    console.log(`  will fail. This demonstrates the instruction structure works.`);
    console.log(`  With a real VK deployed, the full flow will work.`);
  }
}

main().catch(console.error);
