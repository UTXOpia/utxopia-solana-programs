/**
 * Devnet Setup Script for UTXOpia (Poseidon2 version)
 *
 * 1. Initialize pool state (if needed)
 * 2. Add demo commitments using Poseidon2
 *
 * Run: bun run scripts/setup-devnet.ts
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  createMint,
  getOrCreateAssociatedTokenAccount,
  getMint,
} from "@solana/spl-token";
import { sha256 } from "@noble/hashes/sha2.js";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// CONFIGURATION
// ============================================================================

// Load config
const configPath = path.join(__dirname, "../config.json");
const config = JSON.parse(fs.readFileSync(configPath, "utf-8"));
const PROGRAM_ID = new PublicKey(config.programs.devnet.UTXOpia);

const RPC_URL = process.env.RPC_URL || "https://api.devnet.solana.com";

// Seeds for PDA derivation
const Seeds = {
  POOL_STATE: Buffer.from("pool_state"),
  COMMITMENT_TREE: Buffer.from("commitment_tree"),
};

// Instruction discriminators (match lib.rs)
const Instruction = {
  INITIALIZE: 0,
  ADD_DEMO_NOTE: 21,
};

// BN254 field prime
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Number of demo notes to create (each is 10,000 sats fixed by contract)
const NUM_DEMO_NOTES = 5;

// ============================================================================
// HELPERS
// ============================================================================

function bigintToBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let temp = value;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(temp & 0xffn);
    temp = temp >> 8n;
  }
  return bytes;
}

function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  let result = 0n;
  for (const byte of bytes) {
    result = (result << 8n) | BigInt(byte);
  }
  return result % FIELD_PRIME;
}

// ============================================================================
// PDA DERIVATION
// ============================================================================

function derivePoolStatePda(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Seeds.POOL_STATE], PROGRAM_ID);
}

function deriveCommitmentTreePda(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Seeds.COMMITMENT_TREE], PROGRAM_ID);
}

// ============================================================================
// NOTE GENERATION (SHA256 - matches contract)
// ============================================================================

interface DemoNote {
  secret: Uint8Array;
  nullifier: Uint8Array;
  commitment: Uint8Array;
  amount: number;  // Fixed at 10,000 sats by contract
}

// Match contract's derivation
const NULLIFIER_SALT = Buffer.from("nullifier_salt__"); // 16 bytes

function deriveNullifier(secret: Uint8Array): Uint8Array {
  const input = new Uint8Array(48);
  input.set(secret, 0);
  input.set(NULLIFIER_SALT, 32);
  return sha256(input);
}

function deriveCommitment(nullifier: Uint8Array, secret: Uint8Array): Uint8Array {
  const input = new Uint8Array(64);
  input.set(nullifier, 0);
  input.set(secret, 32);
  return sha256(input);
}

function generateDemoNote(): DemoNote {
  // Generate random 32-byte secret
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);

  // Derive nullifier and commitment (matching contract logic)
  const nullifier = deriveNullifier(secret);
  const commitment = deriveCommitment(nullifier, secret);

  return {
    secret,
    nullifier,
    commitment,
    amount: 10_000,  // Fixed by contract
  };
}

// ============================================================================
// INSTRUCTION BUILDERS
// ============================================================================

function buildInitializeIx(
  payer: PublicKey,
  poolState: PublicKey,
  commitmentTree: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
): TransactionInstruction {
  // Instruction data: [discriminator (1 byte)]
  const data = Buffer.alloc(1);
  data.writeUInt8(Instruction.INITIALIZE, 0);

  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: zkbtcMint, isSigner: false, isWritable: false },
      { pubkey: poolVault, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

function buildAddDemoNoteIx(
  authority: PublicKey,
  poolState: PublicKey,
  commitmentTree: PublicKey,
  secret: Uint8Array,
): TransactionInstruction {
  // Instruction data: [discriminator (1), secret (32)]
  const data = Buffer.alloc(1 + 32);
  data.writeUInt8(Instruction.ADD_DEMO_NOTE, 0);
  data.set(secret, 1);

  // Accounts order must match contract:
  // 0. pool_state - Pool state PDA
  // 1. commitment_tree - Commitment tree PDA
  // 2. authority - Pool authority (signer)
  return new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    data,
  });
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
  console.log("\n" + "=".repeat(70));
  console.log("         UTXOpia DEVNET SETUP (Poseidon2)");
  console.log("=".repeat(70) + "\n");

  // Load wallet
  const walletPath = config.wallet.path.replace("~", process.env.HOME!);
  if (!fs.existsSync(walletPath)) {
    console.error("Wallet not found at:", walletPath);
    process.exit(1);
  }

  const walletData = JSON.parse(fs.readFileSync(walletPath, "utf-8"));
  const wallet = Keypair.fromSecretKey(new Uint8Array(walletData));
  console.log("Wallet:", wallet.publicKey.toBase58());
  console.log("Program ID:", PROGRAM_ID.toBase58());

  // Connect
  const connection = new Connection(RPC_URL, "confirmed");
  console.log("RPC:", RPC_URL);

  const balance = await connection.getBalance(wallet.publicKey);
  console.log("Balance:", (balance / LAMPORTS_PER_SOL).toFixed(4), "SOL\n");

  if (balance < 0.1 * LAMPORTS_PER_SOL) {
    console.error("Insufficient balance. Need at least 0.1 SOL.");
    console.error("Run: solana airdrop 1 --url devnet");
    process.exit(1);
  }

  // Derive PDAs
  const [poolStatePda] = derivePoolStatePda();
  const [commitmentTreePda] = deriveCommitmentTreePda();

  console.log("Pool State PDA:", poolStatePda.toBase58());
  console.log("Commitment Tree PDA:", commitmentTreePda.toBase58());

  // Check if already initialized
  const poolStateInfo = await connection.getAccountInfo(poolStatePda);
  let isInitialized = poolStateInfo !== null && poolStateInfo.data.length > 0;

  // ============================================================
  // STEP 1: Create zkBTC Mint (if needed)
  // ============================================================
  console.log("\n" + "-".repeat(70));
  console.log("STEP 1: Setup zkBTC Mint");
  console.log("-".repeat(70));

  let zkbtcMint: PublicKey;
  const mintStatePath = path.join(__dirname, "../.devnet-mint.json");

  if (fs.existsSync(mintStatePath)) {
    const mintState = JSON.parse(fs.readFileSync(mintStatePath, "utf-8"));
    zkbtcMint = new PublicKey(mintState.mint);
    console.log("Using existing mint:", zkbtcMint.toBase58());

    try {
      await getMint(connection, zkbtcMint, undefined, TOKEN_2022_PROGRAM_ID);
      console.log("  ✓ Mint verified");
    } catch {
      console.log("  Mint not found, creating new one...");
      fs.unlinkSync(mintStatePath);
    }
  }

  if (!fs.existsSync(mintStatePath)) {
    console.log("Creating new zkBTC mint (Token-2022)...");
    zkbtcMint = await createMint(
      connection,
      wallet,
      poolStatePda,  // mint authority = pool PDA
      null,
      8,  // decimals
      undefined,
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );
    fs.writeFileSync(mintStatePath, JSON.stringify({ mint: zkbtcMint.toBase58() }));
    console.log("  ✓ Mint created:", zkbtcMint.toBase58());
  }

  zkbtcMint = new PublicKey(JSON.parse(fs.readFileSync(mintStatePath, "utf-8")).mint);

  // Create pool vault
  console.log("\nCreating pool vault...");
  const poolVault = await getOrCreateAssociatedTokenAccount(
    connection,
    wallet,
    zkbtcMint,
    poolStatePda,
    true,
    undefined,
    undefined,
    TOKEN_2022_PROGRAM_ID,
  );
  console.log("  ✓ Pool vault:", poolVault.address.toBase58());

  // ============================================================
  // STEP 2: Initialize Pool (if needed)
  // ============================================================
  console.log("\n" + "-".repeat(70));
  console.log("STEP 2: Initialize Pool");
  console.log("-".repeat(70));

  if (isInitialized) {
    console.log("  Pool already initialized, skipping...");
  } else {
    console.log("  Initializing pool...");
    const initIx = buildInitializeIx(
      wallet.publicKey,
      poolStatePda,
      commitmentTreePda,
      zkbtcMint,
      poolVault.address,
    );

    const tx = new Transaction().add(initIx);
    try {
      const sig = await sendAndConfirmTransaction(connection, tx, [wallet]);
      console.log("  ✓ Initialized:", sig);
      isInitialized = true;
    } catch (err: any) {
      if (err.message?.includes("already in use")) {
        console.log("  Pool already initialized");
        isInitialized = true;
      } else {
        console.error("  ✗ Failed:", err.message);
        process.exit(1);
      }
    }
  }

  // ============================================================
  // STEP 3: Add Demo Commitments
  // ============================================================
  console.log("\n" + "-".repeat(70));
  console.log("STEP 3: Add Demo Commitments (SHA256, 10k sats each)");
  console.log("-".repeat(70));

  const demoNotes: DemoNote[] = [];

  for (let i = 0; i < NUM_DEMO_NOTES; i++) {
    const note = generateDemoNote();
    demoNotes.push(note);

    console.log(`\n  Note ${i + 1}:`);
    console.log(`    Amount: 0.0001 BTC (10,000 sats) [fixed]`);
    console.log(`    Secret: ${Buffer.from(note.secret).toString("hex").slice(0, 16)}...`);
    console.log(`    Commitment: ${Buffer.from(note.commitment).toString("hex").slice(0, 16)}...`);

    const addNoteIx = buildAddDemoNoteIx(
      wallet.publicKey,
      poolStatePda,
      commitmentTreePda,
      note.secret,
    );

    const tx = new Transaction().add(addNoteIx);
    try {
      const sig = await sendAndConfirmTransaction(connection, tx, [wallet]);
      console.log(`    ✓ Added: ${sig.slice(0, 20)}...`);
    } catch (err: any) {
      console.log(`    ✗ Failed: ${err.message}`);
    }
  }

  // ============================================================
  // STEP 4: Save Demo Notes
  // ============================================================
  console.log("\n" + "-".repeat(70));
  console.log("STEP 4: Save Demo Notes");
  console.log("-".repeat(70));

  const notesPath = path.join(__dirname, "../.devnet-notes.json");
  const notesData = demoNotes.map((n, i) => ({
    index: i,
    secret: Buffer.from(n.secret).toString("hex"),
    nullifier: Buffer.from(n.nullifier).toString("hex"),
    commitment: Buffer.from(n.commitment).toString("hex"),
    amount: n.amount,
    claimLink: Buffer.from(JSON.stringify({
      s: Buffer.from(n.secret).toString("hex"),
      a: n.amount,
    })).toString("base64"),
  }));

  fs.writeFileSync(notesPath, JSON.stringify(notesData, null, 2));
  console.log(`  ✓ Saved ${demoNotes.length} notes to ${notesPath}`);

  // ============================================================
  // SUMMARY
  // ============================================================
  console.log("\n" + "=".repeat(70));
  console.log("         SETUP COMPLETE");
  console.log("=".repeat(70));
  console.log("\nProgram ID:", PROGRAM_ID.toBase58());
  console.log("zkBTC Mint:", zkbtcMint.toBase58());
  console.log("Pool State:", poolStatePda.toBase58());
  console.log("Commitment Tree:", commitmentTreePda.toBase58());
  console.log("Demo Notes:", demoNotes.length);
  console.log("\nClaim links saved to:", notesPath);
}

main().catch(console.error);
