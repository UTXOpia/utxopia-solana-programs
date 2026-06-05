/**
 * Devnet Setup Script for UTXOpia
 *
 * This script:
 * 1. Initializes the pool state
 * 2. Creates the zkBTC mint (Token-2022)
 * 3. Records test deposits with commitments
 * 4. Saves test notes for frontend claiming
 *
 * Run: bun run scripts/devnet-setup.ts
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
  createInitializeMintInstruction,
  getMintLen,
  ExtensionType,
  createInitializeMetadataPointerInstruction,
  TYPE_SIZE,
  LENGTH_SIZE,
} from "@solana/spl-token";
import { buildPoseidon } from "circomlibjs";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// CONFIGURATION
// ============================================================================

const PROGRAM_ID = new PublicKey("AtztELZfz3GHA8hFQCv7aT9Mt47Xhknv3ZCNb3fmXsgf");
const RPC_URL = "https://api.devnet.solana.com";

// Seeds for PDA derivation
const Seeds = {
  POOL_STATE: Buffer.from("pool_state"),
  COMMITMENT_TREE: Buffer.from("commitment_tree"),
  DEPOSIT: Buffer.from("deposit"),
  STEALTH: Buffer.from("stealth"),
};

// Instruction discriminators
const Instruction = {
  Initialize: 0,
  RecordDeposit: 1,
};

// BN254 field prime
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

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

function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBigint(bytes) % FIELD_PRIME;
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

function deriveDepositStealthPda(txid: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Seeds.STEALTH, txid],
    PROGRAM_ID,
  );
}

// ============================================================================
// NOTE GENERATION
// ============================================================================

interface TestNote {
  nullifier: string;
  secret: string;
  amount: string;
  commitment: string;
  nullifierHash: string;
  commitmentBytes: string;  // hex
  createdAt: string;
  status: "pending" | "deposited" | "claimed";
}

async function generateTestNote(
  poseidon: Awaited<ReturnType<typeof buildPoseidon>>,
  amountSats: bigint,
): Promise<TestNote> {
  const nullifier = randomFieldElement();
  const secret = randomFieldElement();

  // note = Poseidon(nullifier, secret)
  const note = poseidon.F.toObject(poseidon([nullifier, secret]));

  // commitment = Poseidon(note, amount)
  const commitment = poseidon.F.toObject(poseidon([note, amountSats]));

  // nullifierHash = Poseidon(nullifier)
  const nullifierHash = poseidon.F.toObject(poseidon([nullifier]));

  const commitmentBytes = bigintToBytes(commitment);

  return {
    nullifier: nullifier.toString(),
    secret: secret.toString(),
    amount: amountSats.toString(),
    commitment: commitment.toString(),
    nullifierHash: nullifierHash.toString(),
    commitmentBytes: Buffer.from(commitmentBytes).toString("hex"),
    createdAt: new Date().toISOString(),
    status: "pending",
  };
}

// ============================================================================
// INSTRUCTION BUILDERS
// ============================================================================

function buildInitializeInstruction(
  poolState: PublicKey,
  commitmentTree: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
  frostVault: PublicKey,
  authority: PublicKey,
  poolBump: number,
  treeBump: number,
): TransactionInstruction {
  const data = Buffer.alloc(7);
  data[0] = Instruction.Initialize;
  data[1] = poolBump;
  data[2] = treeBump;
  data.writeUInt16LE(0, 3); // deposit_fee_bps
  data.writeUInt16LE(0, 5); // withdrawal_fee_bps

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: zkbtcMint, isSigner: false, isWritable: false },
      { pubkey: poolVault, isSigner: false, isWritable: false },
      { pubkey: frostVault, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function buildRecordDepositInstruction(
  poolState: PublicKey,
  depositRecord: PublicKey,
  authority: PublicKey,
  commitment: Uint8Array,
  amountSats: bigint,
): TransactionInstruction {
  const data = Buffer.alloc(41);
  data[0] = Instruction.RecordDeposit;
  data.set(commitment, 1);
  data.writeBigUInt64LE(amountSats, 33);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: depositRecord, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

// ============================================================================
// MAIN SETUP
// ============================================================================

async function main() {
  console.log("\n========================================");
  console.log("UTXOpia Devnet Setup");
  console.log("========================================\n");

  // Connect to devnet
  const connection = new Connection(RPC_URL, "confirmed");
  console.log("Connected to:", RPC_URL);

  // Load authority keypair
  const keypairPath = process.env.HOME + "/.config/solana/id.json";
  let authority: Keypair;

  try {
    const keypairData = JSON.parse(fs.readFileSync(keypairPath, "utf8"));
    authority = Keypair.fromSecretKey(new Uint8Array(keypairData));
  } catch {
    console.log("Creating new authority keypair...");
    authority = Keypair.generate();
  }

  console.log("Authority:", authority.publicKey.toString());

  // Check balance
  const balance = await connection.getBalance(authority.publicKey);
  console.log("Balance:", balance / LAMPORTS_PER_SOL, "SOL");

  if (balance < 0.5 * LAMPORTS_PER_SOL) {
    console.log("Requesting airdrop...");
    try {
      const sig = await connection.requestAirdrop(authority.publicKey, 2 * LAMPORTS_PER_SOL);
      await connection.confirmTransaction(sig);
      console.log("Airdrop successful");
    } catch (e) {
      console.log("Airdrop failed (rate limited). Please fund the wallet manually.");
    }
  }

  // Initialize Poseidon
  console.log("\nInitializing Poseidon hasher...");
  const poseidon = await buildPoseidon();

  // Derive PDAs
  const [poolStatePda, poolBump] = derivePoolStatePda();
  const [commitmentTreePda, treeBump] = deriveCommitmentTreePda();

  console.log("\nProgram ID:", PROGRAM_ID.toString());
  console.log("Pool State PDA:", poolStatePda.toString());
  console.log("Commitment Tree PDA:", commitmentTreePda.toString());

  // Check if already initialized
  const poolAccount = await connection.getAccountInfo(poolStatePda);

  if (poolAccount) {
    console.log("\n[SKIP] Pool already initialized");
  } else {
    console.log("\n[INIT] Initializing pool...");

    // Create zkBTC mint (Token-2022)
    const mintKeypair = Keypair.generate();
    const mintLen = getMintLen([ExtensionType.MetadataPointer]);
    const mintLamports = await connection.getMinimumBalanceForRentExemption(mintLen);

    // Create mock vault addresses (for testing)
    const poolVault = Keypair.generate().publicKey;
    const frostVault = Keypair.generate().publicKey;

    // Account sizes (must match Rust structs)
    const POOL_STATE_SIZE = 296;
    const COMMITMENT_TREE_SIZE = 1024; // Adjust based on actual size

    // Calculate rent
    const poolRent = await connection.getMinimumBalanceForRentExemption(POOL_STATE_SIZE);
    const treeRent = await connection.getMinimumBalanceForRentExemption(COMMITMENT_TREE_SIZE);

    // Build transaction 1: Create PDA accounts
    const tx1 = new Transaction();

    // Create pool state PDA account
    tx1.add(
      SystemProgram.createAccountWithSeed({
        fromPubkey: authority.publicKey,
        newAccountPubkey: poolStatePda,
        basePubkey: authority.publicKey,
        seed: "pool_state",
        lamports: poolRent,
        space: POOL_STATE_SIZE,
        programId: PROGRAM_ID,
      }),
    );

    // Build transaction 2: Create mint and initialize
    const tx2 = new Transaction();

    // Create mint account
    tx2.add(
      SystemProgram.createAccount({
        fromPubkey: authority.publicKey,
        newAccountPubkey: mintKeypair.publicKey,
        space: mintLen,
        lamports: mintLamports,
        programId: TOKEN_2022_PROGRAM_ID,
      }),
    );

    // Initialize metadata pointer
    tx2.add(
      createInitializeMetadataPointerInstruction(
        mintKeypair.publicKey,
        authority.publicKey,
        mintKeypair.publicKey,
        TOKEN_2022_PROGRAM_ID,
      ),
    );

    // Initialize mint
    tx2.add(
      createInitializeMintInstruction(
        mintKeypair.publicKey,
        8, // decimals (satoshis)
        poolStatePda, // mint authority is pool PDA
        null, // no freeze authority
        TOKEN_2022_PROGRAM_ID,
      ),
    );

    // Initialize pool
    tx2.add(
      buildInitializeInstruction(
        poolStatePda,
        commitmentTreePda,
        mintKeypair.publicKey,
        poolVault,
        frostVault,
        authority.publicKey,
        poolBump,
        treeBump,
      ),
    );

    // We need a different approach - PDAs can't be created with createAccountWithSeed
    // Instead, modify the Initialize instruction to create accounts via CPI
    // For now, let's just use the tx2 and let the program handle account creation
    const tx = tx2;

    try {
      const sig = await sendAndConfirmTransaction(connection, tx, [authority, mintKeypair]);
      console.log("Pool initialized:", sig);
      console.log("zkBTC Mint:", mintKeypair.publicKey.toString());

      // Save mint info
      const mintInfo = {
        mint: mintKeypair.publicKey.toString(),
        poolState: poolStatePda.toString(),
        commitmentTree: commitmentTreePda.toString(),
        authority: authority.publicKey.toString(),
        programId: PROGRAM_ID.toString(),
      };
      fs.writeFileSync(
        path.join(__dirname, "../devnet-config.json"),
        JSON.stringify(mintInfo, null, 2),
      );
    } catch (e) {
      console.error("Failed to initialize pool:", e);
      return;
    }
  }

  // Generate and record test deposits
  console.log("\n========================================");
  console.log("Creating Test Deposits");
  console.log("========================================\n");

  const testAmounts = [
    100_000n,    // 0.001 BTC
    250_000n,    // 0.0025 BTC
    500_000n,    // 0.005 BTC
    1_000_000n,  // 0.01 BTC
  ];

  const testNotes: TestNote[] = [];

  for (const amount of testAmounts) {
    console.log(`\nGenerating note for ${amount} sats (${Number(amount) / 100_000_000} BTC)...`);

    const note = await generateTestNote(poseidon, amount);
    const commitmentBytes = Buffer.from(note.commitmentBytes, "hex");
    const [depositPda] = deriveDepositStealthPda(commitmentBytes);

    // Check if deposit already exists
    const depositAccount = await connection.getAccountInfo(depositPda);
    if (depositAccount) {
      console.log("  [SKIP] Deposit already exists");
      note.status = "deposited";
      testNotes.push(note);
      continue;
    }

    // Record deposit
    const tx = new Transaction().add(
      buildRecordDepositInstruction(
        poolStatePda,
        depositPda,
        authority.publicKey,
        commitmentBytes,
        amount,
      ),
    );

    try {
      const sig = await sendAndConfirmTransaction(connection, tx, [authority]);
      console.log("  Deposit recorded:", sig.slice(0, 20) + "...");
      console.log("  Commitment:", note.commitment.slice(0, 20) + "...");
      note.status = "deposited";
    } catch (e) {
      console.error("  Failed to record deposit:", e);
      note.status = "pending";
    }

    testNotes.push(note);
  }

  // Save test notes for frontend
  const notesPath = path.join(__dirname, "../devnet-test-notes.json");
  fs.writeFileSync(notesPath, JSON.stringify(testNotes, null, 2));
  console.log("\n========================================");
  console.log("Test Notes Saved");
  console.log("========================================");
  console.log("File:", notesPath);
  console.log("Notes:", testNotes.length);

  // Print summary for frontend
  console.log("\n========================================");
  console.log("Frontend Configuration");
  console.log("========================================");
  console.log(`
Add to frontend .env or config:

NEXT_PUBLIC_PROGRAM_ID=${PROGRAM_ID.toString()}
NEXT_PUBLIC_RPC_URL=${RPC_URL}
NEXT_PUBLIC_POOL_STATE=${poolStatePda.toString()}
NEXT_PUBLIC_COMMITMENT_TREE=${commitmentTreePda.toString()}

Test notes saved to: ${notesPath}
Import these notes in the frontend to test claiming.
`);

  // Print claimable notes
  console.log("========================================");
  console.log("Claimable Test Notes");
  console.log("========================================\n");

  for (const note of testNotes) {
    if (note.status === "deposited") {
      console.log(`Amount: ${note.amount} sats (${Number(note.amount) / 100_000_000} BTC)`);
      console.log(`Nullifier: ${note.nullifier.slice(0, 30)}...`);
      console.log(`Secret: ${note.secret.slice(0, 30)}...`);
      console.log(`Commitment: ${note.commitment.slice(0, 30)}...`);
      console.log("");
    }
  }
}

main().catch(console.error);
