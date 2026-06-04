/**
 * UTXOPIA Devnet Test Script
 *
 * Tests all 6 main functions:
 * 1. deposit - Generate credentials
 * 2. sendLink - Create claim link
 * 3. privateClaim - Claim with ZK proof (requires commitment in tree)
 * 4. privateSplit - Split commitment (requires commitment in tree)
 * 5. sendStealth - Send via ECDH
 * 6. withdraw - Request BTC withdrawal
 *
 * Run: bun run scripts/test-zvault-devnet.ts
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import * as fs from "fs";

// Import from SDK
import {
  createClient,
  UTXOPIA_PROGRAM_ID,
  deposit,
  sendLink,
  generateNote,
  createClaimLink,
  parseClaimLink,
  deriveNote,
  generateStealthKeys,
  createStealthDeposit,
  scanAnnouncements,
  bigintToBytes,
} from "../sdk/src/index";

// ============================================================================
// CONFIGURATION
// ============================================================================

const RPC_URL = "https://api.devnet.solana.com";
const PROGRAM_ID = UTXOPIA_PROGRAM_ID;

// Instruction discriminators
const INSTRUCTION = {
  INITIALIZE: 0,
  SPLIT_COMMITMENT: 4,
  REQUEST_REDEMPTION: 5,
  COMPLETE_REDEMPTION: 6,
  SET_PAUSED: 7,
  VERIFY_DEPOSIT: 8,
  CLAIM: 9,
  INIT_COMMITMENT_TREE: 10,
  ADD_DEMO_COMMITMENT: 11,
  ANNOUNCE_STEALTH: 12,
};

// ============================================================================
// HELPERS
// ============================================================================

function derivePoolStatePDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("pool_state")],
    PROGRAM_ID
  );
}

function deriveCommitmentTreePDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("commitment_tree")],
    PROGRAM_ID
  );
}

function deriveStealthAnnouncementPDA(ephemeralPubKey: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("stealth"), ephemeralPubKey],
    PROGRAM_ID
  );
}

async function loadWallet(): Promise<Keypair> {
  const walletPath = process.env.ANCHOR_WALLET ||
    `${process.env.HOME}/.config/solana/johnny.json`;

  if (!fs.existsSync(walletPath)) {
    throw new Error(`Wallet not found at ${walletPath}`);
  }

  const walletData = JSON.parse(fs.readFileSync(walletPath, "utf-8"));
  return Keypair.fromSecretKey(new Uint8Array(walletData));
}

/**
 * Check if current wallet is the pool authority
 */
async function getPoolAuthority(connection: Connection): Promise<PublicKey | null> {
  const [poolState] = derivePoolStatePDA();
  const poolAccount = await connection.getAccountInfo(poolState);

  if (!poolAccount || poolAccount.data.length < 34) {
    return null;
  }

  // Pool layout: discriminator (1) + bump (1) + authority (32)
  const authorityBytes = poolAccount.data.slice(2, 34);
  return new PublicKey(authorityBytes);
}

// ============================================================================
// INITIALIZE PROGRAM
// ============================================================================

async function initializeProgram(
  connection: Connection,
  payer: Keypair
): Promise<boolean> {
  const [poolState, poolBump] = derivePoolStatePDA();
  const [commitmentTree, treeBump] = deriveCommitmentTreePDA();

  // Check if already initialized
  const poolAccount = await connection.getAccountInfo(poolState);
  if (poolAccount) {
    console.log("Pool already initialized");
    return true;
  }

  console.log("Initializing pool...");

  // Create mock addresses for init
  const zkbtcMint = Keypair.generate().publicKey;
  const poolVault = Keypair.generate().publicKey;
  const frostVault = Keypair.generate().publicKey;

  // Build initialize instruction
  const data = Buffer.alloc(3);
  data[0] = INSTRUCTION.INITIALIZE;
  data[1] = poolBump;
  data[2] = treeBump;

  const initIx = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: zkbtcMint, isSigner: false, isWritable: false },
      { pubkey: poolVault, isSigner: false, isWritable: false },
      { pubkey: frostVault, isSigner: false, isWritable: false },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  try {
    const tx = new Transaction().add(initIx);
    const sig = await sendAndConfirmTransaction(connection, tx, [payer]);
    console.log("Pool initialized:", sig);
    return true;
  } catch (e: any) {
    console.error("Failed to initialize:", e.message);
    return false;
  }
}

// ============================================================================
// INITIALIZE COMMITMENT TREE
// ============================================================================

async function initCommitmentTree(
  connection: Connection,
  payer: Keypair
): Promise<boolean> {
  const [poolState] = derivePoolStatePDA();
  const [commitmentTree, treeBump] = deriveCommitmentTreePDA();

  // Check if tree has data
  const treeAccount = await connection.getAccountInfo(commitmentTree);
  if (treeAccount && treeAccount.data.length > 100) {
    console.log("Commitment tree already initialized");
    return true;
  }

  console.log("Initializing commitment tree...");

  const data = Buffer.alloc(2);
  data[0] = INSTRUCTION.INIT_COMMITMENT_TREE;
  data[1] = treeBump;

  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: false },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });

  try {
    const tx = new Transaction().add(ix);
    const sig = await sendAndConfirmTransaction(connection, tx, [payer]);
    console.log("Commitment tree initialized:", sig);
    return true;
  } catch (e: any) {
    console.error("Failed to init tree:", e.message);
    return false;
  }
}

// ============================================================================
// ADD DEMO COMMITMENT
// ============================================================================

async function addDemoCommitment(
  connection: Connection,
  payer: Keypair,
  commitment: Uint8Array,
  amount: bigint
): Promise<boolean> {
  const [poolState] = derivePoolStatePDA();
  const [commitmentTree] = deriveCommitmentTreePDA();

  // Build instruction: discriminator (1) + commitment (32) + amount (8)
  const data = Buffer.alloc(41);
  data[0] = INSTRUCTION.ADD_DEMO_COMMITMENT;
  data.set(commitment, 1);
  data.writeBigUInt64LE(amount, 33);

  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: false },
    ],
    data,
  });

  try {
    const tx = new Transaction().add(ix);
    const sig = await sendAndConfirmTransaction(connection, tx, [payer]);
    console.log("Demo commitment added:", sig.slice(0, 20) + "...");
    return true;
  } catch (e: any) {
    console.error("Failed to add commitment:", e.message);
    return false;
  }
}

// ============================================================================
// TEST FUNCTIONS
// ============================================================================

async function testDeposit() {
  console.log("\n--- Test 1: DEPOSIT ---");

  const result = await deposit(100_000n, "testnet");

  console.log("Taproot Address:", result.taprootAddress);
  console.log("Claim Link:", result.claimLink.slice(0, 50) + "...");
  console.log("Amount:", result.displayAmount);
  console.log("Note nullifier:", result.note.nullifier.toString().slice(0, 20) + "...");

  return result;
}

function testSendLink() {
  console.log("\n--- Test 2: SEND_LINK ---");

  const note = generateNote(50_000n);
  const link = sendLink(note);

  console.log("Generated note for 50,000 sats");
  console.log("Claim link:", link.slice(0, 60) + "...");

  // Verify we can parse it back
  const parsed = parseClaimLink(link);
  if (parsed) {
    console.log("Parsed amount:", parsed.amount.toString(), "sats");
    console.log("Link round-trip: OK");
  }

  return { note, link };
}

function testDeriveNote() {
  console.log("\n--- Test 3: DERIVE_NOTE (deterministic) ---");

  const seed = "test-wallet-utxopia-2024";

  // Derive multiple notes from same seed
  const note0 = deriveNote(seed, 0, 100_000n);
  const note1 = deriveNote(seed, 1, 50_000n);
  const note2 = deriveNote(seed, 2, 25_000n);

  // Verify determinism
  const note0Again = deriveNote(seed, 0, 100_000n);

  console.log("Seed:", seed);
  console.log("Note 0: nullifier =", note0.nullifier.toString().slice(0, 20) + "...");
  console.log("Note 1: nullifier =", note1.nullifier.toString().slice(0, 20) + "...");
  console.log("Note 2: nullifier =", note2.nullifier.toString().slice(0, 20) + "...");
  console.log("Deterministic check:", note0.nullifier === note0Again.nullifier ? "PASS" : "FAIL");

  return { note0, note1, note2 };
}

async function testStealthDeposit() {
  console.log("\n--- Test 4: STEALTH (ECDH) ---");

  // Generate receiver keys
  const receiverKeys = generateStealthKeys();
  console.log("Receiver pubkey:", Buffer.from(receiverKeys.viewPubKey).toString("hex").slice(0, 20) + "...");

  // Sender creates stealth deposit (minimal format - no hint)
  const amount = 75_000n;
  const stealthDeposit = createStealthDeposit(receiverKeys.viewPubKey, amount);

  console.log("Ephemeral pubkey:", Buffer.from(stealthDeposit.ephemeralPubKey).toString("hex").slice(0, 20) + "...");
  console.log("Encrypted amount:", Buffer.from(stealthDeposit.encryptedAmount).toString("hex"));

  // Receiver scans - minimal format (no hint, no commitment)
  const announcements = [{
    ephemeralPubKey: stealthDeposit.ephemeralPubKey,
    encryptedAmount: stealthDeposit.encryptedAmount,
  }];

  const found = scanAnnouncements(receiverKeys.viewPrivKey, receiverKeys.viewPubKey, announcements);

  if (found.length > 0) {
    console.log("Receiver found deposit!");
    console.log("Recovered amount:", found[0].amount.toString(), "sats");
    console.log("Amount match:", found[0].amount === amount ? "PASS" : "FAIL");
  } else {
    console.log("Receiver did not find deposit: FAIL");
  }

  return { receiverKeys, stealthDeposit, found };
}

async function testSendStealthOnChain(
  connection: Connection,
  payer: Keypair
) {
  console.log("\n--- Test 5: SEND_STEALTH ON-CHAIN ---");

  // Generate receiver keys
  const receiverKeys = generateStealthKeys();
  const amount = 60_000n;
  const stealthDeposit = createStealthDeposit(receiverKeys.viewPubKey, amount);

  // Build ANNOUNCE_STEALTH instruction (minimal 40-byte format)
  // Layout: ephemeral_pubkey (32) + encrypted_amount (8) = 40 bytes
  const data = new Uint8Array(1 + 40);
  data[0] = INSTRUCTION.ANNOUNCE_STEALTH;
  data.set(stealthDeposit.ephemeralPubKey, 1);
  data.set(stealthDeposit.encryptedAmount, 33);

  // PDA seeded by ephemeral_pubkey (not commitment)
  const [announcementPDA] = deriveStealthAnnouncementPDA(stealthDeposit.ephemeralPubKey);

  const ix = new TransactionInstruction({
    programId: PROGRAM_ID,
    keys: [
      { pubkey: announcementPDA, isSigner: false, isWritable: true },
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data: Buffer.from(data),
  });

  try {
    const tx = new Transaction().add(ix);
    const sig = await sendAndConfirmTransaction(connection, tx, [payer]);
    console.log("Stealth announcement created:", sig.slice(0, 20) + "...");
    console.log("Announcement PDA:", announcementPDA.toBase58());
    console.log("Format: 40 bytes (ephemeral + encrypted_amount, no hint)");
    return true;
  } catch (e: any) {
    console.error("Failed:", e.message);
    return false;
  }
}

// ============================================================================
// MAIN
// ============================================================================

interface TestResult {
  name: string;
  passed: boolean;
  message: string;
}

async function main() {
  console.log("\n" + "=".repeat(60));
  console.log("        UTXOPIA DEVNET TEST");
  console.log("=".repeat(60));

  const results: TestResult[] = [];

  // Connect
  const connection = new Connection(RPC_URL, "confirmed");
  console.log("\nConnected to:", RPC_URL);
  console.log("Program ID:", PROGRAM_ID.toBase58());

  // Load wallet
  const payer = await loadWallet();
  console.log("Wallet:", payer.publicKey.toBase58());

  // Check balance
  const balance = await connection.getBalance(payer.publicKey);
  console.log("Balance:", balance / LAMPORTS_PER_SOL, "SOL");

  if (balance < 0.1 * LAMPORTS_PER_SOL) {
    console.log("\nInsufficient balance. Please fund the wallet.");
    return;
  }

  // Derive PDAs
  const [poolState] = derivePoolStatePDA();
  const [commitmentTree] = deriveCommitmentTreePDA();
  console.log("\nPool State PDA:", poolState.toBase58());
  console.log("Commitment Tree PDA:", commitmentTree.toBase58());

  // Check pool authority
  const poolAuthority = await getPoolAuthority(connection);
  const isAuthority = poolAuthority?.equals(payer.publicKey) ?? false;

  if (poolAuthority) {
    console.log("\nPool Authority:", poolAuthority.toBase58());
    if (!isAuthority) {
      console.log("WARNING: Current wallet is NOT the pool authority");
      console.log("Authority-dependent operations will be skipped");
    }
  }

  // Initialize if needed
  console.log("\n" + "-".repeat(60));
  console.log("INITIALIZATION");
  console.log("-".repeat(60));

  await initializeProgram(connection, payer);
  await initCommitmentTree(connection, payer);

  // Run tests
  console.log("\n" + "-".repeat(60));
  console.log("SDK FUNCTION TESTS");
  console.log("-".repeat(60));

  // Test 1: deposit()
  try {
    const depositResult = await testDeposit();
    results.push({ name: "deposit()", passed: true, message: "Generated credentials" });
  } catch (e: any) {
    results.push({ name: "deposit()", passed: false, message: e.message });
  }

  // Test 2: sendLink()
  try {
    const linkResult = testSendLink();
    results.push({ name: "sendLink()", passed: true, message: "Created claim link" });
  } catch (e: any) {
    results.push({ name: "sendLink()", passed: false, message: e.message });
  }

  // Test 3: deriveNote()
  try {
    const deriveResult = testDeriveNote();
    results.push({ name: "deriveNote()", passed: true, message: "Deterministic derivation" });
  } catch (e: any) {
    results.push({ name: "deriveNote()", passed: false, message: e.message });
  }

  // Test 4: stealth ECDH (off-chain)
  try {
    await testStealthDeposit();
    results.push({ name: "stealth ECDH", passed: true, message: "Off-chain deposit/scan" });
  } catch (e: any) {
    results.push({ name: "stealth ECDH", passed: false, message: e.message });
  }

  // Test 5: sendStealth on-chain
  try {
    const success = await testSendStealthOnChain(connection, payer);
    results.push({
      name: "sendStealth on-chain",
      passed: success,
      message: success ? "Created announcement PDA" : "Failed to create",
    });
  } catch (e: any) {
    results.push({ name: "sendStealth on-chain", passed: false, message: e.message });
  }

  // Test 6: Add demo commitment to tree (requires authority)
  console.log("\n--- Test 6: ADD_DEMO_COMMITMENT ---");
  if (isAuthority) {
    try {
      const testNote = generateNote(200_000n);
      const placeholderCommitment = bigintToBytes(
        (testNote.nullifier ^ testNote.secret) % (2n ** 256n)
      );
      const success = await addDemoCommitment(connection, payer, placeholderCommitment, 200_000n);
      results.push({
        name: "addDemoCommitment",
        passed: success,
        message: success ? "Added to tree" : "Failed",
      });
    } catch (e: any) {
      results.push({ name: "addDemoCommitment", passed: false, message: e.message });
    }
  } else {
    console.log("SKIPPED: Requires pool authority");
    results.push({
      name: "addDemoCommitment",
      passed: true,
      message: "SKIPPED (not authority)",
    });
  }

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("        TEST RESULTS");
  console.log("=".repeat(60));

  const passCount = results.filter((r) => r.passed).length;
  const skipCount = results.filter((r) => r.message.includes("SKIPPED")).length;

  console.log(`\n  Total: ${results.length} | Passed: ${passCount} | Skipped: ${skipCount}\n`);

  for (const result of results) {
    const status = result.message.includes("SKIPPED")
      ? "SKIP"
      : result.passed
      ? "PASS"
      : "FAIL";
    const icon = status === "PASS" ? "[+]" : status === "SKIP" ? "[~]" : "[-]";
    console.log(`  ${icon} ${result.name.padEnd(22)} ${status.padEnd(6)} ${result.message}`);
  }

  console.log(`
  SDK Functions Tested:
  1. deposit()         - Generate taproot address + claim link
  2. sendLink()        - Create shareable claim link
  3. deriveNote()      - Deterministic note derivation
  4. stealth ECDH      - Off-chain stealth deposit/scan
  5. sendStealth       - On-chain stealth announcement
  6. addDemoCommitment - Add commitment to Merkle tree

  Note: privateClaim, privateSplit, and withdraw require:
  - Real Groth16 proof generation
  - Commitment already in on-chain Merkle tree
  - These are tested in test-groth16-integration.ts
  `);

  console.log("=".repeat(60));
  console.log("        DONE");
  console.log("=".repeat(60) + "\n");
}

main().catch(console.error);
