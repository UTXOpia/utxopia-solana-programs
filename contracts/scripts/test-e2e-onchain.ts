#!/usr/bin/env bun
/**
 * Full On-Chain E2E Test - Real Proof Verification
 *
 * Complete flow:
 * 1. Add demo deposit (commitment to tree)
 * 2. Fetch on-chain tree state
 * 3. Compute valid merkle proof matching on-chain root
 * 4. Generate ZK proof with correct root
 * 5. Submit claim with Groth16 verification
 *
 * Prerequisites:
 *   - solana-test-validator running
 *   - UTXOpia and Groth16 verifier deployed
 *
 * Run: bun run scripts/test-e2e-onchain.ts
 */

import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  TransactionInstruction,
  SystemProgram,
  sendAndConfirmTransaction,
  ComputeBudgetProgram,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  getAssociatedTokenAddressSync,
  createAssociatedTokenAccountInstruction,
  getAccount,
} from "@solana/spl-token";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { sha256 } from "@noble/hashes/sha2.js";

// SDK imports
import {
  initProver,
  setCircuitPath,
  generateClaimProof,
  cleanupProver,
  initPoseidon,
  poseidonHashSync,
  computeUnifiedCommitmentSync,
  computeNullifierSync,
  hashNullifierSync,
  generateGrumpkinKeyPair,
  pointToCompressedBytes,
  grumpkinEcdh,
  encryptAmount,
  buildAddDemoStealthData,
  // Stealth model imports
  deriveKeysFromSeed,
  createStealthDeposit,
  createStealthMetaAddress,
  prepareClaimInputs,
  bytesToBigint,
  type ClaimInputs,
  type UTXOpiaKeys,
  type StealthMetaAddress,
  type ScannedNote,
} from "@utxopia/sdk";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const NETWORK = process.env.NETWORK || "localnet";
const DEFAULT_RPC_URLS: Record<string, string> = {
  localnet: "http://127.0.0.1:8899",
  devnet: "https://solana-devnet.g.alchemy.com/v2/y1zYW-ovVofq7OzZo0Z6IHenRnyq_Pbd",
};
const RPC_URL = process.env.RPC_URL || DEFAULT_RPC_URLS[NETWORK] || DEFAULT_RPC_URLS.localnet;
const TREE_DEPTH = 20;
const DEMO_AMOUNT = 10_000n;
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Load config based on network
const configPath = path.join(__dirname, "..", NETWORK === "devnet" ? ".devnet-config.json" : ".localnet-config.json");
const mainConfigPath = path.join(__dirname, "..", "config.json");

// Instruction discriminators
const DISCRIMINATOR = {
  ADD_DEMO_STEALTH: 13,
  CLAIM: 2,
};

// Seeds
const SEEDS = {
  POOL_STATE: "pool_state",
  COMMITMENT_TREE: "commitment_tree",
  NULLIFIER: "nullifier",
  STEALTH: "stealth",
};

// =============================================================================
// Helpers
// =============================================================================

function log(msg: string) {
  console.log(`  ${msg}`);
}

function logSection(title: string) {
  console.log("\n" + "=".repeat(60));
  console.log(title);
  console.log("=".repeat(60));
}

function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return BigInt("0x" + Buffer.from(bytes).toString("hex")) % BN254_MODULUS;
}

function bigintToBytes32(n: bigint): Uint8Array {
  const hex = n.toString(16).padStart(64, "0");
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytes32ToBigint(bytes: Uint8Array): bigint {
  let hex = "0x";
  for (const b of bytes) {
    hex += b.toString(16).padStart(2, "0");
  }
  return BigInt(hex);
}

async function loadKeypair(keyPath: string): Promise<Keypair> {
  const absolutePath = keyPath.replace("~", process.env.HOME || "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

// =============================================================================
// PDA Derivation
// =============================================================================

function derivePoolStatePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEEDS.POOL_STATE)],
    programId
  );
}

function deriveCommitmentTreePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEEDS.COMMITMENT_TREE)],
    programId
  );
}

function deriveNullifierPDA(nullifierHash: Uint8Array, programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEEDS.NULLIFIER), nullifierHash],
    programId
  );
}

function deriveStealthAnnouncementPDA(ephemeralPub: Uint8Array, programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEEDS.STEALTH), Buffer.from(ephemeralPub.slice(1, 33))],
    programId
  );
}

// =============================================================================
// On-Chain State Parsing
// =============================================================================

interface CommitmentTreeState {
  bump: number;
  currentRoot: bigint;
  nextIndex: bigint;
  frontier: bigint[];
}

function parseCommitmentTree(data: Buffer): CommitmentTreeState {
  // Layout: disc(1) + bump(1) + padding(6) = 8 bytes header
  // Then: current_root(32) + next_index(8) + frontier([32]*20) + root_history([32]*100)
  const bump = data[1];
  const currentRoot = bytes32ToBigint(data.subarray(8, 40));
  const nextIndex = data.readBigUInt64LE(40);

  // frontier at offset 48, size 32*20 = 640 bytes
  const frontier: bigint[] = [];
  const frontierOffset = 48;
  for (let i = 0; i < TREE_DEPTH; i++) {
    const start = frontierOffset + i * 32;
    frontier.push(bytes32ToBigint(data.subarray(start, start + 32)));
  }

  return { bump, currentRoot, nextIndex, frontier };
}

// =============================================================================
// ZERO_HASHES (must match on-chain values)
// =============================================================================

// Pre-computed Poseidon zero hashes for empty subtrees
// ZERO_HASHES[0] = 0 (empty leaf)
// ZERO_HASHES[i] = Poseidon(ZERO_HASHES[i-1], ZERO_HASHES[i-1])
function computeZeroHashes(): bigint[] {
  const zeroHashes: bigint[] = [0n];
  for (let i = 1; i <= TREE_DEPTH; i++) {
    zeroHashes.push(poseidonHashSync([zeroHashes[i - 1], zeroHashes[i - 1]]));
  }
  return zeroHashes;
}

// =============================================================================
// Merkle Proof Computation
// =============================================================================

/**
 * Compute merkle proof for a leaf at given index using frontier
 *
 * For an incremental Merkle tree:
 * - frontier[level] = the rightmost filled node at that level
 * - When leaf index bit at level is 0 (left child): sibling is ZERO_HASHES[level]
 * - When leaf index bit at level is 1 (right child): sibling is frontier[level]
 */
function computeMerkleProof(
  commitment: bigint,
  leafIndex: number,
  frontier: bigint[],
  zeroHashes: bigint[]
): { siblings: bigint[]; indices: number[]; root: bigint } {
  const siblings: bigint[] = [];
  const indices: number[] = [];

  let current = commitment;
  let idx = leafIndex;

  for (let level = 0; level < TREE_DEPTH; level++) {
    const isRight = (idx & 1) === 1;
    indices.push(isRight ? 1 : 0);

    // Get sibling:
    // - If we're a left child (isRight=false), sibling is the zero hash for this level
    // - If we're a right child (isRight=true), sibling is from frontier
    const sibling = isRight ? frontier[level] : zeroHashes[level];
    siblings.push(sibling);

    // Compute parent hash
    if (isRight) {
      current = poseidonHashSync([sibling, current]);
    } else {
      current = poseidonHashSync([current, sibling]);
    }

    idx = idx >> 1;
  }

  return { siblings, indices, root: current };
}

// =============================================================================
// VK Hash Computation
// =============================================================================

/**
 * Compute VK hash from circuit JSON (for Groth16 verification)
 * The VK hash is sha256 of the circuit's verification key bytes
 */
async function computeVkHash(circuitName: string): Promise<Uint8Array> {
  const circuitPath = path.resolve(__dirname, "../../sdk/circuits", `${circuitName}.json`);
  const circuitJson = JSON.parse(fs.readFileSync(circuitPath, "utf-8"));

  // For Groth16, the VK is derived from the circuit
  // Use a deterministic hash of the circuit bytecode as VK identifier
  const bytecode = circuitJson.bytecode;
  const bytecodeBytes = Buffer.from(bytecode, "base64");

  // Hash the bytecode to get VK hash
  const hash = sha256(bytecodeBytes);
  return new Uint8Array(hash);
}

// =============================================================================
// ChadBuffer Upload (for large proofs)
// =============================================================================

// ChadBuffer instruction discriminators
const CHADBUFFER_IX = {
  CREATE: 0,
  ASSIGN: 1,
  WRITE: 2,
  CLOSE: 3,
};

// Max data per write tx
// Overhead: signature (64) + msg header (3) + 2 account keys (66) + ix header (4) + disc (1) + u24 offset (3) = 141 bytes
// Using 176 bytes for safety margin: 1232 - 176 = 1056 bytes max
const MAX_DATA_PER_WRITE = 950; // Tx overhead ~207 bytes + priority fee ~25 bytes = ~232 bytes overhead

// Buffer authority size
const AUTHORITY_SIZE = 32;

function createChadBufferCreateIx(
  chadbufferProgramId: PublicKey,
  bufferKeypair: Keypair,
  payer: PublicKey,
  initialData: Uint8Array
): TransactionInstruction {
  const data = Buffer.alloc(1 + initialData.length);
  data[0] = CHADBUFFER_IX.CREATE;
  data.set(initialData, 1);

  // ChadBuffer CREATE expects: payer, buffer (no system program - account created separately)
  return new TransactionInstruction({
    programId: chadbufferProgramId,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: bufferKeypair.publicKey, isSigner: true, isWritable: true },
    ],
    data,
  });
}

function createChadBufferWriteIx(
  chadbufferProgramId: PublicKey,
  buffer: PublicKey,
  payer: PublicKey,
  offset: number,
  data: Uint8Array
): TransactionInstruction {
  const ixData = Buffer.alloc(4 + data.length);
  ixData[0] = CHADBUFFER_IX.WRITE;
  // u24 offset (little-endian)
  ixData[1] = offset & 0xff;
  ixData[2] = (offset >> 8) & 0xff;
  ixData[3] = (offset >> 16) & 0xff;
  ixData.set(data, 4);

  return new TransactionInstruction({
    programId: chadbufferProgramId,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: buffer, isSigner: false, isWritable: true },
    ],
    data: ixData,
  });
}

function createChadBufferCloseIx(
  chadbufferProgramId: PublicKey,
  buffer: PublicKey,
  payer: PublicKey
): TransactionInstruction {
  return new TransactionInstruction({
    programId: chadbufferProgramId,
    keys: [
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: buffer, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([CHADBUFFER_IX.CLOSE]),
  });
}

async function uploadProofToBuffer(
  connection: Connection,
  chadbufferProgramId: PublicKey,
  payer: Keypair,
  proof: Uint8Array
): Promise<PublicKey> {
  // Create buffer keypair
  const bufferKeypair = Keypair.generate();
  const bufferSize = AUTHORITY_SIZE + proof.length;

  log(`Creating buffer for ${proof.length} byte proof...`);

  // Calculate rent
  const rentExemption = await connection.getMinimumBalanceForRentExemption(bufferSize);

  // ChadBuffer CREATE:
  // - discriminator (1 byte)
  // - initial data (variable)
  // Combined with SystemProgram.createAccount, we have limited space.
  // Transaction overhead: ~360 bytes (2 signatures @ 128, header, accounts, instructions)
  // Max tx size: 1232 bytes
  // Available for data: 1232 - 360 = ~870 bytes max, use 800 for safety
  const firstChunkSize = Math.min(800, proof.length);
  const firstChunk = proof.slice(0, firstChunkSize);

  // Create account via SystemProgram + Initialize via ChadBuffer CREATE in one tx
  const createAccountIx = SystemProgram.createAccount({
    fromPubkey: payer.publicKey,
    newAccountPubkey: bufferKeypair.publicKey,
    lamports: rentExemption,
    space: bufferSize,
    programId: chadbufferProgramId,
  });

  const initIx = createChadBufferCreateIx(
    chadbufferProgramId,
    bufferKeypair,
    payer.publicKey,
    firstChunk
  );

  // Add priority fee for devnet congestion (1M micro-lamports for fast inclusion)
  const priorityFeeIx = NETWORK === "devnet"
    ? ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000 })
    : null;

  const createTx = new Transaction();
  if (priorityFeeIx) createTx.add(priorityFeeIx);
  createTx.add(createAccountIx, initIx);

  await sendAndConfirmTransaction(connection, createTx, [payer, bufferKeypair], {
    commitment: "confirmed",
    skipPreflight: NETWORK === "devnet",
  });
  log(`✓ Buffer created with ${firstChunkSize} bytes: ${bufferKeypair.publicKey.toBase58().slice(0, 16)}...`);

  // Build all remaining chunks
  const chunks: { offset: number; data: Uint8Array }[] = [];
  let currentOffset = firstChunkSize;
  while (currentOffset < proof.length) {
    const chunkSize = Math.min(MAX_DATA_PER_WRITE, proof.length - currentOffset);
    chunks.push({
      offset: currentOffset,
      data: proof.slice(currentOffset, currentOffset + chunkSize),
    });
    currentOffset += chunkSize;
  }

  // Upload chunks in parallel batches (5 at a time to avoid rate limiting)
  const BATCH_SIZE = 5;
  for (let i = 0; i < chunks.length; i += BATCH_SIZE) {
    const batch = chunks.slice(i, i + BATCH_SIZE);

    const promises = batch.map(async (chunk, batchIdx) => {
      const writeIx = createChadBufferWriteIx(
        chadbufferProgramId,
        bufferKeypair.publicKey,
        payer.publicKey,
        AUTHORITY_SIZE + chunk.offset,
        chunk.data
      );

      const writeTx = new Transaction();
      if (priorityFeeIx) writeTx.add(priorityFeeIx);
      writeTx.add(writeIx);

      // Retry logic
      let retries = 3;
      while (retries > 0) {
        try {
          await sendAndConfirmTransaction(connection, writeTx, [payer], {
            commitment: "confirmed",
            skipPreflight: NETWORK === "devnet",
          });
          return;
        } catch (err: any) {
          retries--;
          if (retries === 0) throw err;
          log(`  Chunk ${i + batchIdx + 2} failed, retrying... (${retries} left)`);
          await new Promise((r) => setTimeout(r, 500));
        }
      }
    });

    await Promise.all(promises);
    log(`  Batch ${Math.floor(i / BATCH_SIZE) + 1}: ${batch.length} chunks uploaded`);
  }

  log(`✓ Uploaded ${chunks.length + 1} chunks total (${proof.length} bytes)`);

  return bufferKeypair.publicKey;
}

// =============================================================================
// Build Claim Instruction
// =============================================================================

/**
 * Build claim instruction data for BUFFER mode (proof_source=1)
 * Buffer mode: discriminator(1) + proof_source(1) + root(32) + nullifier(32) + amount(8) + recipient(32) + vk_hash(32)
 */
function buildClaimDataBufferMode(
  root: Uint8Array,
  nullifierHash: Uint8Array,
  amountSats: bigint,
  recipient: PublicKey,
  vkHash: Uint8Array
): Uint8Array {
  const totalSize = 1 + 1 + 32 + 32 + 8 + 32 + 32; // 138 bytes
  const data = new Uint8Array(totalSize);
  const view = new DataView(data.buffer);
  let offset = 0;

  // Discriminator
  data[offset++] = DISCRIMINATOR.CLAIM;
  // Proof source (1 = buffer)
  data[offset++] = 1;
  // Root
  data.set(root, offset);
  offset += 32;
  // Nullifier hash
  data.set(nullifierHash, offset);
  offset += 32;
  // Amount (little endian)
  view.setBigUint64(offset, amountSats, true);
  offset += 8;
  // Recipient
  data.set(recipient.toBytes(), offset);
  offset += 32;
  // VK hash
  data.set(vkHash, offset);

  return data;
}

function buildClaimData(
  proof: Uint8Array,
  root: Uint8Array,
  nullifierHash: Uint8Array,
  amountSats: bigint,
  recipient: PublicKey,
  vkHash: Uint8Array
): Uint8Array {
  // Inline mode: discriminator(1) + proof_source(1) + proof_len(4) + proof + root(32) + nullifier(32) + amount(8) + recipient(32) + vk_hash(32)
  const proofLen = proof.length;
  const totalSize = 1 + 1 + 4 + proofLen + 32 + 32 + 8 + 32 + 32;
  const data = new Uint8Array(totalSize);
  const view = new DataView(data.buffer);
  let offset = 0;

  // Discriminator
  data[offset++] = DISCRIMINATOR.CLAIM;
  // Proof source (0 = inline)
  data[offset++] = 0;
  // Proof length (little endian)
  view.setUint32(offset, proofLen, true);
  offset += 4;
  // Proof bytes
  data.set(proof, offset);
  offset += proofLen;
  // Root
  data.set(root, offset);
  offset += 32;
  // Nullifier hash
  data.set(nullifierHash, offset);
  offset += 32;
  // Amount (little endian)
  view.setBigUint64(offset, amountSats, true);
  offset += 8;
  // Recipient
  data.set(recipient.toBytes(), offset);
  offset += 32;
  // VK hash
  data.set(vkHash, offset);

  return data;
}

// =============================================================================
// Main Test
// =============================================================================

async function main() {
  console.log("============================================================");
  console.log("Full On-Chain E2E Test - Real Proof Verification");
  console.log("============================================================");

  // Load configs
  if (!fs.existsSync(configPath)) {
    console.error("❌ Localnet config not found. Run deploy-localnet.ts first.");
    process.exit(1);
  }
  const localConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
  const mainConfig = JSON.parse(fs.readFileSync(mainConfigPath, "utf-8"));

  // Setup connection
  const connection = new Connection(RPC_URL, "confirmed");
  const walletPath = mainConfig.wallet?.path || "~/.config/solana/id.json";
  const authority = await loadKeypair(walletPath);

  // Program IDs
  const programId = new PublicKey(localConfig.programs.UTXOpia);
  const zkbtcMint = new PublicKey(localConfig.accounts.zkbtcMint);
  const poolVault = new PublicKey(localConfig.accounts.poolVault);

  // Groth16 verifier - get from config or keypair
  let groth16VerifierId: PublicKey;
  if (localConfig.programs.groth16Verifier) {
    groth16VerifierId = new PublicKey(localConfig.programs.groth16Verifier);
  } else {
    const groth16KeypairPath = path.join(__dirname, "..", "target/deploy/groth16_verifier-keypair.json");
    const groth16Keypair = await loadKeypair(groth16KeypairPath);
    groth16VerifierId = groth16Keypair.publicKey;
  }

  // PDAs
  const [poolStatePda] = derivePoolStatePDA(programId);
  const [commitmentTreePda] = deriveCommitmentTreePDA(programId);

  logSection("Setup");
  log(`Authority: ${authority.publicKey.toBase58()}`);
  log(`Program ID: ${programId.toBase58()}`);
  log(`Groth16 Verifier: ${groth16VerifierId.toBase58()}`);
  log(`zkBTC Mint: ${zkbtcMint.toBase58()}`);

  // Initialize Poseidon
  await initPoseidon();
  log("✓ Poseidon initialized");

  // Compute zero hashes (needed for merkle proofs)
  const zeroHashes = computeZeroHashes();
  log(`✓ Zero hashes computed (${zeroHashes.length} levels)`);

  // Initialize prover
  const circuitPath = path.resolve(__dirname, "../../sdk/circuits");
  setCircuitPath(circuitPath);
  await initProver();
  log("✓ Prover initialized");

  // ==========================================================================
  // Step 1: Generate UTXOPIA keys (proper stealth model)
  // ==========================================================================
  logSection("Step 1: Generate Stealth Keys");

  // Generate deterministic keys from a seed (simulating wallet signature derivation)
  const testSeed = randomFieldElement();
  const keys: UTXOpiaKeys = await deriveKeysFromSeed(bigintToBytes32(testSeed));

  // Create stealth meta address (spending + viewing public keys)
  const stealthMetaAddress: StealthMetaAddress = createStealthMetaAddress(keys);

  log(`Spending pub X: 0x${keys.spendingPubKey.x.toString(16).slice(0, 16)}...`);
  log(`Viewing pub X: 0x${keys.viewingPubKey.x.toString(16).slice(0, 16)}...`);

  // ==========================================================================
  // Step 2: Create stealth deposit (correct commitment model)
  // ==========================================================================
  logSection("Step 2: Create Stealth Deposit");

  // Use SDK's createStealthDeposit - produces correct commitment: Poseidon(stealthPub.x, amount)
  // where stealthPub.x is an EC point x-coordinate (not a Poseidon hash!)
  const stealthDepositData = await createStealthDeposit(stealthMetaAddress, DEMO_AMOUNT);

  // Extract deposit data
  const ephemeralPub = stealthDepositData.ephemeralPub;
  const commitment = bytesToBigint(stealthDepositData.commitment);
  const commitmentBytes = stealthDepositData.commitment;
  const encryptedAmountBytes = stealthDepositData.encryptedAmount;

  log(`Ephemeral pub: 0x${Buffer.from(ephemeralPub).toString("hex").slice(0, 16)}...`);
  log(`Commitment: 0x${commitment.toString(16).slice(0, 16)}...`);
  log(`Encrypted amount: 0x${Buffer.from(encryptedAmountBytes).toString("hex")}`);

  const [stealthAnnouncementPDA] = deriveStealthAnnouncementPDA(ephemeralPub, programId);

  const demoData = buildAddDemoStealthData(ephemeralPub, commitmentBytes, encryptedAmountBytes);

  const demoIx = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: poolStatePda, isWritable: true, isSigner: false },
      { pubkey: commitmentTreePda, isWritable: true, isSigner: false },
      { pubkey: stealthAnnouncementPDA, isWritable: true, isSigner: false },
      { pubkey: authority.publicKey, isWritable: true, isSigner: true },
      { pubkey: SystemProgram.programId, isWritable: false, isSigner: false },
      { pubkey: zkbtcMint, isWritable: true, isSigner: false },
      { pubkey: poolVault, isWritable: true, isSigner: false },
      { pubkey: TOKEN_2022_PROGRAM_ID, isWritable: false, isSigner: false },
    ],
    data: Buffer.from(demoData),
  });

  const demoTx = new Transaction();
  if (NETWORK === "devnet") {
    demoTx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000 }));
  }
  demoTx.add(demoIx);

  // Retry logic for demo deposit
  let demoSig = "";
  let demoRetries = 3;
  while (demoRetries > 0) {
    try {
      demoSig = await sendAndConfirmTransaction(connection, demoTx, [authority], {
        commitment: "confirmed",
        skipPreflight: NETWORK === "devnet",
      });
      break;
    } catch (err: any) {
      demoRetries--;
      if (demoRetries === 0) throw err;
      log(`  Demo deposit failed, retrying... (${demoRetries} left)`);
      await new Promise((r) => setTimeout(r, 2000));
    }
  }
  log(`✓ Demo deposit: ${demoSig.slice(0, 16)}...`);

  // ==========================================================================
  // Step 3: Fetch on-chain tree state
  // ==========================================================================
  logSection("Step 3: Fetch On-Chain Tree State");

  const treeAccount = await connection.getAccountInfo(commitmentTreePda);
  if (!treeAccount) throw new Error("Commitment tree not found");

  const treeState = parseCommitmentTree(treeAccount.data as Buffer);
  const leafIndex = Number(treeState.nextIndex) - 1;

  log(`Leaf index: ${leafIndex}`);
  log(`On-chain root: 0x${treeState.currentRoot.toString(16).slice(0, 16)}...`);
  log(`Next index: ${treeState.nextIndex}`);

  // ==========================================================================
  // Step 4: Compute merkle proof matching on-chain root
  // ==========================================================================
  logSection("Step 4: Compute Merkle Proof");

  const merkleProof = computeMerkleProof(commitment, leafIndex, treeState.frontier, zeroHashes);

  log(`Computed root: 0x${merkleProof.root.toString(16).slice(0, 16)}...`);
  log(`Root match: ${merkleProof.root === treeState.currentRoot ? "✓ YES" : "❌ NO"}`);

  if (merkleProof.root !== treeState.currentRoot) {
    log("⚠ Root mismatch - using on-chain root for proof");
  }

  // ==========================================================================
  // Step 5: Scan the deposit and derive stealth key
  // ==========================================================================
  logSection("Step 5: Scan Deposit & Derive Keys");

  const leafIndexBigint = BigInt(leafIndex);

  // Use scanAnnouncements to properly reconstruct the ScannedNote
  // This uses the SDK's internal stealth derivation logic (SHA256 domain separator)
  const { scanAnnouncements } = await import("@utxopia/sdk");

  // Format the deposit as an announcement for scanning
  const announcements = [{
    ephemeralPub: ephemeralPub,
    encryptedAmount: encryptedAmountBytes,
    commitment: commitmentBytes,
    leafIndex: leafIndex,
  }];

  // Scan using our keys - this derives stealthPub correctly
  const scannedNotes = await scanAnnouncements(keys, announcements);

  if (scannedNotes.length === 0) {
    throw new Error("Failed to scan deposit - commitment mismatch or decryption failed");
  }

  const scannedNote = scannedNotes[0];
  log(`✓ Deposit scanned successfully`);
  log(`  Amount: ${scannedNote.amount.toString()} sats`);
  log(`  StealthPub.x: 0x${scannedNote.stealthPub.x.toString(16).slice(0, 16)}...`);

  // Use SDK's prepareClaimInputs to derive stealthPrivKey correctly
  const claimPrepInputs = await prepareClaimInputs(keys, scannedNote, {
    root: treeState.currentRoot,
    pathElements: merkleProof.siblings,
    pathIndices: merkleProof.indices,
  });

  // Extract stealthPrivKey and pubKeyX from prepared inputs
  const stealthPrivKey = claimPrepInputs.stealthPrivKey;
  const pubKeyX = scannedNote.stealthPub.x;

  log(`Stealth priv: 0x${stealthPrivKey.toString(16).slice(0, 16)}...`);
  log(`Stealth pub X: 0x${pubKeyX.toString(16).slice(0, 16)}...`);

  // Compute nullifier using stealth private key
  const nullifier = computeNullifierSync(stealthPrivKey, leafIndexBigint);
  const nullifierHash = hashNullifierSync(nullifier);
  const nullifierHashBytes = bigintToBytes32(nullifierHash);

  log(`Nullifier: 0x${nullifier.toString(16).slice(0, 16)}...`);
  log(`Nullifier hash: 0x${nullifierHash.toString(16).slice(0, 16)}...`);

  // Verify commitment matches what circuit will compute
  const expectedCommitment = computeUnifiedCommitmentSync(pubKeyX, DEMO_AMOUNT);
  if (expectedCommitment !== commitment) {
    log(`⚠ Commitment mismatch!`);
    log(`  Expected: 0x${expectedCommitment.toString(16).slice(0, 16)}...`);
    log(`  Actual: 0x${commitment.toString(16).slice(0, 16)}...`);
    throw new Error("Commitment verification failed");
  }
  log(`✓ Commitment verified: Poseidon(stealthPub.x, amount)`);

  // ==========================================================================
  // Step 6: Generate ZK proof
  // ==========================================================================
  logSection("Step 6: Generate ZK Proof");

  // Convert recipient (Solana pubkey) to bigint for circuit
  const recipientBigint = bytes32ToBigint(authority.publicKey.toBytes());

  const claimInputs: ClaimInputs = {
    privKey: stealthPrivKey,  // Use stealth private key (not original spending key!)
    pubKeyX,                  // Use stealthPub.x (EC point x-coordinate)
    amount: DEMO_AMOUNT,
    leafIndex: leafIndexBigint,
    merkleRoot: treeState.currentRoot, // Use on-chain root
    merkleProof: {
      siblings: merkleProof.siblings,
      indices: merkleProof.indices,
    },
    recipient: recipientBigint, // Bound to proof - prevents fund redirection
  };

  log("Generating Groth16 proof...");
  const startTime = Date.now();
  const proofData = await generateClaimProof(claimInputs);
  const duration = ((Date.now() - startTime) / 1000).toFixed(2);

  log(`✓ Proof generated in ${duration}s`);
  log(`Proof size: ${proofData.proof.length} bytes`);
  log(`Public inputs: ${proofData.publicInputs.length}`);

  // ==========================================================================
  // Step 7: Compute VK hash
  // ==========================================================================
  logSection("Step 7: Compute VK Hash");

  const vkHash = await computeVkHash("utxopia_claim");
  log(`VK hash: 0x${Buffer.from(vkHash).toString("hex").slice(0, 32)}...`);

  // ==========================================================================
  // Step 8: Upload Proof to ChadBuffer
  // ==========================================================================
  logSection("Step 8: Upload Proof to ChadBuffer");

  // Get ChadBuffer program ID from config
  const chadbufferProgramId = new PublicKey(localConfig.programs.chadbuffer);
  log(`ChadBuffer Program: ${chadbufferProgramId.toBase58()}`);
  log(`Proof size: ${proofData.proof.length} bytes`);

  // Upload proof to buffer
  const proofBuffer = await uploadProofToBuffer(
    connection,
    chadbufferProgramId,
    authority,
    proofData.proof
  );
  log(`✓ Proof buffer: ${proofBuffer.toBase58()}`);

  // ==========================================================================
  // Step 9: Submit On-Chain Claim (Buffer Mode)
  // ==========================================================================
  logSection("Step 9: Submit On-Chain Claim (Buffer Mode)");

  // Create recipient ATA if needed
  const recipientAta = getAssociatedTokenAddressSync(
    zkbtcMint,
    authority.publicKey,
    false,
    TOKEN_2022_PROGRAM_ID
  );

  try {
    await getAccount(connection, recipientAta, "confirmed", TOKEN_2022_PROGRAM_ID);
    log(`Recipient ATA exists: ${recipientAta.toBase58()}`);
  } catch {
    log("Creating recipient ATA...");
    const createAtaIx = createAssociatedTokenAccountInstruction(
      authority.publicKey,
      recipientAta,
      authority.publicKey,
      zkbtcMint,
      TOKEN_2022_PROGRAM_ID
    );
    const ataTx = new Transaction();
    if (NETWORK === "devnet") {
      ataTx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000 }));
    }
    ataTx.add(createAtaIx);
    await sendAndConfirmTransaction(connection, ataTx, [authority], { commitment: "confirmed" });
    log(`✓ Created: ${recipientAta.toBase58()}`);
  }

  // Derive nullifier PDA
  const [nullifierPda] = deriveNullifierPDA(nullifierHashBytes, programId);

  // Build claim instruction data in BUFFER MODE (proof_source=1)
  const claimData = buildClaimDataBufferMode(
    bigintToBytes32(treeState.currentRoot),
    nullifierHashBytes,
    DEMO_AMOUNT,
    authority.publicKey,
    vkHash
  );

  // Add compute budget and priority fee for devnet
  const computeIx = ComputeBudgetProgram.setComputeUnitLimit({
    units: 1_400_000,
  });
  const claimPriorityIx = NETWORK === "devnet"
    ? ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000 })
    : null;

  // Build claim instruction with proof buffer account
  // Account order: pool_state, commitment_tree, nullifier, zkbtc_mint, pool_vault, recipient_ata, user, token_program, system_program, groth16_verifier, proof_buffer
  const claimIx = new TransactionInstruction({
    programId,
    keys: [
      { pubkey: poolStatePda, isWritable: true, isSigner: false },         // 0: pool_state
      { pubkey: commitmentTreePda, isWritable: false, isSigner: false },   // 1: commitment_tree
      { pubkey: nullifierPda, isWritable: true, isSigner: false },         // 2: nullifier_record
      { pubkey: zkbtcMint, isWritable: true, isSigner: false },            // 3: zkbtc_mint
      { pubkey: poolVault, isWritable: true, isSigner: false },            // 4: pool_vault
      { pubkey: recipientAta, isWritable: true, isSigner: false },         // 5: recipient_ata
      { pubkey: authority.publicKey, isWritable: true, isSigner: true },   // 6: user (signer)
      { pubkey: TOKEN_2022_PROGRAM_ID, isWritable: false, isSigner: false }, // 7: token_program
      { pubkey: SystemProgram.programId, isWritable: false, isSigner: false }, // 8: system_program
      { pubkey: groth16VerifierId, isWritable: false, isSigner: false }, // 9: groth16_verifier
      { pubkey: proofBuffer, isWritable: false, isSigner: false },         // 10: proof_buffer (buffer mode)
    ],
    data: Buffer.from(claimData),
  });

  const claimTx = new Transaction();
  if (claimPriorityIx) claimTx.add(claimPriorityIx);
  claimTx.add(computeIx, claimIx);

  log(`Instruction size: ${claimData.length} bytes (buffer mode)`);
  log(`Nullifier PDA: ${nullifierPda.toBase58()}`);
  log(`Proof buffer: ${proofBuffer.toBase58()}`);
  log("Submitting claim transaction...");

  try {
    // Simulate first
    const { value: simResult } = await connection.simulateTransaction(claimTx, [authority]);

    if (simResult.err) {
      log(`❌ Simulation failed: ${JSON.stringify(simResult.err)}`);
      if (simResult.logs) {
        log("Logs:");
        simResult.logs.forEach((l) => console.log(`    ${l}`));
      }
    } else {
      log(`✓ Simulation passed! CU: ${simResult.unitsConsumed}`);

      // Send real transaction
      const sig = await sendAndConfirmTransaction(connection, claimTx, [authority], {
        commitment: "confirmed",
      });
      log(`✓ Claim successful! Signature: ${sig}`);

      // Check balance
      const ataAccount = await getAccount(connection, recipientAta, "confirmed", TOKEN_2022_PROGRAM_ID);
      log(`✓ Recipient balance: ${ataAccount.amount} sats`);
    }
  } catch (err: any) {
    log(`❌ Error: ${err.message}`);
    if (err.logs) {
      log("Logs:");
      err.logs.forEach((l: string) => console.log(`    ${l}`));
    }
  }

  // ==========================================================================
  // Step 10: Close Proof Buffer (reclaim rent)
  // ==========================================================================
  logSection("Step 10: Close Proof Buffer");

  try {
    const closeIx = createChadBufferCloseIx(chadbufferProgramId, proofBuffer, authority.publicKey);
    const closeTx = new Transaction();
    if (NETWORK === "devnet") {
      closeTx.add(ComputeBudgetProgram.setComputeUnitPrice({ microLamports: 1_000_000 }));
    }
    closeTx.add(closeIx);
    const closeSig = await sendAndConfirmTransaction(connection, closeTx, [authority], {
      commitment: "confirmed",
    });
    log(`✓ Buffer closed, rent reclaimed: ${closeSig.slice(0, 16)}...`);
  } catch (err: any) {
    log(`⚠ Failed to close buffer: ${err.message}`);
  }

  // Cleanup
  logSection("Cleanup");
  await cleanupProver();
  log("✓ Prover resources released");

  console.log("\n============================================================");
  console.log("E2E Test Complete");
  console.log("============================================================\n");
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
