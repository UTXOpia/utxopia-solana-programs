/**
 * JoinSplit Groth16 Proof Integration Test
 *
 * Tests the full flow:
 * 1. Register VK hash for joinsplit_1x1 variant
 * 2. Create a demo deposit (commitment in Merkle tree)
 * 3. Generate Baby Jubjub keys + EdDSA-Poseidon signature
 * 4. Build a real Groth16 proof via snarkjs (Node.js subprocess for bun compat)
 * 5. Submit transact instruction (disc=14) with real proof
 * 6. Verify on-chain: nullifier PDA, commitment tree update, stealth announcement
 *
 * Prerequisites:
 *   - solana-test-validator running (with BN254: --clone-feature-set --url devnet)
 *   - Programs deployed (bun run deploy:localnet)
 *
 * Run:
 *   bun run scripts/test-joinsplit-proof.ts
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
} from "@solana/spl-token";
import { sha256 } from "@noble/hashes/sha2.js";
import { buildPoseidon } from "circomlibjs";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { fileURLToPath } from "url";
import { execSync } from "child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =============================================================================
// Configuration
// =============================================================================

const NETWORK = process.env.NETWORK || "localnet";
const RPC_URL = process.env.RPC_URL || (NETWORK === "devnet"
  ? "https://api.devnet.solana.com"
  : "http://127.0.0.1:8899");

const DEVNET_PROGRAM_ID = "7JJeVjVCy1fZqCDWvf41R7LuTWirTjX7Tp6suC2WVUMQ";

function loadConfig(): any {
  const configFile = NETWORK === "devnet" ? ".devnet-config.json" : ".localnet-config.json";
  const configPath = path.join(__dirname, "..", configFile);
  return JSON.parse(fs.readFileSync(configPath, "utf-8"));
}

function loadProgramId(): PublicKey {
  if (process.env.PROGRAM_ID) return new PublicKey(process.env.PROGRAM_ID);
  try {
    const config = loadConfig();
    return new PublicKey(config.programs.UTXOpia);
  } catch {
    return NETWORK === "devnet"
      ? new PublicKey(DEVNET_PROGRAM_ID)
      : new PublicKey("3Df8Xv9hMtVVLRxagnbCsofvgn18yPzfCqTmbUEnx9KF");
  }
}

const PROGRAM_ID = loadProgramId();

// Constants
const ZKBTC_TOKEN_ID = 0x7a627463n; // "zkbtc" as u32
const BN254_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
const BABYJUB_ORDER = 2736030358979909402780800718157159386076813972158567259200215660948447373041n;
const TREE_DEPTH = 16;

// Instruction discriminators
const Instruction = {
  INITIALIZE: 0,
  INIT_VK_REGISTRY: 11,
  ADD_DEMO_STEALTH: 13,
  TRANSACT: 14,
} as const;

// Seeds
const Seeds = {
  POOL_STATE: "pool_state",
  COMMITMENT_TREE: "commitment_tree",
  VK_REGISTRY: "vk_registry",
  NULLIFIER: "nullifier",
  STEALTH_ANNOUNCEMENT: "stealth",
};

// =============================================================================
// Poseidon Instance (circomlibjs — matches on-chain sol_poseidon)
// =============================================================================

let poseidon: any;

async function initPoseidon() {
  poseidon = await buildPoseidon();
}

function poseidonHash(inputs: bigint[]): bigint {
  const hash = poseidon(inputs);
  return poseidon.F.toObject(hash) as bigint;
}

// =============================================================================
// Baby Jubjub (minimal impl for key generation)
// =============================================================================

const BJJ_A = 168700n;
const BJJ_D = 168696n;
const P = BN254_FIELD_PRIME;

function modInv(a: bigint, p: bigint): bigint {
  let [old_r, r] = [a % p, p];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  return ((old_s % p) + p) % p;
}

interface Point { x: bigint; y: bigint }

function bjjAdd(p1: Point, p2: Point): Point {
  const x1x2 = (p1.x * p2.x) % P;
  const y1y2 = (p1.y * p2.y) % P;
  const dx1x2y1y2 = (BJJ_D * x1x2 % P) * y1y2 % P;
  const x3Num = ((p1.x * p2.y % P) + (p1.y * p2.x % P)) % P;
  const x3Den = (1n + dx1x2y1y2) % P;
  const y3Num = (y1y2 + P - BJJ_A * x1x2 % P) % P;
  const y3Den = (1n + P - dx1x2y1y2 % P) % P;
  return {
    x: (x3Num * modInv(x3Den, P)) % P,
    y: (y3Num * modInv(y3Den, P)) % P,
  };
}

function bjjMul(scalar: bigint, point: Point): Point {
  let result: Point = { x: 0n, y: 1n }; // identity
  let base = { ...point };
  let s = scalar;
  while (s > 0n) {
    if (s & 1n) result = bjjAdd(result, base);
    base = bjjAdd(base, base);
    s >>= 1n;
  }
  return result;
}

// BASE8 generator (from circomlib)
const BASE8: Point = {
  x: 5299619240641551281634865583518297030282874472190772894086521144482721001553n,
  y: 16950150798460657717958625567821834550301663161624707787222815936182638968203n,
};

// =============================================================================
// Helpers
// =============================================================================

function bigintToBytes32BE(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let v = value;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return bytes;
}

function bytes32ToBigintBE(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes32ToBigintBE(bytes) % BN254_FIELD_PRIME;
}

// =============================================================================
// PDA Derivations
// =============================================================================

function derivePoolStatePDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from(Seeds.POOL_STATE)], PROGRAM_ID);
}

function deriveCommitmentTreePDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Buffer.from(Seeds.COMMITMENT_TREE)], PROGRAM_ID);
}

function deriveVkRegistryPDA(nInputs: number, nOutputs: number): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.VK_REGISTRY), Buffer.from([nInputs]), Buffer.from([nOutputs])],
    PROGRAM_ID,
  );
}

function deriveNullifierPDA(nullifierHash: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.NULLIFIER), Buffer.from(nullifierHash)],
    PROGRAM_ID,
  );
}

function deriveStealthAnnouncementPDA(ephemeralPub: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.STEALTH_ANNOUNCEMENT), Buffer.from(ephemeralPub)],
    PROGRAM_ID,
  );
}

// =============================================================================
// On-chain state parsers
// =============================================================================

function parseCommitmentTree(data: Buffer) {
  if (data.length < 100 || data[0] !== 0x05) return null;
  return {
    discriminator: data[0],
    bump: data[1],
    currentRoot: data.subarray(8, 40),
    nextIndex: data.readBigUInt64LE(40),
    // frontier starts at offset 48, 16 * 32 = 512 bytes
    frontier: data.subarray(48, 48 + TREE_DEPTH * 32),
  };
}

// =============================================================================
// Merkle Tree (local, matches on-chain Poseidon tree)
// =============================================================================

// Pre-computed zero hashes (must match commitment_tree.rs)
const ZERO_HASHES: bigint[] = [
  0n, // level 0: empty leaf
];

function computeZeroHashes() {
  for (let i = 1; i <= TREE_DEPTH; i++) {
    ZERO_HASHES[i] = poseidonHash([ZERO_HASHES[i - 1], ZERO_HASHES[i - 1]]);
  }
}

/**
 * Compute Merkle proof for the LAST inserted leaf using on-chain frontier.
 *
 * The incremental Merkle tree stores only the frontier (rightmost filled node
 * at each level). For the last inserted leaf, the proof is:
 *   - If bit is 0 (left child): sibling = ZERO_HASHES[level]
 *   - If bit is 1 (right child): sibling = frontier[level]
 */
function getMerkleProofFromFrontier(
  leafIndex: number,
  frontier: bigint[],
): { siblings: bigint[]; indices: number[] } {
  const siblings: bigint[] = [];
  const indices: number[] = [];

  let idx = leafIndex;
  for (let level = 0; level < TREE_DEPTH; level++) {
    const bit = idx & 1;
    indices.push(bit);
    if (bit === 0) {
      // Left child — right sibling doesn't exist yet
      siblings.push(ZERO_HASHES[level]);
    } else {
      // Right child — left sibling is in the frontier
      siblings.push(frontier[level]);
    }
    idx >>= 1;
  }

  return { siblings, indices };
}

// =============================================================================
// VK Hash Computation (matches register-vk-hashes.ts)
// =============================================================================

function serializeG1(point: string[]): Buffer {
  const x = BigInt(point[0]);
  const y = BigInt(point[1]);
  const buf = Buffer.alloc(64);
  Buffer.from(x.toString(16).padStart(64, "0"), "hex").copy(buf, 0);
  Buffer.from(y.toString(16).padStart(64, "0"), "hex").copy(buf, 32);
  return buf;
}

function serializeG2(point: string[][]): Buffer {
  const buf = Buffer.alloc(128);
  Buffer.from(BigInt(point[0][0]).toString(16).padStart(64, "0"), "hex").copy(buf, 0);
  Buffer.from(BigInt(point[0][1]).toString(16).padStart(64, "0"), "hex").copy(buf, 32);
  Buffer.from(BigInt(point[1][0]).toString(16).padStart(64, "0"), "hex").copy(buf, 64);
  Buffer.from(BigInt(point[1][1]).toString(16).padStart(64, "0"), "hex").copy(buf, 96);
  return buf;
}

function computeVkHash(vkJson: any): Buffer {
  const parts: Buffer[] = [];
  parts.push(serializeG1(vkJson.vk_alpha_1));
  parts.push(serializeG2(vkJson.vk_beta_2));
  parts.push(serializeG2(vkJson.vk_gamma_2));
  parts.push(serializeG2(vkJson.vk_delta_2));
  for (const ic of vkJson.IC) parts.push(serializeG1(ic));
  const serialized = Buffer.concat(parts);
  return Buffer.from(crypto.createHash("sha256").update(serialized).digest());
}

// =============================================================================
// Bound Params Hash (matches sdk/src/bound-params.ts)
// =============================================================================

function computeBoundParamsHash(): bigint {
  const buf = new Uint8Array(45);
  const view = new DataView(buf.buffer);
  // treeNumber = 0 (4 bytes LE)
  view.setUint32(0, 0, true);
  // hasUnshield = 0 (private transfer)
  buf[4] = 0;
  // unshieldAddress = zeros (32 bytes)
  // chainId = 103 (Solana devnet, 8 bytes LE)
  const chainIdBuf = new Uint8Array(8);
  chainIdBuf[0] = 103;
  buf.set(chainIdBuf, 37);

  const hash = sha256(buf);
  return bytes32ToBigintBE(hash) % BN254_FIELD_PRIME;
}

// =============================================================================
// EdDSA-Poseidon Signing (via circomlibjs)
// =============================================================================

let eddsaInstance: any = null;

async function initEddsa() {
  if (!eddsaInstance) {
    const { buildEddsa } = await import("circomlibjs");
    eddsaInstance = await buildEddsa();
  }
  return eddsaInstance;
}

/**
 * Generate a Baby Jubjub key pair using circomlibjs's internal derivation.
 * This matches how EdDSAPoseidonVerifier works in the circuit.
 *
 * circomlibjs internally hashes the privKey buffer (like standard EdDSA),
 * so we must use its derived public key, not our own scalar multiplication.
 */
async function generateEddsaKeyPair(seed: Uint8Array): Promise<{
  privKeyBuf: Buffer;
  pubKeyX: bigint;
  pubKeyY: bigint;
}> {
  const eddsa = await initEddsa();
  const F = eddsa.babyJub.F;

  // circomlibjs expects a 32-byte buffer as the "private key"
  const privKeyBuf = Buffer.from(seed);

  // Derive the public key using circomlibjs (matches circuit's BabyPbk)
  const pubKey = eddsa.prv2pub(privKeyBuf);
  const pubKeyX = F.toObject(pubKey[0]) as bigint;
  const pubKeyY = F.toObject(pubKey[1]) as bigint;

  return { privKeyBuf, pubKeyX, pubKeyY };
}

async function eddsaPoseidonSign(
  privKeyBuf: Buffer,
  msg: bigint,
): Promise<[bigint, bigint, bigint]> {
  const eddsa = await initEddsa();
  const F = eddsa.babyJub.F;

  // Convert message to F element
  const msgF = F.e(msg);

  // Sign
  const signature = eddsa.signPoseidon(privKeyBuf, msgF);

  // Extract R8 and S
  const R8x = F.toObject(signature.R8[0]) as bigint;
  const R8y = F.toObject(signature.R8[1]) as bigint;
  const S = signature.S as bigint;

  return [R8x, R8y, S];
}

// =============================================================================
// Proof Generation via Node.js subprocess (bun + snarkjs incompatibility)
// =============================================================================

function generateProofViaNode(
  circuitName: string,
  inputs: Record<string, any>,
): { proof: any; publicSignals: string[] } {
  const circuitsDir = path.resolve(__dirname, "../../sdk/circuits");
  const wasmPath = path.join(circuitsDir, circuitName, `${circuitName}_js`, `${circuitName}.wasm`);
  const zkeyPath = path.join(circuitsDir, circuitName, `${circuitName}.zkey`);

  if (!fs.existsSync(wasmPath)) throw new Error(`WASM not found: ${wasmPath}`);
  if (!fs.existsSync(zkeyPath)) throw new Error(`zkey not found: ${zkeyPath}`);

  const tmpDir = path.join(__dirname, "..", ".tmp");
  fs.mkdirSync(tmpDir, { recursive: true });
  const ts = Date.now();
  const tmpInput = path.join(tmpDir, `input_${ts}.json`);
  const tmpProof = path.join(tmpDir, `proof_${ts}.json`);
  const tmpPublic = path.join(tmpDir, `public_${ts}.json`);

  fs.writeFileSync(tmpInput, JSON.stringify(inputs));

  try {
    console.log(`  Generating ${circuitName} Groth16 proof via Node.js subprocess...`);
    execSync(
      `node -e "
        const snarkjs = require('snarkjs');
        const fs = require('fs');
        (async () => {
          const input = JSON.parse(fs.readFileSync('${tmpInput}', 'utf8'));
          const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            input,
            '${wasmPath}',
            '${zkeyPath}'
          );
          fs.writeFileSync('${tmpProof}', JSON.stringify(proof));
          fs.writeFileSync('${tmpPublic}', JSON.stringify(publicSignals));
          process.exit(0);
        })().catch(e => { console.error(e); process.exit(1); });
      "`,
      { timeout: 120000, stdio: "pipe" },
    );

    const proof = JSON.parse(fs.readFileSync(tmpProof, "utf8"));
    const publicSignals: string[] = JSON.parse(fs.readFileSync(tmpPublic, "utf8"));
    return { proof, publicSignals };
  } finally {
    try { fs.unlinkSync(tmpInput); } catch {}
    try { fs.unlinkSync(tmpProof); } catch {}
    try { fs.unlinkSync(tmpPublic); } catch {}
  }
}

function serializeGroth16Proof(proof: any): Uint8Array {
  const bytes = new Uint8Array(256);
  const piA = proof.pi_a;
  const piB = proof.pi_b;
  const piC = proof.pi_c;

  function writeBE(buf: Uint8Array, offset: number, value: bigint, len: number) {
    for (let i = len - 1; i >= 0; i--) {
      buf[offset + i] = Number(value & 0xffn);
      value >>= 8n;
    }
  }

  // G1 point A (64 bytes)
  writeBE(bytes, 0, BigInt(piA[0]), 32);
  writeBE(bytes, 32, BigInt(piA[1]), 32);
  // G2 point B (128 bytes): [x_imag, x_real, y_imag, y_real]
  writeBE(bytes, 64, BigInt(piB[0][1]), 32);
  writeBE(bytes, 96, BigInt(piB[0][0]), 32);
  writeBE(bytes, 128, BigInt(piB[1][1]), 32);
  writeBE(bytes, 160, BigInt(piB[1][0]), 32);
  // G1 point C (64 bytes)
  writeBE(bytes, 192, BigInt(piC[0]), 32);
  writeBE(bytes, 224, BigInt(piC[1]), 32);

  return bytes;
}

// =============================================================================
// Instruction Builders
// =============================================================================

function buildInitVkRegistryIx(
  poolState: PublicKey,
  vkRegistry: PublicKey,
  authority: PublicKey,
  nInputs: number,
  nOutputs: number,
  vkHash: Buffer,
): TransactionInstruction {
  const data = Buffer.alloc(35);
  data[0] = Instruction.INIT_VK_REGISTRY;
  data[1] = nInputs;
  data[2] = nOutputs;
  vkHash.copy(data, 3);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: false },
      { pubkey: vkRegistry, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function buildTransactIx(
  poolState: PublicKey,
  commitmentTree: PublicKey,
  vkRegistry: PublicKey,
  user: PublicKey,
  nInputs: number,
  nOutputs: number,
  proofBytes: Uint8Array,
  merkleRoot: Uint8Array,
  boundParamsHash: Uint8Array,
  nullifiers: Uint8Array[],
  commitmentsOut: Uint8Array[],
  stealthDataEntries: Array<{ ephemeralPub: Uint8Array; encryptedAmount: Uint8Array }>,
  nullifierPDAs: PublicKey[],
  stealthAnnouncementPDAs: PublicKey[],
): TransactionInstruction {
  // Data layout: disc(1) + n_inputs(1) + n_outputs(1) + proof(256) + root(32) + boundParamsHash(32)
  //              + nullifiers(32*N) + commitments(32*M) + stealth_data(40*M)
  const dataLen = 1 + 1 + 1 + 256 + 32 + 32 + nInputs * 32 + nOutputs * 32 + nOutputs * 40;
  const data = Buffer.alloc(dataLen);
  let offset = 0;

  data[offset++] = Instruction.TRANSACT;
  data[offset++] = nInputs;
  data[offset++] = nOutputs;
  Buffer.from(proofBytes).copy(data, offset); offset += 256;
  Buffer.from(merkleRoot).copy(data, offset); offset += 32;
  Buffer.from(boundParamsHash).copy(data, offset); offset += 32;

  for (const nul of nullifiers) {
    Buffer.from(nul).copy(data, offset); offset += 32;
  }
  for (const comm of commitmentsOut) {
    Buffer.from(comm).copy(data, offset); offset += 32;
  }
  for (const s of stealthDataEntries) {
    Buffer.from(s.ephemeralPub).copy(data, offset); offset += 32;
    Buffer.from(s.encryptedAmount).copy(data, offset); offset += 8;
  }

  // Accounts: pool_state, commitment_tree, vk_registry, user, system_program,
  //           ...nullifier PDAs, ...stealth announcement PDAs
  const keys = [
    { pubkey: poolState, isSigner: false, isWritable: true },
    { pubkey: commitmentTree, isSigner: false, isWritable: true },
    { pubkey: vkRegistry, isSigner: false, isWritable: false },
    { pubkey: user, isSigner: true, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
  ];

  for (const nulPDA of nullifierPDAs) {
    keys.push({ pubkey: nulPDA, isSigner: false, isWritable: true });
  }
  for (const annPDA of stealthAnnouncementPDAs) {
    keys.push({ pubkey: annPDA, isSigner: false, isWritable: true });
  }

  return new TransactionInstruction({ keys, programId: PROGRAM_ID, data });
}

// =============================================================================
// Demo stealth deposit (reuse from test-all.ts pattern)
// =============================================================================

async function addDemoStealthDeposit(
  connection: Connection,
  authority: Keypair,
  commitment: bigint,
): Promise<{ ephemeralPub: Uint8Array; leafIndex: bigint }> {
  const [poolState] = derivePoolStatePDA();
  const [commitmentTree] = deriveCommitmentTreePDA();

  // Load mint + vault from config
  const config = loadConfig();
  const zkbtcMint = new PublicKey(config.accounts.zkbtcMint);
  const poolVault = new PublicKey(config.accounts.poolVault);

  // Get tree state before
  const treeInfoBefore = await connection.getAccountInfo(commitmentTree);
  const treeBefore = treeInfoBefore ? parseCommitmentTree(Buffer.from(treeInfoBefore.data)) : null;
  const leafIndex = treeBefore?.nextIndex ?? 0n;

  // Generate random ephemeral pub + encrypted amount (just test data)
  const ephemeralPub = new Uint8Array(32);
  crypto.getRandomValues(ephemeralPub);
  const encryptedAmount = new Uint8Array(8);
  crypto.getRandomValues(encryptedAmount);
  const commitmentBytes = bigintToBytes32BE(commitment);

  const [stealthAnnouncement] = deriveStealthAnnouncementPDA(ephemeralPub);

  // Build ADD_DEMO_STEALTH instruction
  // SDK's buildAddDemoStealthData: disc(1) + ephemeralPub(32) + commitment(32) + encryptedAmount(8)
  const data = Buffer.alloc(73);
  data[0] = Instruction.ADD_DEMO_STEALTH;
  Buffer.from(ephemeralPub).copy(data, 1);
  Buffer.from(commitmentBytes).copy(data, 33);
  Buffer.from(encryptedAmount).copy(data, 65);

  const ix = new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: stealthAnnouncement, isSigner: false, isWritable: true },
      { pubkey: authority.publicKey, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: zkbtcMint, isSigner: false, isWritable: true },
      { pubkey: poolVault, isSigner: false, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });

  const tx = new Transaction().add(ix);
  await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });

  return { ephemeralPub, leafIndex };
}

// =============================================================================
// Main Test
// =============================================================================

async function main() {
  console.log("============================================================");
  console.log("JoinSplit Groth16 Proof Integration Test");
  console.log("============================================================");
  console.log(`Network: ${NETWORK}`);
  console.log(`RPC: ${RPC_URL}`);
  console.log(`Program: ${PROGRAM_ID.toBase58()}`);

  const connection = new Connection(RPC_URL, "confirmed");

  // Load authority keypair from KEYPAIR env or default path
  const keypairPath = process.env.KEYPAIR || `${process.env.HOME}/.config/solana/id.json`;
  const authority = Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(keypairPath, "utf-8"))),
  );

  // Fund
  const balance = await connection.getBalance(authority.publicKey);
  if (balance < LAMPORTS_PER_SOL) {
    if (NETWORK === "devnet") {
      console.log("  Requesting devnet airdrop...");
    }
    const sig = await connection.requestAirdrop(
      authority.publicKey,
      NETWORK === "devnet" ? 2 * LAMPORTS_PER_SOL : 10 * LAMPORTS_PER_SOL,
    );
    await connection.confirmTransaction(sig);
  }

  // Initialize Poseidon
  console.log("\n1. Initializing Poseidon...");
  await initPoseidon();
  computeZeroHashes();
  console.log("   Poseidon initialized, zero hashes computed");

  // =========================================================================
  // Step 1: Register VK hash for joinsplit_1x1
  // =========================================================================
  console.log("\n2. Registering VK hash for joinsplit_1x1...");

  const vkJsonPath = path.resolve(__dirname, "../../circuits/build/joinsplit_1x1/joinsplit_1x1.vkey.json");
  const vkJson = JSON.parse(fs.readFileSync(vkJsonPath, "utf-8"));
  const vkHash = computeVkHash(vkJson);

  const [poolState] = derivePoolStatePDA();
  const [commitmentTree] = deriveCommitmentTreePDA();
  const [vkRegistry] = deriveVkRegistryPDA(1, 1);

  // Check if already registered
  const existingVk = await connection.getAccountInfo(vkRegistry);
  if (existingVk && existingVk.data[0] === 0x14) {
    console.log("   VK registry already exists, skipping");
  } else {
    const ix = buildInitVkRegistryIx(poolState, vkRegistry, authority.publicKey, 1, 1, vkHash);
    const tx = new Transaction().add(ix);
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
    console.log(`   VK registered: ${sig.slice(0, 16)}...`);
  }

  // =========================================================================
  // Step 2: Generate keys and create a deposit
  // =========================================================================
  console.log("\n3. Generating keys and creating deposit...");

  // Generate Baby Jubjub spending key using circomlibjs (matches circuit's EdDSA verifier)
  const spendingSeed = new Uint8Array(32);
  crypto.getRandomValues(spendingSeed);
  const { privKeyBuf, pubKeyX, pubKeyY } = await generateEddsaKeyPair(spendingSeed);
  console.log(`   Spending pub: (${pubKeyX.toString(16).slice(0, 16)}..., ${pubKeyY.toString(16).slice(0, 16)}...)`);

  // Derive nullifying key: SHA256("nullify" || seed) mod BN254
  const nullifyingKeyInput = new Uint8Array(39);
  nullifyingKeyInput.set(new TextEncoder().encode("nullify"), 0);
  nullifyingKeyInput.set(spendingSeed, 7);
  const nullifyingKey = bytes32ToBigintBE(sha256(nullifyingKeyInput)) % BN254_FIELD_PRIME;

  // Compute MPK = Poseidon(pkX, pkY, nullifyingKey)
  const mpk = poseidonHash([pubKeyX, pubKeyY, nullifyingKey]);
  console.log(`   MPK: ${mpk.toString(16).slice(0, 16)}...`);

  // Create input note
  const inputRandom = randomFieldElement();
  const inputAmount = 10_000n; // 10,000 sats
  const npkIn = poseidonHash([mpk, inputRandom]);
  const commitmentIn = poseidonHash([npkIn, ZKBTC_TOKEN_ID, inputAmount]);
  console.log(`   Input commitment: ${commitmentIn.toString(16).slice(0, 16)}...`);

  // Add deposit to on-chain tree
  const { leafIndex } = await addDemoStealthDeposit(connection, authority, commitmentIn);
  console.log(`   Deposit added at leaf index: ${leafIndex}`);

  // =========================================================================
  // Step 3: Read on-chain tree frontier and compute Merkle proof
  // =========================================================================
  console.log("\n4. Reading on-chain tree state...");

  // Read on-chain tree AFTER our deposit was inserted
  const treeInfo = await connection.getAccountInfo(commitmentTree);
  if (!treeInfo) throw new Error("Commitment tree not found");
  const treeData = parseCommitmentTree(Buffer.from(treeInfo.data));
  if (!treeData) throw new Error("Failed to parse commitment tree");

  const nextIndex = Number(treeData.nextIndex);
  const ourLeafIndex = Number(leafIndex);
  console.log(`   On-chain tree has ${nextIndex} leaves, our leaf at index: ${ourLeafIndex}`);

  // Extract frontier from on-chain account (16 x 32-byte hashes starting at offset 48)
  const frontier: bigint[] = [];
  for (let i = 0; i < TREE_DEPTH; i++) {
    const frontierBytes = treeData.frontier.subarray(i * 32, (i + 1) * 32);
    frontier.push(bytes32ToBigintBE(new Uint8Array(frontierBytes)));
  }
  console.log(`   Frontier[0] (last left leaf): ${frontier[0].toString(16).slice(0, 16)}...`);

  // Compute Merkle proof using frontier (works for the LAST inserted leaf)
  const merkleProof = getMerkleProofFromFrontier(ourLeafIndex, frontier);

  // Use on-chain current root
  const merkleRoot = bytes32ToBigintBE(new Uint8Array(treeData.currentRoot));
  console.log(`   On-chain root: ${merkleRoot.toString(16).slice(0, 20)}...`);

  // Verify: recompute root from our leaf + proof to confirm correctness
  let verifyHash = commitmentIn;
  for (let level = 0; level < TREE_DEPTH; level++) {
    if (merkleProof.indices[level] === 0) {
      verifyHash = poseidonHash([verifyHash, merkleProof.siblings[level]]);
    } else {
      verifyHash = poseidonHash([merkleProof.siblings[level], verifyHash]);
    }
  }
  console.log(`   Recomputed root: ${verifyHash.toString(16).slice(0, 20)}...`);
  if (verifyHash !== merkleRoot) {
    console.error("   ERROR: Merkle proof verification failed locally!");
    console.error(`   Expected: ${merkleRoot.toString(16)}`);
    console.error(`   Got:      ${verifyHash.toString(16)}`);
    process.exit(1);
  }
  console.log("   Merkle proof verified locally");

  // =========================================================================
  // Step 4: Compute circuit inputs
  // =========================================================================
  console.log("\n5. Computing circuit inputs...");

  // Output note: same amount, new random (1-in-1-out private refresh)
  const outputRandom = randomFieldElement();
  const npkOut = poseidonHash([mpk, outputRandom]);
  const commitmentOut = poseidonHash([npkOut, ZKBTC_TOKEN_ID, inputAmount]);

  // Compute nullifier = Poseidon(nullifyingKey, leafIndex)
  const nullifier = poseidonHash([nullifyingKey, BigInt(ourLeafIndex)]);
  console.log(`   Nullifier: ${nullifier.toString(16).slice(0, 16)}...`);
  console.log(`   Output commitment: ${commitmentOut.toString(16).slice(0, 16)}...`);

  // Compute bound params hash
  const boundParamsHash = computeBoundParamsHash();
  console.log(`   Bound params hash: ${boundParamsHash.toString(16).slice(0, 16)}...`);

  // Compute message hash for signature
  // msgHash = Poseidon(merkleRoot, boundParamsHash, nullifier, commitmentOut)
  const msgHash = poseidonHash([merkleRoot, boundParamsHash, nullifier, commitmentOut]);

  // Sign with EdDSA-Poseidon
  console.log("   Signing with EdDSA-Poseidon...");
  const [sigR8x, sigR8y, sigS] = await eddsaPoseidonSign(privKeyBuf, msgHash);
  console.log(`   Signature R8x: ${sigR8x.toString(16).slice(0, 16)}...`);

  // =========================================================================
  // Step 5: Generate real Groth16 proof
  // =========================================================================
  console.log("\n6. Generating Groth16 proof...");

  const circuitInputs = {
    merkleRoot: merkleRoot.toString(),
    boundParamsHash: boundParamsHash.toString(),
    nullifiers: [nullifier.toString()],
    commitmentsOut: [commitmentOut.toString()],
    token: ZKBTC_TOKEN_ID.toString(),
    publicKey: [pubKeyX.toString(), pubKeyY.toString()],
    signature: [sigR8x.toString(), sigR8y.toString(), sigS.toString()],
    nullifyingKey: nullifyingKey.toString(),
    randomIn: [inputRandom.toString()],
    valueIn: [inputAmount.toString()],
    leavesIndices: [ourLeafIndex.toString()],
    pathElements: [merkleProof.siblings.map(s => s.toString())],
    pathIndices: [merkleProof.indices],
    npkOut: [npkOut.toString()],
    valueOut: [inputAmount.toString()],
  };

  const { proof, publicSignals } = generateProofViaNode("joinsplit_1x1", circuitInputs);
  const proofBytes = serializeGroth16Proof(proof);
  console.log(`   Proof generated! Size: ${proofBytes.length} bytes`);
  console.log(`   Public signals: [${publicSignals.map(s => s.slice(0, 10) + "...").join(", ")}]`);

  // =========================================================================
  // Step 6: Submit transact instruction
  // =========================================================================
  console.log("\n7. Submitting transact instruction...");

  const nullifierBytes = bigintToBytes32BE(nullifier);
  const commitmentOutBytes = bigintToBytes32BE(commitmentOut);
  const merkleRootBytes = bigintToBytes32BE(merkleRoot);
  const boundParamsHashBytes = bigintToBytes32BE(boundParamsHash);

  // Derive PDAs
  const [nullifierPDA] = deriveNullifierPDA(nullifierBytes);
  console.log(`   Nullifier PDA: ${nullifierPDA.toBase58().slice(0, 20)}...`);

  // Stealth announcement: use random ephemeral pub for output
  const outputEphemeralPub = new Uint8Array(32);
  crypto.getRandomValues(outputEphemeralPub);
  const outputEncryptedAmount = new Uint8Array(8);
  // Store amount as LE (just for test)
  let amt = inputAmount;
  for (let i = 0; i < 8; i++) {
    outputEncryptedAmount[i] = Number(amt & 0xffn);
    amt >>= 8n;
  }

  const [stealthAnnPDA] = deriveStealthAnnouncementPDA(outputEphemeralPub);
  console.log(`   Stealth ann PDA: ${stealthAnnPDA.toBase58().slice(0, 20)}...`);

  const transactIx = buildTransactIx(
    poolState,
    commitmentTree,
    vkRegistry,
    authority.publicKey,
    1, // nInputs
    1, // nOutputs
    proofBytes,
    merkleRootBytes,
    boundParamsHashBytes,
    [nullifierBytes],
    [commitmentOutBytes],
    [{ ephemeralPub: outputEphemeralPub, encryptedAmount: outputEncryptedAmount }],
    [nullifierPDA],
    [stealthAnnPDA],
  );

  try {
    const tx = new Transaction().add(transactIx);
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
    console.log(`   Transaction confirmed: ${sig}`);
  } catch (err: any) {
    console.error(`   Transaction FAILED: ${err.message.slice(0, 300)}`);
    // Try to extract program logs
    if (err.logs) {
      console.error("   Program logs:");
      for (const log of err.logs) {
        console.error(`     ${log}`);
      }
    }
    process.exit(1);
  }

  // =========================================================================
  // Step 7: Verify on-chain state
  // =========================================================================
  console.log("\n8. Verifying on-chain state...");

  // Check nullifier PDA exists
  const nullifierInfo = await connection.getAccountInfo(nullifierPDA);
  if (!nullifierInfo) {
    console.error("   FAIL: Nullifier PDA not found");
    process.exit(1);
  }
  if (nullifierInfo.data[0] !== 0x03) {
    console.error(`   FAIL: Nullifier discriminator mismatch: ${nullifierInfo.data[0]}`);
    process.exit(1);
  }
  console.log("   Nullifier PDA exists with correct discriminator (0x03)");

  // Check nullifier operation type = PrivateTransfer (2)
  if (nullifierInfo.data[1] !== 2) {
    console.error(`   FAIL: Nullifier op type: expected 2 (PrivateTransfer), got ${nullifierInfo.data[1]}`);
    process.exit(1);
  }
  console.log("   Nullifier operation type: PrivateTransfer (2)");

  // Check commitment tree index increased
  const treeInfoAfter = await connection.getAccountInfo(commitmentTree);
  const treeAfter = treeInfoAfter ? parseCommitmentTree(Buffer.from(treeInfoAfter.data)) : null;
  if (!treeAfter) {
    console.error("   FAIL: Commitment tree not found after transact");
    process.exit(1);
  }
  const expectedNextIndex = BigInt(nextIndex) + 1n;
  if (treeAfter.nextIndex !== expectedNextIndex) {
    console.error(`   FAIL: Tree index: expected ${expectedNextIndex}, got ${treeAfter.nextIndex}`);
    process.exit(1);
  }
  console.log(`   Commitment tree next_index: ${treeAfter.nextIndex} (correct)`);

  // Check stealth announcement PDA
  const stealthInfo = await connection.getAccountInfo(stealthAnnPDA);
  if (!stealthInfo) {
    console.error("   FAIL: Stealth announcement PDA not found");
    process.exit(1);
  }
  if (stealthInfo.data[0] !== 0x08) {
    console.error(`   FAIL: Stealth announcement discriminator: ${stealthInfo.data[0]}`);
    process.exit(1);
  }
  console.log("   Stealth announcement PDA exists with correct discriminator (0x08)");

  // =========================================================================
  // Step 8: Error test — tampered proof should fail
  // =========================================================================
  console.log("\n9. Error test: tampered proof should fail...");

  const tamperedProof = new Uint8Array(proofBytes);
  tamperedProof[0] ^= 0xff; // Flip first byte

  // New random output for error test
  const errorOutputRandom = randomFieldElement();
  const errorNpkOut = poseidonHash([mpk, errorOutputRandom]);
  const errorCommitmentOut = poseidonHash([errorNpkOut, ZKBTC_TOKEN_ID, inputAmount]);
  const errorNullifier = poseidonHash([nullifyingKey, BigInt(ourLeafIndex + 1000)]); // Different nullifier
  const errorEphemeralPub = new Uint8Array(32);
  crypto.getRandomValues(errorEphemeralPub);

  const [errorNullifierPDA] = deriveNullifierPDA(bigintToBytes32BE(errorNullifier));
  const [errorStealthPDA] = deriveStealthAnnouncementPDA(errorEphemeralPub);

  const errorIx = buildTransactIx(
    poolState,
    commitmentTree,
    vkRegistry,
    authority.publicKey,
    1, 1,
    tamperedProof,
    merkleRootBytes,
    boundParamsHashBytes,
    [bigintToBytes32BE(errorNullifier)],
    [bigintToBytes32BE(errorCommitmentOut)],
    [{ ephemeralPub: errorEphemeralPub, encryptedAmount: outputEncryptedAmount }],
    [errorNullifierPDA],
    [errorStealthPDA],
  );

  try {
    const tx = new Transaction().add(errorIx);
    await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
    console.error("   FAIL: Tampered proof should have been rejected!");
    process.exit(1);
  } catch {
    console.log("   Tampered proof correctly rejected");
  }

  // =========================================================================
  // Summary
  // =========================================================================
  console.log("\n============================================================");
  console.log("ALL TESTS PASSED");
  console.log("============================================================");
  console.log("- VK registry registered for joinsplit_1x1");
  console.log("- Real Groth16 proof generated and verified on-chain");
  console.log("- Nullifier PDA created with correct data");
  console.log("- Commitment tree updated with new output");
  console.log("- Stealth announcement PDA created");
  console.log("- Tampered proof correctly rejected");
  console.log("============================================================");

  process.exit(0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
