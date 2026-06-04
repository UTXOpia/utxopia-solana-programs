#!/usr/bin/env bun
/**
 * E2E User Flow Test — 4 Parts (Bitcoin regtest)
 *
 * Exercises the 4 main UTXOpia user flows, each building on the previous:
 *   Part 1: Deposit      — COMPLETE_DEPOSIT (disc=1) with real BTC regtest + SPV
 *   Part 2: Private Send  — JoinSplit 1x1 TRANSACT (disc=14)
 *   Part 3: Split         — JoinSplit 1x2 TRANSACT (disc=14)
 *   Part 4: Withdraw      — REQUEST_REDEMPTION (disc=5)
 *
 * Data flow:
 *   Part 1: BTC sweep tx -> SPV verify -> [commitment0: 25,000 sats @ leaf 0]
 *   Part 2: [commitment0] -> nullifier0 -> [commitment1: 25,000 sats @ leaf 1]
 *   Part 3: [commitment1] -> nullifier1 -> [commitment2: 15,000 sats @ leaf 2]
 *                                        -> [commitment3: 10,000 sats @ leaf 3]
 *   Part 4: [commitment2] -> nullifier2 -> RedemptionRequest(15,000 sats -> tb1q...)
 *
 * Prerequisites:
 *   - Run setup first: bun run setup:localnet
 *   - Or manually: solana-test-validator + Docker regtest + bun run deploy:localnet
 *
 * Run:
 *   bun run test:flows
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
import { TOKEN_2022_PROGRAM_ID } from "@solana/spl-token";
import { sha256 } from "@noble/hashes/sha2.js";
import { buildPoseidon } from "circomlibjs";
import * as fs from "fs";
import * as path from "path";
import * as crypto from "crypto";
import { fileURLToPath } from "url";
import { execSync } from "child_process";
import {
  createOpReturnTx,
  mineBlocks,
  getNewAddress,
  waitForTxIndexed,
  fetchBlockHeader,
  fetchMerkleProof,
  fetchRawTx,
  fetchTxStatus,
  serializeMerkleProof,
  stripWitnessData,
} from "./regtest-helpers.js";
import {
  Seeds,
  TREE_DEPTH,
  derivePoolStatePDA,
  deriveCommitmentTreePDA,
  deriveVkRegistryPDA,
  deriveNullifierPDA,
  deriveStealthAnnouncementPDA,
  deriveRedemptionPDA,
  deriveDepositStealthPDA,
  deriveLightClientPDA,
  parseCommitmentTree,
  parsePoolState,
  parseRedemptionRequest,
  createTxBufferAccount,
  buildRequestRedemptionIx,
  fetchAndSubmitHeaders,
  loadAuthorityKeypair,
} from "./test-helpers.js";

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

let PROGRAM_ID = loadProgramId();

// Constants
const ZKBTC_TOKEN_ID = 0x7a627463n; // "zkbtc" as u32
const BN254_FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

// Instruction discriminators
const Instruction = {
  COMPLETE_DEPOSIT: 1,
  INIT_VK_REGISTRY: 11,
  ADD_DEMO_STEALTH: 13,
  TRANSACT: 14,
} as const;

// =============================================================================
// Poseidon Instance
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

function amountToLE8(amount: bigint): Uint8Array {
  const buf = new Uint8Array(8);
  let v = amount;
  for (let i = 0; i < 8; i++) {
    buf[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return buf;
}

function randomEphemeralPub(): Uint8Array {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}

// =============================================================================
// Merkle Tree
// =============================================================================

const ZERO_HASHES: bigint[] = [0n];

function computeZeroHashes() {
  for (let i = 1; i <= TREE_DEPTH; i++) {
    ZERO_HASHES[i] = poseidonHash([ZERO_HASHES[i - 1], ZERO_HASHES[i - 1]]);
  }
}

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
      siblings.push(ZERO_HASHES[level]);
    } else {
      siblings.push(frontier[level]);
    }
    idx >>= 1;
  }
  return { siblings, indices };
}

function verifyMerkleProof(leaf: bigint, proof: { siblings: bigint[]; indices: number[] }, expectedRoot: bigint): boolean {
  let hash = leaf;
  for (let level = 0; level < TREE_DEPTH; level++) {
    if (proof.indices[level] === 0) {
      hash = poseidonHash([hash, proof.siblings[level]]);
    } else {
      hash = poseidonHash([proof.siblings[level], hash]);
    }
  }
  return hash === expectedRoot;
}

// =============================================================================
// VK Hash Computation
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
// Bound Params Hash
// =============================================================================

function computeBoundParamsHash(): bigint {
  const buf = new Uint8Array(45);
  const view = new DataView(buf.buffer);
  view.setUint32(0, 0, true); // treeNumber = 0
  buf[4] = 0; // hasUnshield = 0
  const chainIdBuf = new Uint8Array(8);
  chainIdBuf[0] = 103; // Solana devnet
  buf.set(chainIdBuf, 37);
  const hash = sha256(buf);
  return bytes32ToBigintBE(hash) % BN254_FIELD_PRIME;
}

// =============================================================================
// EdDSA-Poseidon Signing
// =============================================================================

let eddsaInstance: any = null;

async function initEddsa() {
  if (!eddsaInstance) {
    const { buildEddsa } = await import("circomlibjs");
    eddsaInstance = await buildEddsa();
  }
  return eddsaInstance;
}

async function generateEddsaKeyPair(seed: Uint8Array): Promise<{
  privKeyBuf: Buffer;
  pubKeyX: bigint;
  pubKeyY: bigint;
}> {
  const eddsa = await initEddsa();
  const F = eddsa.babyJub.F;
  const privKeyBuf = Buffer.from(seed);
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
  const msgF = F.e(msg);
  const signature = eddsa.signPoseidon(privKeyBuf, msgF);
  const R8x = F.toObject(signature.R8[0]) as bigint;
  const R8y = F.toObject(signature.R8[1]) as bigint;
  const S = signature.S as bigint;
  return [R8x, R8y, S];
}

// =============================================================================
// Proof Generation via Node.js subprocess
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

  writeBE(bytes, 0, BigInt(piA[0]), 32);
  writeBE(bytes, 32, BigInt(piA[1]), 32);
  writeBE(bytes, 64, BigInt(piB[0][1]), 32);
  writeBE(bytes, 96, BigInt(piB[0][0]), 32);
  writeBE(bytes, 128, BigInt(piB[1][1]), 32);
  writeBE(bytes, 160, BigInt(piB[1][0]), 32);
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

/**
 * Build complete_deposit instruction (disc=1)
 *
 * Data layout (116 bytes + merkle proof):
 *   [0-31]   txid              (32 bytes)
 *   [32-39]  block_height      (8 bytes LE)
 *   [40-47]  amount_sats       (8 bytes LE)
 *   [48-51]  tx_size           (4 bytes LE)
 *   [52-83]  ephemeral_pub     (32 bytes)
 *   [84-115] npk               (32 bytes)
 *   [116+]   merkle_proof      (variable)
 *
 * Merkle proof for single-tx block (41 bytes):
 *   txid(32) + path_bits(4)=0 + path_len(1)=0 + tx_index(4)=0
 *
 * Accounts (11):
 *   0. pool_state (writable)
 *   1. light_client (read)
 *   2. block_header (read)
 *   3. commitment_tree (writable)
 *   4. deposit_record (writable, PDA seeded by ["deposit", txid])
 *   5. tx_buffer (read, ChadBuffer)
 *   6. authority (signer, writable)
 *   7. system_program
 *   8. zkbtc_mint (writable)
 *   9. pool_vault (writable)
 *  10. token_program (Token-2022)
 */
function buildVerifyStealthDepositIx(
  poolState: PublicKey,
  lightClient: PublicKey,
  blockHeader: PublicKey,
  commitmentTree: PublicKey,
  depositRecord: PublicKey,
  txBuffer: PublicKey,
  authority: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
  params: {
    txid: Uint8Array;
    blockHeight: bigint;
    amountSats: bigint;
    txSize: number;
    ephemeralPub: Uint8Array;
    npk: Uint8Array;
    merkleProofData: Buffer; // Pre-serialized merkle proof (variable length)
  },
): TransactionInstruction {
  const merkleProof = params.merkleProofData;

  const dataLen = 1 + 116 + merkleProof.length;
  const data = Buffer.alloc(dataLen);
  let off = 0;

  data[off++] = Instruction.COMPLETE_DEPOSIT;

  // txid (32)
  Buffer.from(params.txid).copy(data, off); off += 32;
  // block_height (8 LE)
  data.writeBigUInt64LE(params.blockHeight, off); off += 8;
  // amount_sats (8 LE)
  data.writeBigUInt64LE(params.amountSats, off); off += 8;
  // tx_size (4 LE)
  data.writeUInt32LE(params.txSize, off); off += 4;
  // ephemeral_pub (32)
  Buffer.from(params.ephemeralPub).copy(data, off); off += 32;
  // npk (32)
  Buffer.from(params.npk).copy(data, off); off += 32;

  // Merkle proof (variable length)
  merkleProof.copy(data, off);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: lightClient, isSigner: false, isWritable: false },
      { pubkey: blockHeader, isSigner: false, isWritable: false },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: depositRecord, isSigner: false, isWritable: true },
      { pubkey: txBuffer, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: zkbtcMint, isSigner: false, isWritable: true },
      { pubkey: poolVault, isSigner: false, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
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
// Helpers
// =============================================================================

function readOnChainTree(connection: Connection, commitmentTreeKey: PublicKey) {
  return connection.getAccountInfo(commitmentTreeKey).then((info) => {
    if (!info) throw new Error("Commitment tree not found");
    return parseCommitmentTree(Buffer.from(info.data))!;
  });
}

function extractFrontier(treeData: ReturnType<typeof parseCommitmentTree>): bigint[] {
  const frontier: bigint[] = [];
  for (let i = 0; i < TREE_DEPTH; i++) {
    const frontierBytes = treeData!.frontier.subarray(i * 32, (i + 1) * 32);
    frontier.push(bytes32ToBigintBE(new Uint8Array(frontierBytes)));
  }
  return frontier;
}

// =============================================================================
// Main Test
// =============================================================================

async function main() {
  const ESPLORA_URL = process.env.BITCOIN_API_URL || "http://localhost:3000/regtest/api";

  console.log("============================================================");
  console.log(`UTXOpia E2E User Flow Test — 4 Parts (${NETWORK})`);
  console.log("============================================================");
  console.log(`Network: ${NETWORK}`);
  console.log(`RPC: ${RPC_URL}`);
  if (NETWORK === "devnet") {
    console.log("Bitcoin API: https://mempool.space/testnet/api");
  } else {
    console.log(`Esplora: ${ESPLORA_URL}`);
  }

  PROGRAM_ID = loadProgramId();
  console.log(`Program: ${PROGRAM_ID.toBase58()}`);

  const connection = new Connection(RPC_URL, "confirmed");

  const authority = loadAuthorityKeypair();

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

  // Initialize Poseidon + EdDSA
  console.log("\nInitializing Poseidon + EdDSA...");
  await initPoseidon();
  computeZeroHashes();
  await initEddsa();
  console.log("  Done");

  // Derive PDAs
  const [poolState] = derivePoolStatePDA(PROGRAM_ID);
  const [commitmentTree] = deriveCommitmentTreePDA(PROGRAM_ID);

  // Load config for mint/vault/programs
  const networkConfig = loadConfig();
  const zkbtcMint = new PublicKey(networkConfig.accounts.zkbtcMint);
  const poolVault = new PublicKey(networkConfig.accounts.poolVault);
  const BTC_LIGHT_CLIENT_ID = new PublicKey(networkConfig.programs.btcLightClient);
  const CHADBUFFER_ID = new PublicKey(networkConfig.programs.chadbuffer);

  // =========================================================================
  // Setup: Generate keys (shared across all parts)
  // =========================================================================
  console.log("\nGenerating Baby Jubjub spending key...");
  const spendingSeed = new Uint8Array(32);
  if (NETWORK === "devnet" && process.env.TESTNET_SPENDING_SEED) {
    const seedBuf = Buffer.from(process.env.TESTNET_SPENDING_SEED, "hex");
    if (seedBuf.length !== 32) throw new Error("TESTNET_SPENDING_SEED must be 32 bytes (64 hex chars)");
    spendingSeed.set(seedBuf);
    console.log("  Using deterministic spending seed from TESTNET_SPENDING_SEED");
  } else {
    crypto.getRandomValues(spendingSeed);
  }
  const { privKeyBuf, pubKeyX, pubKeyY } = await generateEddsaKeyPair(spendingSeed);

  // Derive nullifying key
  const nullifyingKeyInput = new Uint8Array(39);
  nullifyingKeyInput.set(new TextEncoder().encode("nullify"), 0);
  nullifyingKeyInput.set(spendingSeed, 7);
  const nullifyingKey = bytes32ToBigintBE(sha256(nullifyingKeyInput)) % BN254_FIELD_PRIME;

  // Compute MPK = Poseidon(pkX, pkY, nullifyingKey)
  const mpk = poseidonHash([pubKeyX, pubKeyY, nullifyingKey]);
  console.log(`  MPK: ${mpk.toString(16).slice(0, 16)}...`);

  // =========================================================================
  // Setup: Register VK hashes for joinsplit_1x1 and joinsplit_1x2
  // =========================================================================
  console.log("\nRegistering VK hashes...");

  for (const [nIn, nOut] of [[1, 1], [1, 2]] as [number, number][]) {
    const circuitName = `joinsplit_${nIn}x${nOut}`;
    const vkJsonPath = path.resolve(__dirname, `../../circuits/build/${circuitName}/${circuitName}.vkey.json`);
    const vkJson = JSON.parse(fs.readFileSync(vkJsonPath, "utf-8"));
    const vkHash = computeVkHash(vkJson);
    const [vkRegistry] = deriveVkRegistryPDA(PROGRAM_ID,nIn, nOut);

    const existing = await connection.getAccountInfo(vkRegistry);
    if (existing && existing.data[0] === 0x14) {
      console.log(`  ${circuitName} VK already registered`);
    } else {
      const ix = buildInitVkRegistryIx(poolState, vkRegistry, authority.publicKey, nIn, nOut, vkHash);
      const tx = new Transaction().add(ix);
      await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
      console.log(`  ${circuitName} VK registered`);
    }
  }

  // =========================================================================
  // PART 1: Deposit
  // =========================================================================

  // Create note keys
  let random0: bigint;
  if (NETWORK === "devnet" && process.env.TESTNET_RANDOM) {
    random0 = BigInt("0x" + process.env.TESTNET_RANDOM) % BN254_FIELD_PRIME;
    console.log("  Using deterministic random from TESTNET_RANDOM");
  } else {
    random0 = randomFieldElement();
  }
  const amount0 = NETWORK === "devnet" && process.env.TESTNET_AMOUNT
    ? BigInt(process.env.TESTNET_AMOUNT)
    : 25_000n;
  const npk0 = poseidonHash([mpk, random0]);
  const npk0Bytes = bigintToBytes32BE(npk0);
  // Commitment will be computed ON-CHAIN: Poseidon(npk, ZKBTC_TOKEN_ID, amount)
  // But we compute it locally for later verification in Parts 2-4
  const commitment0 = poseidonHash([npk0, ZKBTC_TOKEN_ID, amount0]);

  // Read tree state before deposit
  const treeBefore1 = await readOnChainTree(connection, commitmentTree);
  const leafIndex0 = Number(treeBefore1.nextIndex);

  if (NETWORK === "devnet") {
    // ---- Devnet: COMPLETE_DEPOSIT with real SPV ----
    // Two modes:
    //   A) TESTNET_TXID set → use pre-existing testnet tx from mempool.space
    //   B) USE_REGTEST=1   → create tx on local regtest, submit to devnet Solana
    const useRegtest = process.env.USE_REGTEST === "1";
    const btcSource = useRegtest ? "regtest" : "testnet";
    console.log("\n" + "=".repeat(60));
    console.log(`PART 1: DEPOSIT — COMPLETE_DEPOSIT (devnet+${btcSource} SPV)`);
    console.log("=".repeat(60));

    let txid: string;
    let ephPub0: Uint8Array;
    let btcApiUrl: string;

    if (useRegtest) {
      // Mode B: Create tx on local regtest
      btcApiUrl = process.env.BITCOIN_API_URL || "http://localhost:3000/regtest/api";
      console.log(`  Bitcoin API: ${btcApiUrl}`);

      ephPub0 = randomEphemeralPub();
      const payloadHex = Buffer.from(ephPub0).toString("hex") + Buffer.from(npk0Bytes).toString("hex");
      const poolAddr = getNewAddress("bech32");
      txid = createOpReturnTx(poolAddr, Number(amount0), payloadHex);
      console.log(`  Txid: ${txid}`);

      console.log("  Mining 1 block...");
      mineBlocks(1);
      await waitForTxIndexed(txid, btcApiUrl);
    } else {
      // Mode A: Pre-existing testnet tx
      const testnetTxid = process.env.TESTNET_TXID;
      if (!testnetTxid) throw new Error("TESTNET_TXID env var required for devnet E2E (or set USE_REGTEST=1)");
      if (!process.env.TESTNET_AMOUNT) throw new Error("TESTNET_AMOUNT env var required (sats)");
      if (!process.env.TESTNET_SPENDING_SEED) throw new Error("TESTNET_SPENDING_SEED env var required (64-char hex)");
      if (!process.env.TESTNET_RANDOM) throw new Error("TESTNET_RANDOM env var required (64-char hex)");
      const testnetEphPub = process.env.TESTNET_EPH_PUB;
      if (!testnetEphPub) throw new Error("TESTNET_EPH_PUB env var required (64-char hex)");
      ephPub0 = Buffer.from(testnetEphPub, "hex");
      if (ephPub0.length !== 32) throw new Error("TESTNET_EPH_PUB must be 32 bytes (64 hex chars)");

      txid = testnetTxid;
      btcApiUrl = "https://mempool.space/testnet/api";
    }

    console.log(`  Amount: ${amount0} sats`);
    console.log(`  npk0: ${npk0.toString(16).slice(0, 16)}...`);
    console.log(`  Expected commitment0: ${commitment0.toString(16).slice(0, 16)}...`);
    console.log(`  Tree next_index before: ${leafIndex0}`);

    // 1. Fetch tx status (must be confirmed)
    console.log(`  Fetching tx status from ${btcApiUrl}...`);
    const txStatus = await fetchTxStatus(txid, btcApiUrl);
    if (!txStatus.confirmed || !txStatus.block_hash || !txStatus.block_height) {
      throw new Error(`Tx ${txid} not confirmed`);
    }
    const blockHash = txStatus.block_hash;
    const blockHeight = txStatus.block_height;
    console.log(`  Confirmed at height ${blockHeight}, block ${blockHash.slice(0, 16)}...`);

    // 2. Fetch block header, raw tx, merkle proof
    const rawHeader = await fetchBlockHeader(blockHash, btcApiUrl);
    console.log(`  Block header: ${rawHeader.length} bytes`);

    const rawTxBuf = await fetchRawTx(txid, btcApiUrl);
    const strippedTx = stripWitnessData(rawTxBuf);
    const rawSweepTx = new Uint8Array(strippedTx);
    console.log(`  Raw tx: ${rawTxBuf.length} bytes (witness-stripped: ${strippedTx.length} bytes)`);

    const txidBytes = Buffer.from(txid, "hex");
    txidBytes.reverse(); // internal byte order
    const txHash = new Uint8Array(txidBytes);

    const esploraProof = await fetchMerkleProof(txid, btcApiUrl);
    console.log(`  Merkle proof: ${esploraProof.merkle.length} hashes, pos=${esploraProof.pos}`);
    const merkleProofData = serializeMerkleProof(txid, esploraProof);

    // 3. Handle block header sync — extend_blockchain (batch of 2+ headers)
    const [lightClient] = deriveLightClientPDA(BTC_LIGHT_CLIENT_ID);
    const newBlockHeight = BigInt(blockHeight);

    console.log(`  Submitting headers up to height ${newBlockHeight}...`);
    const blockHeaderPda = await fetchAndSubmitHeaders(
      connection, authority, newBlockHeight,
      new Uint8Array(rawHeader), BTC_LIGHT_CLIENT_ID,
      btcApiUrl, fetchBlockHeader,
    );
    console.log(`  Block headers submitted`);

    // 4. Upload stripped tx to ChadBuffer
    console.log("  Uploading sweep tx to ChadBuffer...");
    const bufferKeypair = await createTxBufferAccount(connection, authority, rawSweepTx, CHADBUFFER_ID);
    console.log(`  ChadBuffer: ${bufferKeypair.publicKey.toBase58().slice(0, 20)}...`);

    // 5. Call complete_deposit
    const [depositRecord] = deriveDepositStealthPDA(PROGRAM_ID, txHash);
    console.log(`  Deposit record PDA: ${depositRecord.toBase58().slice(0, 20)}...`);

    const verifyDepositIx = buildVerifyStealthDepositIx(
      poolState, lightClient, blockHeaderPda, commitmentTree,
      depositRecord, bufferKeypair.publicKey, authority.publicKey,
      zkbtcMint, poolVault,
      {
        txid: txHash,
        blockHeight: newBlockHeight,
        amountSats: amount0,
        txSize: rawSweepTx.length,
        ephemeralPub: ephPub0,
        npk: npk0Bytes,
        merkleProofData,
      },
    );

    try {
      const tx = new Transaction().add(verifyDepositIx);
      const sig = await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
      console.log(`  Verify deposit tx: ${sig.slice(0, 20)}...`);
    } catch (err: any) {
      console.error(`  FAIL: ${err.message?.slice(0, 300)}`);
      if (err.logs) for (const log of err.logs) console.error(`    ${log}`);
      process.exit(1);
    }

    // Verify tree updated
    const treeAfter1 = await readOnChainTree(connection, commitmentTree);
    if (Number(treeAfter1.nextIndex) !== leafIndex0 + 1) {
      console.error(`  FAIL: next_index expected ${leafIndex0 + 1}, got ${treeAfter1.nextIndex}`);
      process.exit(1);
    }

    const depositRecordInfo = await connection.getAccountInfo(depositRecord);
    if (!depositRecordInfo || depositRecordInfo.data[0] !== 0x02) {
      console.error("  FAIL: Deposit record PDA not created");
      process.exit(1);
    }
    const recordLeafIndex = Buffer.from(depositRecordInfo.data).readBigUInt64LE(88);
    console.log(`  Deposit record: leaf_index=${recordLeafIndex}`);
    console.log(`  Commitment at leaf ${leafIndex0} (computed on-chain via SPV)`);
    console.log("  PART 1 PASSED");
  } else {
    // ---- Localnet: COMPLETE_DEPOSIT with real BTC regtest + SPV ----
    console.log("\n" + "=".repeat(60));
    console.log("PART 1: DEPOSIT — COMPLETE_DEPOSIT (25,000 sats)");
    console.log("=".repeat(60));
    console.log(`  npk0: ${npk0.toString(16).slice(0, 16)}...`);
    console.log(`  Expected commitment0: ${commitment0.toString(16).slice(0, 16)}...`);
    console.log(`  Tree next_index before: ${leafIndex0}`);

    // Create real BTC transaction on regtest
    console.log("  Creating real BTC transaction...");

    const ephPub0 = randomEphemeralPub();
    const payloadHex = Buffer.from(ephPub0).toString("hex") + Buffer.from(npk0Bytes).toString("hex");
    const poolAddr = getNewAddress("bech32");
    const txid = createOpReturnTx(poolAddr, Number(amount0), payloadHex);
    console.log(`  Txid: ${txid}`);

    console.log("  Mining 1 block...");
    mineBlocks(1);
    await waitForTxIndexed(txid, ESPLORA_URL);

    const txStatus = await fetchTxStatus(txid, ESPLORA_URL);
    if (!txStatus.confirmed || !txStatus.block_hash || !txStatus.block_height) {
      throw new Error("Tx not confirmed after mining");
    }
    const blockHash = txStatus.block_hash;
    const blockHeight = txStatus.block_height;

    const rawHeader = await fetchBlockHeader(blockHash, ESPLORA_URL);
    console.log(`  Block header: ${rawHeader.length} bytes at height ${blockHeight}`);

    const rawTxBuf = await fetchRawTx(txid, ESPLORA_URL);
    const strippedTx = stripWitnessData(rawTxBuf);
    const rawSweepTx = new Uint8Array(strippedTx);
    console.log(`  Raw tx: ${rawTxBuf.length} bytes (witness-stripped: ${strippedTx.length} bytes)`);

    const txidBytes = Buffer.from(txid, "hex");
    txidBytes.reverse();
    const txHash = new Uint8Array(txidBytes);

    const esploraProof = await fetchMerkleProof(txid, ESPLORA_URL);
    console.log(`  Merkle proof: ${esploraProof.merkle.length} hashes, pos=${esploraProof.pos}`);
    const merkleProofData = serializeMerkleProof(txid, esploraProof);

    const [lightClient] = deriveLightClientPDA(BTC_LIGHT_CLIENT_ID);
    const newBlockHeight = BigInt(blockHeight);

    console.log(`  Submitting headers up to height ${newBlockHeight}...`);
    const blockHeaderPda = await fetchAndSubmitHeaders(
      connection, authority, newBlockHeight,
      new Uint8Array(rawHeader), BTC_LIGHT_CLIENT_ID,
      ESPLORA_URL, fetchBlockHeader,
    );
    console.log(`  Block headers submitted`);

    console.log("  Uploading sweep tx to ChadBuffer...");
    const bufferKeypair = await createTxBufferAccount(connection, authority, rawSweepTx, CHADBUFFER_ID);
    console.log(`  ChadBuffer: ${bufferKeypair.publicKey.toBase58().slice(0, 20)}...`);

    const [depositRecord] = deriveDepositStealthPDA(PROGRAM_ID, txHash);
    console.log(`  Deposit record PDA: ${depositRecord.toBase58().slice(0, 20)}...`);

    const verifyDepositIx = buildVerifyStealthDepositIx(
      poolState, lightClient, blockHeaderPda, commitmentTree,
      depositRecord, bufferKeypair.publicKey, authority.publicKey,
      zkbtcMint, poolVault,
      {
        txid: txHash,
        blockHeight: newBlockHeight,
        amountSats: amount0,
        txSize: rawSweepTx.length,
        ephemeralPub: ephPub0,
        npk: npk0Bytes,
        merkleProofData,
      },
    );

    try {
      const tx = new Transaction().add(verifyDepositIx);
      const sig = await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
      console.log(`  Verify deposit tx: ${sig.slice(0, 20)}...`);
    } catch (err: any) {
      console.error(`  FAIL: ${err.message?.slice(0, 300)}`);
      if (err.logs) for (const log of err.logs) console.error(`    ${log}`);
      process.exit(1);
    }

    const treeAfter1 = await readOnChainTree(connection, commitmentTree);
    if (Number(treeAfter1.nextIndex) !== leafIndex0 + 1) {
      console.error(`  FAIL: next_index expected ${leafIndex0 + 1}, got ${treeAfter1.nextIndex}`);
      process.exit(1);
    }

    const depositRecordInfo = await connection.getAccountInfo(depositRecord);
    if (!depositRecordInfo || depositRecordInfo.data[0] !== 0x02) {
      console.error("  FAIL: Deposit record PDA not created");
      process.exit(1);
    }
    const recordLeafIndex = Buffer.from(depositRecordInfo.data).readBigUInt64LE(88);
    console.log(`  Deposit record: leaf_index=${recordLeafIndex}, minted=${depositRecordInfo.data[1]}`);
    if (Number(recordLeafIndex) !== leafIndex0) {
      console.error(`  FAIL: leaf_index mismatch: ${recordLeafIndex} vs ${leafIndex0}`);
      process.exit(1);
    }
    console.log(`  Commitment at leaf ${leafIndex0} (computed on-chain)`);
    console.log("  PART 1 PASSED");
  }

  // =========================================================================
  // PART 2: Private Send — JoinSplit 1x1 (TRANSACT, disc=14)
  // =========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("PART 2: PRIVATE SEND — JoinSplit 1x1 (25,000 sats)");
  console.log("=".repeat(60));

  // Read tree frontier and compute Merkle proof for leaf 0
  const treeData2 = await readOnChainTree(connection, commitmentTree);
  const frontier2 = extractFrontier(treeData2);
  const merkleRoot2 = bytes32ToBigintBE(new Uint8Array(treeData2.currentRoot));
  console.log(`  Merkle root: ${merkleRoot2.toString(16).slice(0, 20)}...`);

  const proof2 = getMerkleProofFromFrontier(leafIndex0, frontier2);
  if (!verifyMerkleProof(commitment0, proof2, merkleRoot2)) {
    console.error("  FAIL: Local Merkle proof verification failed");
    process.exit(1);
  }
  console.log("  Merkle proof verified locally");

  // Create output note (same amount, new random — private refresh)
  const random1 = randomFieldElement();
  const amount1 = 25_000n;
  const npk1 = poseidonHash([mpk, random1]);
  const commitment1 = poseidonHash([npk1, ZKBTC_TOKEN_ID, amount1]);

  // Compute nullifier
  const nullifier0 = poseidonHash([nullifyingKey, BigInt(leafIndex0)]);
  console.log(`  Nullifier0: ${nullifier0.toString(16).slice(0, 16)}...`);
  console.log(`  Output commitment1: ${commitment1.toString(16).slice(0, 16)}...`);

  // Bound params hash and message hash
  const boundParamsHash = computeBoundParamsHash();
  const msgHash2 = poseidonHash([merkleRoot2, boundParamsHash, nullifier0, commitment1]);
  const [sigR8x2, sigR8y2, sigS2] = await eddsaPoseidonSign(privKeyBuf, msgHash2);

  // Generate real Groth16 proof
  const circuitInputs2 = {
    merkleRoot: merkleRoot2.toString(),
    boundParamsHash: boundParamsHash.toString(),
    nullifiers: [nullifier0.toString()],
    commitmentsOut: [commitment1.toString()],
    token: ZKBTC_TOKEN_ID.toString(),
    publicKey: [pubKeyX.toString(), pubKeyY.toString()],
    signature: [sigR8x2.toString(), sigR8y2.toString(), sigS2.toString()],
    nullifyingKey: nullifyingKey.toString(),
    randomIn: [random0.toString()],
    valueIn: [amount0.toString()],
    leavesIndices: [leafIndex0.toString()],
    pathElements: [proof2.siblings.map(s => s.toString())],
    pathIndices: [proof2.indices],
    npkOut: [npk1.toString()],
    valueOut: [amount1.toString()],
  };

  const { proof: groth16Proof2 } = generateProofViaNode("joinsplit_1x1", circuitInputs2);
  const proofBytes2 = serializeGroth16Proof(groth16Proof2);
  console.log(`  Proof generated: ${proofBytes2.length} bytes`);

  // Submit TRANSACT
  const nullifierBytes0 = bigintToBytes32BE(nullifier0);
  const commitmentBytes1 = bigintToBytes32BE(commitment1);
  const [nullifierPDA0] = deriveNullifierPDA(PROGRAM_ID,nullifierBytes0);
  const ephPub1 = randomEphemeralPub();
  const [stealthAnn1] = deriveStealthAnnouncementPDA(PROGRAM_ID,ephPub1);
  const [vkRegistry1x1] = deriveVkRegistryPDA(PROGRAM_ID,1, 1);

  const transactIx2 = buildTransactIx(
    poolState, commitmentTree, vkRegistry1x1, authority.publicKey,
    1, 1,
    proofBytes2,
    bigintToBytes32BE(merkleRoot2),
    bigintToBytes32BE(boundParamsHash),
    [nullifierBytes0],
    [commitmentBytes1],
    [{ ephemeralPub: ephPub1, encryptedAmount: amountToLE8(amount1) }],
    [nullifierPDA0],
    [stealthAnn1],
  );

  try {
    const tx = new Transaction().add(transactIx2);
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
    console.log(`  Transact tx: ${sig.slice(0, 20)}...`);
  } catch (err: any) {
    console.error(`  FAIL: ${err.message?.slice(0, 300)}`);
    if (err.logs) for (const log of err.logs) console.error(`    ${log}`);
    process.exit(1);
  }

  // Verify Part 2
  const nullifierInfo0 = await connection.getAccountInfo(nullifierPDA0);
  if (!nullifierInfo0 || nullifierInfo0.data[0] !== 0x03) {
    console.error("  FAIL: Nullifier PDA not found");
    process.exit(1);
  }
  if (nullifierInfo0.data[1] !== 2) {
    console.error(`  FAIL: Nullifier op type expected 2 (PrivateTransfer), got ${nullifierInfo0.data[1]}`);
    process.exit(1);
  }
  console.log("  Nullifier PDA created (op=PrivateTransfer)");

  const treeAfter2 = await readOnChainTree(connection, commitmentTree);
  const leafIndex1 = Number(treeAfter2.nextIndex) - 1;
  if (leafIndex1 !== leafIndex0 + 1) {
    console.error(`  FAIL: Expected leaf at ${leafIndex0 + 1}, got ${leafIndex1}`);
    process.exit(1);
  }
  console.log(`  New commitment at leaf ${leafIndex1}`);
  console.log("  PART 2 PASSED");

  // =========================================================================
  // PART 3: Split — JoinSplit 1x2 (TRANSACT, disc=14)
  // =========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("PART 3: SPLIT — JoinSplit 1x2 (25,000 -> 15,000 + 10,000)");
  console.log("=".repeat(60));

  // Read tree frontier after Part 2
  const treeData3 = await readOnChainTree(connection, commitmentTree);
  const frontier3 = extractFrontier(treeData3);
  const merkleRoot3 = bytes32ToBigintBE(new Uint8Array(treeData3.currentRoot));
  console.log(`  Merkle root: ${merkleRoot3.toString(16).slice(0, 20)}...`);

  // Merkle proof for leaf 1 (the Part 2 output)
  const proof3 = getMerkleProofFromFrontier(leafIndex1, frontier3);
  if (!verifyMerkleProof(commitment1, proof3, merkleRoot3)) {
    console.error("  FAIL: Local Merkle proof verification failed for leaf 1");
    process.exit(1);
  }
  console.log("  Merkle proof verified locally");

  // Create two output notes
  const random2 = randomFieldElement();
  const amount2 = 15_000n;
  const npk2 = poseidonHash([mpk, random2]);
  const commitment2 = poseidonHash([npk2, ZKBTC_TOKEN_ID, amount2]);

  const random3 = randomFieldElement();
  const amount3 = 10_000n;
  const npk3 = poseidonHash([mpk, random3]);
  const commitment3 = poseidonHash([npk3, ZKBTC_TOKEN_ID, amount3]);

  // Nullifier for leaf 1
  const nullifier1 = poseidonHash([nullifyingKey, BigInt(leafIndex1)]);
  console.log(`  Nullifier1: ${nullifier1.toString(16).slice(0, 16)}...`);
  console.log(`  Output commitment2 (7k): ${commitment2.toString(16).slice(0, 16)}...`);
  console.log(`  Output commitment3 (3k): ${commitment3.toString(16).slice(0, 16)}...`);

  // Message hash includes ALL nullifiers and ALL output commitments
  const msgHash3 = poseidonHash([merkleRoot3, boundParamsHash, nullifier1, commitment2, commitment3]);
  const [sigR8x3, sigR8y3, sigS3] = await eddsaPoseidonSign(privKeyBuf, msgHash3);

  // Generate real Groth16 proof using joinsplit_1x2
  const circuitInputs3 = {
    merkleRoot: merkleRoot3.toString(),
    boundParamsHash: boundParamsHash.toString(),
    nullifiers: [nullifier1.toString()],
    commitmentsOut: [commitment2.toString(), commitment3.toString()],
    token: ZKBTC_TOKEN_ID.toString(),
    publicKey: [pubKeyX.toString(), pubKeyY.toString()],
    signature: [sigR8x3.toString(), sigR8y3.toString(), sigS3.toString()],
    nullifyingKey: nullifyingKey.toString(),
    randomIn: [random1.toString()],
    valueIn: [amount1.toString()],
    leavesIndices: [leafIndex1.toString()],
    pathElements: [proof3.siblings.map(s => s.toString())],
    pathIndices: [proof3.indices],
    npkOut: [npk2.toString(), npk3.toString()],
    valueOut: [amount2.toString(), amount3.toString()],
  };

  const { proof: groth16Proof3 } = generateProofViaNode("joinsplit_1x2", circuitInputs3);
  const proofBytes3 = serializeGroth16Proof(groth16Proof3);
  console.log(`  Proof generated: ${proofBytes3.length} bytes`);

  // Submit TRANSACT (1 input, 2 outputs)
  const nullifierBytes1 = bigintToBytes32BE(nullifier1);
  const commitmentBytes2 = bigintToBytes32BE(commitment2);
  const commitmentBytes3 = bigintToBytes32BE(commitment3);
  const [nullifierPDA1] = deriveNullifierPDA(PROGRAM_ID,nullifierBytes1);
  const ephPub2 = randomEphemeralPub();
  const ephPub3 = randomEphemeralPub();
  const [stealthAnn2] = deriveStealthAnnouncementPDA(PROGRAM_ID,ephPub2);
  const [stealthAnn3] = deriveStealthAnnouncementPDA(PROGRAM_ID,ephPub3);
  const [vkRegistry1x2] = deriveVkRegistryPDA(PROGRAM_ID,1, 2);

  const transactIx3 = buildTransactIx(
    poolState, commitmentTree, vkRegistry1x2, authority.publicKey,
    1, 2,
    proofBytes3,
    bigintToBytes32BE(merkleRoot3),
    bigintToBytes32BE(boundParamsHash),
    [nullifierBytes1],
    [commitmentBytes2, commitmentBytes3],
    [
      { ephemeralPub: ephPub2, encryptedAmount: amountToLE8(amount2) },
      { ephemeralPub: ephPub3, encryptedAmount: amountToLE8(amount3) },
    ],
    [nullifierPDA1],
    [stealthAnn2, stealthAnn3],
  );

  try {
    const tx = new Transaction().add(transactIx3);
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
    console.log(`  Transact tx: ${sig.slice(0, 20)}...`);
  } catch (err: any) {
    console.error(`  FAIL: ${err.message?.slice(0, 300)}`);
    if (err.logs) for (const log of err.logs) console.error(`    ${log}`);
    process.exit(1);
  }

  // Verify Part 3
  const nullifierInfo1 = await connection.getAccountInfo(nullifierPDA1);
  if (!nullifierInfo1 || nullifierInfo1.data[0] !== 0x03) {
    console.error("  FAIL: Nullifier PDA not found for Part 3");
    process.exit(1);
  }
  if (nullifierInfo1.data[1] !== 2) {
    console.error(`  FAIL: Nullifier op type expected 2, got ${nullifierInfo1.data[1]}`);
    process.exit(1);
  }
  console.log("  Nullifier PDA created (op=PrivateTransfer)");

  const treeAfter3 = await readOnChainTree(connection, commitmentTree);
  const expectedNextIndex3 = leafIndex1 + 3; // +2 outputs
  if (Number(treeAfter3.nextIndex) !== expectedNextIndex3) {
    console.error(`  FAIL: next_index expected ${expectedNextIndex3}, got ${treeAfter3.nextIndex}`);
    process.exit(1);
  }
  const leafIndex2 = leafIndex1 + 1;
  const leafIndex3 = leafIndex1 + 2;
  console.log(`  New commitments at leaves ${leafIndex2} (7k) and ${leafIndex3} (3k)`);

  // Check stealth announcements
  const stealthInfo2 = await connection.getAccountInfo(stealthAnn2);
  const stealthInfo3 = await connection.getAccountInfo(stealthAnn3);
  if (!stealthInfo2 || stealthInfo2.data[0] !== 0x08) {
    console.error("  FAIL: Stealth announcement 2 not created");
    process.exit(1);
  }
  if (!stealthInfo3 || stealthInfo3.data[0] !== 0x08) {
    console.error("  FAIL: Stealth announcement 3 not created");
    process.exit(1);
  }
  console.log("  Both stealth announcements created");
  console.log("  PART 3 PASSED");

  // =========================================================================
  // PART 4: Withdraw — REQUEST_REDEMPTION (disc=5)
  // =========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("PART 4: WITHDRAW — REQUEST_REDEMPTION (15,000 sats)");
  console.log("=".repeat(60));

  // Read pool state before
  const poolInfo = await connection.getAccountInfo(poolState);
  const poolBefore = poolInfo ? parsePoolState(Buffer.from(poolInfo.data)) : null;
  if (!poolBefore) {
    console.error("  FAIL: Pool state not found");
    process.exit(1);
  }
  console.log(`  Pool before: shielded=${poolBefore.totalShielded}, pending=${poolBefore.pendingRedemptions}`);

  // Compute nullifier for leaf 2 (the 7,000 sat commitment)
  const nullifier2 = poseidonHash([nullifyingKey, BigInt(leafIndex2)]);
  const nullifierBytes2 = bigintToBytes32BE(nullifier2);
  console.log(`  Nullifier2: ${nullifier2.toString(16).slice(0, 16)}...`);

  // Read current merkle root
  const treeData4 = await readOnChainTree(connection, commitmentTree);
  const merkleRoot4 = new Uint8Array(treeData4.currentRoot);

  // Build redemption request
  const proofHash = new Uint8Array(32); // zeros (demo mode)
  const vkHash = new Uint8Array(32); // zeros (demo mode)
  const btcAddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
  const requestNonce = 1n;

  const [nullifierPDA2] = deriveNullifierPDA(PROGRAM_ID,nullifierBytes2);
  const [redemptionPDA] = deriveRedemptionPDA(PROGRAM_ID,authority.publicKey, requestNonce);
  console.log(`  Nullifier PDA: ${nullifierPDA2.toBase58().slice(0, 20)}...`);
  console.log(`  Redemption PDA: ${redemptionPDA.toBase58().slice(0, 20)}...`);

  const redemptionIx = buildRequestRedemptionIx(
    PROGRAM_ID,
    poolState,
    commitmentTree,
    nullifierPDA2,
    redemptionPDA,
    authority.publicKey,
    {
      proofHash,
      merkleRoot: merkleRoot4,
      nullifierHash: nullifierBytes2,
      amountSats: amount2,
      vkHash,
      btcAddress,
      nonce: requestNonce,
    },
  );

  try {
    const tx = new Transaction().add(redemptionIx);
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
    console.log(`  Redemption tx: ${sig.slice(0, 20)}...`);
  } catch (err: any) {
    console.error(`  FAIL: ${err.message?.slice(0, 300)}`);
    if (err.logs) for (const log of err.logs) console.error(`    ${log}`);
    process.exit(1);
  }

  // Verify redemption PDA
  const redemptionInfo = await connection.getAccountInfo(redemptionPDA);
  if (!redemptionInfo) {
    console.error("  FAIL: Redemption PDA not created");
    process.exit(1);
  }
  const redemptionData = parseRedemptionRequest(Buffer.from(redemptionInfo.data));
  if (!redemptionData) {
    console.error("  FAIL: Could not parse redemption PDA");
    process.exit(1);
  }
  if (redemptionData.status !== 0) {
    console.error(`  FAIL: Expected status=0 (Pending), got ${redemptionData.status}`);
    process.exit(1);
  }
  if (redemptionData.amountSats !== amount2) {
    console.error(`  FAIL: Amount mismatch: ${redemptionData.amountSats} vs ${amount2}`);
    process.exit(1);
  }
  console.log(`  Redemption PDA: status=Pending, amount=${redemptionData.amountSats}`);

  // Verify nullifier PDA
  const nullifierInfo2 = await connection.getAccountInfo(nullifierPDA2);
  if (!nullifierInfo2 || nullifierInfo2.data[0] !== 0x03) {
    console.error("  FAIL: Nullifier PDA not found for Part 4");
    process.exit(1);
  }
  if (nullifierInfo2.data[1] !== 0) {
    console.error(`  FAIL: Nullifier op type expected 0 (FullWithdrawal), got ${nullifierInfo2.data[1]}`);
    process.exit(1);
  }
  console.log("  Nullifier PDA created (op=FullWithdrawal)");

  // Verify pool state
  const poolInfoAfter = await connection.getAccountInfo(poolState);
  const poolAfter = poolInfoAfter ? parsePoolState(Buffer.from(poolInfoAfter.data)) : null;
  if (!poolAfter) {
    console.error("  FAIL: Pool state not found after redemption");
    process.exit(1);
  }
  if (poolAfter.totalShielded !== poolBefore.totalShielded - amount2) {
    console.error(`  FAIL: total_shielded expected ${poolBefore.totalShielded - amount2}, got ${poolAfter.totalShielded}`);
    process.exit(1);
  }
  if (poolAfter.pendingRedemptions !== poolBefore.pendingRedemptions + 1n) {
    console.error(`  FAIL: pending_redemptions expected ${poolBefore.pendingRedemptions + 1n}, got ${poolAfter.pendingRedemptions}`);
    process.exit(1);
  }
  console.log(`  Pool after: shielded=${poolAfter.totalShielded}, pending=${poolAfter.pendingRedemptions}`);
  console.log("  PART 4 PASSED");

  // =========================================================================
  // Summary
  // =========================================================================
  console.log("\n" + "=".repeat(60));
  console.log("ALL 4 PARTS PASSED");
  console.log("=".repeat(60));
  console.log(`  Part 1: Deposit (SPV${NETWORK === "devnet" ? "+testnet" : ""}) - ${amount0} sats -> leaf ${leafIndex0}`);
  console.log(`  Part 2: Private Send  - ${amount1} sats -> leaf ${leafIndex1} (nullified leaf ${leafIndex0})`);
  console.log(`  Part 3: Split         - ${amount2} + ${amount3} sats -> leaves ${leafIndex2},${leafIndex3} (nullified leaf ${leafIndex1})`);
  console.log(`  Part 4: Withdraw      - ${amount2} sats redemption request (nullified leaf ${leafIndex2})`);
  console.log(`  Remaining: ${amount3} sats at leaf ${leafIndex3}`);
  console.log("=".repeat(60));

  process.exit(0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
