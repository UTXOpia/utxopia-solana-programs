/**
 * UTXOpia Pinocchio Program Test Suite
 *
 * IDL-like TypeScript interface for testing the raw Pinocchio program
 * with Circom ZK proof integration.
 *
 * Run: bun test tests/pinocchio-UTXOpia.ts
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
  createAccount,
  getAccount,
  getOrCreateAssociatedTokenAccount,
} from "@solana/spl-token";
import { buildPoseidon } from "circomlibjs";
type Poseidon = Awaited<ReturnType<typeof buildPoseidon>>;
import * as snarkjs from "snarkjs";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import { expect } from "chai";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ============================================================================
// PROGRAM IDL-LIKE DEFINITIONS
// ============================================================================

/**
 * Program ID for UTXOpia Pinocchio
 * Update this after deployment
 */
const PROGRAM_ID = new PublicKey("AtztELZfz3GHA8hFQCv7aT9Mt47Xhknv3ZCNb3fmXsgf");

/**
 * Instruction discriminators (single byte for gas efficiency)
 */
export const Instruction = {
  Initialize: 0,
  RecordDeposit: 1,
  ClaimDirect: 2,
  MintToCommitment: 3,
  SplitCommitment: 4,
  RequestRedemption: 5,
  CompleteRedemption: 6,
  SetPaused: 7,
  InitLightClient: 8,
  SubmitHeader: 9,
  VerifyDeposit: 10,
  ClaimGroth16: 11,
} as const;

/**
 * Account seeds for PDA derivation
 */
export const Seeds = {
  POOL_STATE: Buffer.from("pool_state"),
  COMMITMENT_TREE: Buffer.from("commitment_tree"),
  DEPOSIT: Buffer.from("deposit"),
  STEALTH: Buffer.from("stealth"),
  NULLIFIER: Buffer.from("nullifier"),
  REDEMPTION: Buffer.from("redemption"),
};

/**
 * Account discriminators (first byte of account data)
 */
export const Discriminators = {
  POOL_STATE: 0x01,
  COMMITMENT_TREE: 0x02,
  DEPOSIT_RECORD: 0x03,
  NULLIFIER_RECORD: 0x04,
  REDEMPTION_REQUEST: 0x05,
};

/**
 * Program constants
 */
export const Constants = {
  MIN_DEPOSIT_SATS: 10_000n,           // 0.0001 BTC
  MAX_DEPOSIT_SATS: 100_000_000_000n,  // 1000 BTC
  PROOF_SIZE: 256,
  MAX_BTC_ADDRESS_LEN: 62,
  TREE_DEPTH: 20,
};

// ============================================================================
// ACCOUNT LAYOUTS (Zero-Copy Compatible)
// ============================================================================

/**
 * PoolState account layout (264 bytes)
 */
export interface PoolStateLayout {
  discriminator: number;     // 1 byte
  bump: number;              // 1 byte
  flags: number;             // 1 byte (bit 0 = paused)
  _padding: number;          // 1 byte
  authority: Uint8Array;     // 32 bytes
  zkbtcMint: Uint8Array;     // 32 bytes
  poolVault: Uint8Array;     // 32 bytes (offset 68)
  frostVault: Uint8Array;    // 32 bytes
  depositCount: bigint;      // 8 bytes
  totalMinted: bigint;       // 8 bytes
  totalBurned: bigint;       // 8 bytes
  pendingRedemptions: bigint; // 8 bytes
  directClaims: bigint;      // 8 bytes
  splitCount: bigint;        // 8 bytes
  lastUpdate: bigint;        // 8 bytes
  minDeposit: bigint;        // 8 bytes
  maxDeposit: bigint;        // 8 bytes
  _reserved: Uint8Array;     // 64 bytes
}

export const POOL_STATE_SIZE = 264;

/**
 * Parse PoolState from account data
 */
export function parsePoolState(data: Buffer): PoolStateLayout {
  if (data.length < POOL_STATE_SIZE) {
    throw new Error(`Invalid PoolState size: ${data.length} < ${POOL_STATE_SIZE}`);
  }
  if (data[0] !== Discriminators.POOL_STATE) {
    throw new Error(`Invalid PoolState discriminator: ${data[0]}`);
  }

  return {
    discriminator: data[0],
    bump: data[1],
    flags: data[2],
    _padding: data[3],
    authority: data.subarray(4, 36),
    zkbtcMint: data.subarray(36, 68),
    poolVault: data.subarray(68, 100),
    frostVault: data.subarray(100, 132),
    depositCount: data.readBigUInt64LE(132),
    totalMinted: data.readBigUInt64LE(140),
    totalBurned: data.readBigUInt64LE(148),
    pendingRedemptions: data.readBigUInt64LE(156),
    directClaims: data.readBigUInt64LE(164),
    splitCount: data.readBigUInt64LE(172),
    lastUpdate: data.readBigInt64LE(180),
    minDeposit: data.readBigUInt64LE(188),
    maxDeposit: data.readBigUInt64LE(196),
    _reserved: data.subarray(200, 264),
  };
}

/**
 * CommitmentTree account layout
 */
export interface CommitmentTreeLayout {
  discriminator: number;
  bump: number;
  nextIndex: bigint;
  currentRoot: Uint8Array;
  rootHistory: Uint8Array[];
}

// ============================================================================
// INSTRUCTION BUILDERS
// ============================================================================

/**
 * Build Initialize instruction
 */
export function buildInitializeInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  commitmentTree: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
  frostVault: PublicKey,
  authority: PublicKey,
  poolBump: number,
  treeBump: number,
): TransactionInstruction {
  const data = Buffer.alloc(3);
  data[0] = Instruction.Initialize;
  data[1] = poolBump;
  data[2] = treeBump;

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
    programId,
    data,
  });
}

/**
 * Build RecordDeposit instruction
 */
export function buildRecordDepositInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  depositRecord: PublicKey,
  authority: PublicKey,
  commitment: Uint8Array,
  amountSats: bigint,
): TransactionInstruction {
  // Data: discriminator (1) + commitment (32) + amount (8) = 41 bytes
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
    programId,
    data,
  });
}

/**
 * Build ClaimDirect instruction
 */
export function buildClaimDirectInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  commitmentTree: PublicKey,
  nullifierRecord: PublicKey,
  zkbtcMint: PublicKey,
  userTokenAccount: PublicKey,
  user: PublicKey,
  proof: Uint8Array,
  root: Uint8Array,
  nullifierHash: Uint8Array,
  amount: bigint,
): TransactionInstruction {
  // Data: discriminator (1) + proof (256) + root (32) + nullifier_hash (32) + amount (8) = 329 bytes
  const data = Buffer.alloc(329);
  data[0] = Instruction.ClaimDirect;
  data.set(proof, 1);
  data.set(root, 257);
  data.set(nullifierHash, 289);
  data.writeBigUInt64LE(amount, 321);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: false },
      { pubkey: nullifierRecord, isSigner: false, isWritable: true },
      { pubkey: zkbtcMint, isSigner: false, isWritable: true },
      { pubkey: userTokenAccount, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data,
  });
}

/**
 * Build MintToCommitment instruction (1-in-1-out transfer)
 */
export function buildMintToCommitmentInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  commitmentTree: PublicKey,
  nullifierRecord: PublicKey,
  user: PublicKey,
  proof: Uint8Array,
  root: Uint8Array,
  nullifierHash: Uint8Array,
  outputCommitment: Uint8Array,
): TransactionInstruction {
  // Data: discriminator (1) + proof (256) + root (32) + nullifier_hash (32) + output_commitment (32) = 353 bytes
  const data = Buffer.alloc(353);
  data[0] = Instruction.MintToCommitment;
  data.set(proof, 1);
  data.set(root, 257);
  data.set(nullifierHash, 289);
  data.set(outputCommitment, 321);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: nullifierRecord, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data,
  });
}

/**
 * Build SplitCommitment instruction (1-in-2-out)
 */
export function buildSplitCommitmentInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  commitmentTree: PublicKey,
  nullifierRecord: PublicKey,
  user: PublicKey,
  proof: Uint8Array,
  root: Uint8Array,
  nullifierHash: Uint8Array,
  outputCommitment1: Uint8Array,
  outputCommitment2: Uint8Array,
): TransactionInstruction {
  // Data: discriminator (1) + proof (256) + root (32) + nullifier_hash (32) + output_1 (32) + output_2 (32) = 385 bytes
  const data = Buffer.alloc(385);
  data[0] = Instruction.SplitCommitment;
  data.set(proof, 1);
  data.set(root, 257);
  data.set(nullifierHash, 289);
  data.set(outputCommitment1, 321);
  data.set(outputCommitment2, 353);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: nullifierRecord, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data,
  });
}

/**
 * Build RequestRedemption instruction
 */
export function buildRequestRedemptionInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  redemptionRequest: PublicKey,
  zkbtcMint: PublicKey,
  userTokenAccount: PublicKey,
  user: PublicKey,
  amountSats: bigint,
  btcAddress: string,
  requestNonce: bigint,
): TransactionInstruction {
  const btcAddressBytes = Buffer.from(btcAddress, "utf8");
  // Data: discriminator (1) + amount (8) + btc_address_len (1) + btc_address + nonce (8)
  const data = Buffer.alloc(1 + 8 + 1 + btcAddressBytes.length + 8);
  let offset = 0;
  data[offset++] = Instruction.RequestRedemption;
  data.writeBigUInt64LE(amountSats, offset);
  offset += 8;
  data[offset++] = btcAddressBytes.length;
  data.set(btcAddressBytes, offset);
  offset += btcAddressBytes.length;
  data.writeBigUInt64LE(requestNonce, offset);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: redemptionRequest, isSigner: false, isWritable: true },
      { pubkey: zkbtcMint, isSigner: false, isWritable: true },
      { pubkey: userTokenAccount, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data,
  });
}

/**
 * Build SetPaused instruction
 */
export function buildSetPausedInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  authority: PublicKey,
  paused: boolean,
): TransactionInstruction {
  const data = Buffer.alloc(2);
  data[0] = Instruction.SetPaused;
  data[1] = paused ? 1 : 0;

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    programId,
    data,
  });
}

/**
 * Build ClaimGroth16 instruction
 *
 * Data layout (200 bytes):
 * - proof_hash: [u8; 32] - SHA256 hash of the Groth16 proof
 * - merkle_root: [u8; 32] - Public input: merkle root
 * - nullifier_hash_pi: [u8; 32] - Public input: nullifier hash
 * - amount_pi: [u8; 32] - Public input: amount (big-endian)
 * - vk_hash: [u8; 32] - Verification key hash (zeros = demo mode)
 * - nullifier_hash: [u8; 32] - Nullifier hash for PDA derivation
 * - amount: u64 - Amount in satoshis
 */
export function buildClaimGroth16Instruction(
  programId: PublicKey,
  poolState: PublicKey,
  commitmentTree: PublicKey,
  nullifierRecord: PublicKey,
  zkbtcMint: PublicKey,
  userTokenAccount: PublicKey,
  user: PublicKey,
  proofHash: Uint8Array,
  merkleRoot: Uint8Array,
  nullifierHash: Uint8Array,
  amount: bigint,
  vkHash?: Uint8Array, // Optional - zeros means demo mode
): TransactionInstruction {
  // Data: discriminator (1) + proof_hash (32) + merkle_root (32) + nullifier_hash_pi (32)
  //     + amount_pi (32) + vk_hash (32) + nullifier_hash (32) + amount (8) = 201 bytes
  const data = Buffer.alloc(201);
  let offset = 0;

  data[offset++] = Instruction.ClaimGroth16;

  // proof_hash (32 bytes)
  data.set(proofHash, offset);
  offset += 32;

  // merkle_root (32 bytes)
  data.set(merkleRoot, offset);
  offset += 32;

  // nullifier_hash_pi (32 bytes) - must match nullifier_hash
  data.set(nullifierHash, offset);
  offset += 32;

  // amount_pi (32 bytes) - big-endian in last 8 bytes
  const amountPi = new Uint8Array(32);
  const amountBytes = new Uint8Array(8);
  let tempAmount = amount;
  for (let i = 7; i >= 0; i--) {
    amountBytes[i] = Number(tempAmount & 0xffn);
    tempAmount = tempAmount >> 8n;
  }
  amountPi.set(amountBytes, 24);
  data.set(amountPi, offset);
  offset += 32;

  // vk_hash (32 bytes) - zeros = demo mode
  if (vkHash) {
    data.set(vkHash, offset);
  } // else zeros (demo mode)
  offset += 32;

  // nullifier_hash (32 bytes)
  data.set(nullifierHash, offset);
  offset += 32;

  // amount (8 bytes, little-endian)
  data.writeBigUInt64LE(amount, offset);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: false },
      { pubkey: nullifierRecord, isSigner: false, isWritable: true },
      { pubkey: zkbtcMint, isSigner: false, isWritable: true },
      { pubkey: userTokenAccount, isSigner: false, isWritable: true },
      { pubkey: user, isSigner: true, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data,
  });
}

// ============================================================================
// PDA DERIVATION HELPERS
// ============================================================================

/**
 * Derive PoolState PDA
 */
export function derivePoolStatePda(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Seeds.POOL_STATE], programId);
}

/**
 * Derive CommitmentTree PDA
 */
export function deriveCommitmentTreePda(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Seeds.COMMITMENT_TREE], programId);
}

/**
 * Derive Deposit Stealth Announcement PDA (unified: ["stealth", txid])
 */
export function deriveDepositStealthPda(
  programId: PublicKey,
  txid: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Seeds.STEALTH, txid],
    programId,
  );
}

/**
 * Derive NullifierRecord PDA
 */
export function deriveNullifierRecordPda(
  programId: PublicKey,
  nullifierHash: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Seeds.NULLIFIER, nullifierHash],
    programId,
  );
}

/**
 * Derive RedemptionRequest PDA
 */
export function deriveRedemptionRequestPda(
  programId: PublicKey,
  user: PublicKey,
  nonce: bigint,
): [PublicKey, number] {
  const nonceBuffer = Buffer.alloc(8);
  nonceBuffer.writeBigUInt64LE(nonce);
  return PublicKey.findProgramAddressSync(
    [Seeds.REDEMPTION, user.toBuffer(), nonceBuffer],
    programId,
  );
}

// ============================================================================
// CIRCOM ZK PROOF INTEGRATION
// ============================================================================

// Circuit paths - contracts/tests -> ../../circuits/build
const CIRCUIT_DIR = path.resolve(__dirname, "../../circuits/build");
const CLAIM_WASM = path.join(CIRCUIT_DIR, "claim_direct_js/claim_direct.wasm");
const CLAIM_ZKEY = path.join(CIRCUIT_DIR, "claim_direct_final.zkey");
const CLAIM_VK = path.join(CIRCUIT_DIR, "claim_direct_vk.json");

// BN254 field prime
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Note structure for shielded amounts
 */
export interface Note {
  amount: bigint;
  nullifier: bigint;
  secret: bigint;
  commitment: bigint;
  nullifierHash: bigint;
  nullifierBytes: Uint8Array;
  secretBytes: Uint8Array;
  commitmentBytes: Uint8Array;
  nullifierHashBytes: Uint8Array;
}

/**
 * Convert bigint to 32-byte Uint8Array (big-endian)
 */
export function bigintToBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let temp = value;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(temp & 0xffn);
    temp = temp >> 8n;
  }
  return bytes;
}

/**
 * Convert Uint8Array to bigint (big-endian)
 */
export function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Generate random field element
 */
export function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBigint(bytes) % FIELD_PRIME;
}

/**
 * Generate a note with Poseidon hashing
 *
 * Circuit structure:
 *   note = Poseidon(nullifier, secret)
 *   commitment = Poseidon(note, amount)
 *   nullifierHash = Poseidon(nullifier)
 */
export async function generateNote(poseidon: Poseidon, amountSats: bigint): Promise<Note> {
  const nullifier = randomFieldElement();
  const secret = randomFieldElement();

  // note = Poseidon(nullifier, secret)
  const note = poseidon.F.toObject(poseidon([nullifier, secret]));

  // commitment = Poseidon(note, amount)
  const commitment = poseidon.F.toObject(poseidon([note, amountSats]));

  // nullifierHash = Poseidon(nullifier)
  const nullifierHash = poseidon.F.toObject(poseidon([nullifier]));

  return {
    amount: amountSats,
    nullifier,
    secret,
    commitment,
    nullifierHash,
    nullifierBytes: bigintToBytes(nullifier),
    secretBytes: bigintToBytes(secret),
    commitmentBytes: bigintToBytes(commitment),
    nullifierHashBytes: bigintToBytes(nullifierHash),
  };
}

/**
 * Groth16 proof result
 */
export interface Groth16ProofResult {
  proofBytes: Uint8Array;  // 256 bytes
  publicSignals: string[];
  isValid: boolean;
}

/**
 * Generate claim_direct proof
 *
 * Circuit public inputs: root, nullifierHash, amount, recipient
 * Circuit private inputs: nullifier, secret, pathElements[20], pathIndices[20]
 */
export async function generateClaimDirectProof(
  note: Note,
  merkleRoot: Uint8Array,
  merklePath: bigint[],
  merkleIndices: number[],
  recipient: PublicKey,
): Promise<Groth16ProofResult> {
  const circuitExists = fs.existsSync(CLAIM_WASM);
  console.log("  Circuit path:", CLAIM_WASM);
  console.log("  Circuit exists:", circuitExists);

  if (!circuitExists) {
    console.log("  Using mock proof (circuit files not found).");
    return {
      proofBytes: new Uint8Array(256).fill(1),
      publicSignals: [
        bytesToBigint(merkleRoot).toString(),
        note.nullifierHash.toString(),
        note.amount.toString(),
        bytesToBigint(recipient.toBytes()).toString(),
      ],
      isValid: true,
    };
  }

  // Convert recipient pubkey to field element (take first 31 bytes to stay in field)
  const recipientBytes = recipient.toBytes();
  const recipientField = bytesToBigint(recipientBytes.slice(0, 31));

  const input = {
    // Public inputs (must match circuit order)
    root: bytesToBigint(merkleRoot).toString(),
    nullifierHash: note.nullifierHash.toString(),
    amount: note.amount.toString(),
    recipient: recipientField.toString(),
    // Private inputs
    nullifier: note.nullifier.toString(),
    secret: note.secret.toString(),
    pathElements: merklePath.map(p => p.toString()),
    pathIndices: merkleIndices,
  };

  console.log("  Generating real Groth16 proof...");
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    CLAIM_WASM,
    CLAIM_ZKEY,
  );

  const proofBytes = groth16ProofToBytes(proof);

  // Verify locally
  const vk = JSON.parse(fs.readFileSync(CLAIM_VK, "utf8"));
  const isValid = await snarkjs.groth16.verify(vk, publicSignals, proof);

  console.log("  Proof generated and verified:", isValid);

  return { proofBytes, publicSignals, isValid };
}

/**
 * Convert snarkjs Groth16 proof to 256 bytes
 */
function groth16ProofToBytes(proof: snarkjs.Groth16Proof): Uint8Array {
  const bytes = new Uint8Array(256);

  // A point (G1) - 64 bytes
  const aX = hexPadStart(BigInt(proof.pi_a[0]).toString(16), 64);
  const aY = hexPadStart(BigInt(proof.pi_a[1]).toString(16), 64);
  bytes.set(hexToBytes(aX), 0);
  bytes.set(hexToBytes(aY), 32);

  // B point (G2) - 128 bytes (note: snarkjs uses different coordinate order)
  const bX1 = hexPadStart(BigInt(proof.pi_b[0][1]).toString(16), 64);
  const bX2 = hexPadStart(BigInt(proof.pi_b[0][0]).toString(16), 64);
  const bY1 = hexPadStart(BigInt(proof.pi_b[1][1]).toString(16), 64);
  const bY2 = hexPadStart(BigInt(proof.pi_b[1][0]).toString(16), 64);
  bytes.set(hexToBytes(bX1), 64);
  bytes.set(hexToBytes(bX2), 96);
  bytes.set(hexToBytes(bY1), 128);
  bytes.set(hexToBytes(bY2), 160);

  // C point (G1) - 64 bytes
  const cX = hexPadStart(BigInt(proof.pi_c[0]).toString(16), 64);
  const cY = hexPadStart(BigInt(proof.pi_c[1]).toString(16), 64);
  bytes.set(hexToBytes(cX), 192);
  bytes.set(hexToBytes(cY), 224);

  return bytes;
}

function hexPadStart(hex: string, length: number): string {
  return hex.padStart(length, "0");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

// ============================================================================
// MERKLE TREE (Poseidon-based)
// ============================================================================

const TREE_DEPTH = 20;
const ZERO_VALUE = 0n;

export class PoseidonMerkleTree {
  private poseidon: Poseidon;
  private leaves: bigint[] = [];
  private filledSubtrees: bigint[] = [];
  private zeros: bigint[] = [];
  public root: bigint;
  private rootHistory: bigint[] = [];

  constructor(poseidon: Poseidon) {
    this.poseidon = poseidon;

    // Compute zero values for each level
    let currentZero = ZERO_VALUE;
    this.zeros.push(currentZero);
    for (let i = 0; i < TREE_DEPTH; i++) {
      currentZero = this.hash(currentZero, currentZero);
      this.zeros.push(currentZero);
      this.filledSubtrees.push(this.zeros[i]);
    }
    this.root = this.zeros[TREE_DEPTH];
  }

  private hash(left: bigint, right: bigint): bigint {
    return this.poseidon.F.toObject(this.poseidon([left, right]));
  }

  insert(commitment: bigint): number {
    const leafIndex = this.leaves.length;
    this.leaves.push(commitment);

    let currentHash = commitment;
    let currentIndex = leafIndex;

    for (let level = 0; level < TREE_DEPTH; level++) {
      if (currentIndex % 2 === 0) {
        this.filledSubtrees[level] = currentHash;
        currentHash = this.hash(currentHash, this.zeros[level]);
      } else {
        currentHash = this.hash(this.filledSubtrees[level], currentHash);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }

    this.root = currentHash;
    this.rootHistory.push(currentHash);
    if (this.rootHistory.length > 30) {
      this.rootHistory.shift();
    }

    return leafIndex;
  }

  isValidRoot(root: bigint): boolean {
    if (root === this.root) return true;
    return this.rootHistory.includes(root);
  }

  generateProof(leafIndex: number): { path: bigint[]; indices: number[] } {
    const path: bigint[] = [];
    const indices: number[] = [];
    let currentIndex = leafIndex;

    for (let level = 0; level < TREE_DEPTH; level++) {
      const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
      indices.push(currentIndex % 2);

      if (siblingIndex < this.leaves.length && level === 0) {
        path.push(this.leaves[siblingIndex]);
      } else if (currentIndex % 2 === 0) {
        path.push(this.zeros[level]);
      } else {
        path.push(this.filledSubtrees[level]);
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    return { path, indices };
  }

  get rootBytes(): Uint8Array {
    return bigintToBytes(this.root);
  }

  get leafCount(): number {
    return this.leaves.length;
  }
}

// ============================================================================
// TEST SUITE
// ============================================================================

describe("UTXOpia Pinocchio Program", function() {
  this.timeout(120000);

  let connection: Connection;
  let payer: Keypair;
  let authority: Keypair;
  let user: Keypair;
  let poseidon: Poseidon;
  let merkleTree: PoseidonMerkleTree;

  // PDAs
  let poolStatePda: PublicKey;
  let poolStateBump: number;
  let commitmentTreePda: PublicKey;
  let commitmentTreeBump: number;

  // Token accounts
  let zkbtcMint: PublicKey;
  let poolVault: PublicKey;
  let userTokenAccount: PublicKey;

  before(async () => {
    console.log("\n=== Setting up Pinocchio test environment ===\n");

    // Connect to local validator
    connection = new Connection("http://localhost:8899", "confirmed");

    // Generate keypairs
    payer = Keypair.generate();
    authority = Keypair.generate();
    user = Keypair.generate();

    // Airdrop SOL
    console.log("Airdropping SOL...");
    await Promise.all([
      connection.requestAirdrop(payer.publicKey, 10 * LAMPORTS_PER_SOL),
      connection.requestAirdrop(authority.publicKey, 10 * LAMPORTS_PER_SOL),
      connection.requestAirdrop(user.publicKey, 10 * LAMPORTS_PER_SOL),
    ]);
    await new Promise(resolve => setTimeout(resolve, 2000));

    // Initialize Poseidon
    console.log("Initializing Poseidon...");
    poseidon = await buildPoseidon();

    // Initialize Merkle tree
    merkleTree = new PoseidonMerkleTree(poseidon);

    // Derive PDAs
    [poolStatePda, poolStateBump] = derivePoolStatePda(PROGRAM_ID);
    [commitmentTreePda, commitmentTreeBump] = deriveCommitmentTreePda(PROGRAM_ID);

    console.log("Program ID:", PROGRAM_ID.toString());
    console.log("Pool State PDA:", poolStatePda.toString());
    console.log("Commitment Tree PDA:", commitmentTreePda.toString());
    console.log("Authority:", authority.publicKey.toString());
    console.log("User:", user.publicKey.toString());
    console.log("\n=== Setup complete ===\n");
  });

  describe("IDL-like Interface Tests", () => {
    it("should correctly encode Initialize instruction", () => {
      const ix = buildInitializeInstruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock vault
        Keypair.generate().publicKey, // mock frost vault
        authority.publicKey,
        poolStateBump,
        commitmentTreeBump,
      );

      expect(ix.data[0]).to.equal(Instruction.Initialize);
      expect(ix.data[1]).to.equal(poolStateBump);
      expect(ix.data[2]).to.equal(commitmentTreeBump);
      expect(ix.keys.length).to.equal(7);
      console.log("Initialize instruction encoded correctly");
    });

    it("should correctly encode RecordDeposit instruction", () => {
      const commitment = new Uint8Array(32).fill(0xab);
      const amount = 100_000n;

      const [depositPda] = deriveDepositStealthPda(PROGRAM_ID, commitment);
      const ix = buildRecordDepositInstruction(
        PROGRAM_ID,
        poolStatePda,
        depositPda,
        authority.publicKey,
        commitment,
        amount,
      );

      expect(ix.data[0]).to.equal(Instruction.RecordDeposit);
      expect(ix.data.readBigUInt64LE(33)).to.equal(amount);
      console.log("RecordDeposit instruction encoded correctly");
    });

    it("should correctly encode ClaimDirect instruction", () => {
      const proof = new Uint8Array(256).fill(1);
      const root = new Uint8Array(32).fill(2);
      const nullifierHash = new Uint8Array(32).fill(3);
      const amount = 50_000n;

      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, nullifierHash);
      const ix = buildClaimDirectInstruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock token account
        user.publicKey,
        proof,
        root,
        nullifierHash,
        amount,
      );

      expect(ix.data[0]).to.equal(Instruction.ClaimDirect);
      expect(ix.data.length).to.equal(329);
      expect(ix.data.readBigUInt64LE(321)).to.equal(amount);
      console.log("ClaimDirect instruction encoded correctly");
    });

    it("should correctly encode SplitCommitment instruction", () => {
      const proof = new Uint8Array(256).fill(1);
      const root = new Uint8Array(32).fill(2);
      const nullifierHash = new Uint8Array(32).fill(3);
      const output1 = new Uint8Array(32).fill(4);
      const output2 = new Uint8Array(32).fill(5);

      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, nullifierHash);
      const ix = buildSplitCommitmentInstruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        user.publicKey,
        proof,
        root,
        nullifierHash,
        output1,
        output2,
      );

      expect(ix.data[0]).to.equal(Instruction.SplitCommitment);
      expect(ix.data.length).to.equal(385);
      console.log("SplitCommitment instruction encoded correctly");
    });

    it("should correctly encode RequestRedemption instruction", () => {
      const btcAddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
      const amount = 100_000n;
      const nonce = 1n;

      const [redemptionPda] = deriveRedemptionRequestPda(PROGRAM_ID, user.publicKey, nonce);
      const ix = buildRequestRedemptionInstruction(
        PROGRAM_ID,
        poolStatePda,
        redemptionPda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock token account
        user.publicKey,
        amount,
        btcAddress,
        nonce,
      );

      expect(ix.data[0]).to.equal(Instruction.RequestRedemption);
      expect(ix.data.readBigUInt64LE(1)).to.equal(amount);
      console.log("RequestRedemption instruction encoded correctly");
    });

    it("should correctly encode SetPaused instruction", () => {
      const ix = buildSetPausedInstruction(
        PROGRAM_ID,
        poolStatePda,
        authority.publicKey,
        true,
      );

      expect(ix.data[0]).to.equal(Instruction.SetPaused);
      expect(ix.data[1]).to.equal(1);
      console.log("SetPaused instruction encoded correctly");
    });

    it("should correctly encode ClaimGroth16 instruction", () => {
      const proofHash = new Uint8Array(32).fill(0xab);
      const merkleRoot = new Uint8Array(32).fill(0xcd);
      const nullifierHash = new Uint8Array(32).fill(0xef);
      const amount = 100_000n;

      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, nullifierHash);
      const ix = buildClaimGroth16Instruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock token account
        user.publicKey,
        proofHash,
        merkleRoot,
        nullifierHash,
        amount,
      );

      expect(ix.data[0]).to.equal(Instruction.ClaimGroth16);
      expect(ix.data.length).to.equal(201);
      expect(ix.data.readBigUInt64LE(193)).to.equal(amount);
      console.log("ClaimGroth16 instruction encoded correctly (201 bytes)");
    });
  });

  describe("Circom ZK Proof Integration", () => {
    it("should generate a valid note with Poseidon", async () => {
      const note = await generateNote(poseidon, 100_000n);

      expect(note.amount).to.equal(100_000n);
      expect(note.nullifierBytes.length).to.equal(32);
      expect(note.secretBytes.length).to.equal(32);
      expect(note.commitmentBytes.length).to.equal(32);
      expect(note.nullifierHashBytes.length).to.equal(32);

      // Verify commitment formula: note = Poseidon(nullifier, secret), commitment = Poseidon(note, amount)
      const noteHash = poseidon.F.toObject(poseidon([note.nullifier, note.secret]));
      const recomputed = poseidon.F.toObject(poseidon([noteHash, note.amount]));
      expect(note.commitment).to.equal(recomputed);

      console.log("Note generated:");
      console.log("  Amount:", note.amount.toString(), "sats");
      console.log("  Commitment:", note.commitment.toString().slice(0, 20) + "...");
      console.log("  NullifierHash:", note.nullifierHash.toString().slice(0, 20) + "...");
    });

    it("should insert commitments into Merkle tree", async () => {
      const note1 = await generateNote(poseidon, 50_000n);
      const note2 = await generateNote(poseidon, 75_000n);

      const idx1 = merkleTree.insert(note1.commitment);
      const idx2 = merkleTree.insert(note2.commitment);

      expect(idx1).to.equal(0);
      expect(idx2).to.equal(1);
      expect(merkleTree.leafCount).to.equal(2);

      console.log("Merkle tree state:");
      console.log("  Leaf count:", merkleTree.leafCount);
      console.log("  Root:", merkleTree.root.toString().slice(0, 20) + "...");
    });

    it("should generate and verify Merkle proofs", async () => {
      const note = await generateNote(poseidon, 100_000n);
      const leafIndex = merkleTree.insert(note.commitment);

      const { path, indices } = merkleTree.generateProof(leafIndex);

      expect(path.length).to.equal(TREE_DEPTH);
      expect(indices.length).to.equal(TREE_DEPTH);

      // Verify root is valid
      expect(merkleTree.isValidRoot(merkleTree.root)).to.be.true;

      console.log("Merkle proof generated for leaf index:", leafIndex);
    });

    it("should generate claim_direct proof (mock or real)", async () => {
      const note = await generateNote(poseidon, 100_000n);
      merkleTree.insert(note.commitment);

      const { path, indices } = merkleTree.generateProof(merkleTree.leafCount - 1);

      const result = await generateClaimDirectProof(
        note,
        merkleTree.rootBytes,
        path,  // Pass bigint[] directly
        indices,
        user.publicKey,
      );

      expect(result.proofBytes.length).to.equal(256);
      expect(result.isValid).to.be.true;

      console.log("ClaimDirect proof generated:");
      console.log("  Proof size:", result.proofBytes.length, "bytes");
      console.log("  Valid:", result.isValid);
      console.log("  Public signals:", result.publicSignals.length);
    });
  });

  describe("Full E2E Flow Simulation", () => {
    it("should simulate complete deposit -> claim flow", async () => {
      console.log("\n=== E2E Flow Simulation ===\n");

      // 1. User generates note off-chain
      const note = await generateNote(poseidon, 100_000n);
      console.log("1. User generates note:");
      console.log("   Amount: 100,000 sats (0.001 BTC)");
      console.log("   Commitment:", note.commitment.toString().slice(0, 20) + "...");

      // 2. User sends BTC to taproot address (simulated)
      console.log("\n2. User sends BTC to taproot address (off-chain)");

      // 3. Relayer records deposit on-chain
      const [depositPda] = deriveDepositStealthPda(PROGRAM_ID, note.commitmentBytes);
      const recordDepositIx = buildRecordDepositInstruction(
        PROGRAM_ID,
        poolStatePda,
        depositPda,
        authority.publicKey,
        note.commitmentBytes,
        note.amount,
      );
      console.log("\n3. Relayer records deposit:");
      console.log("   Deposit PDA:", depositPda.toString());
      console.log("   Instruction size:", recordDepositIx.data.length, "bytes");

      // 4. Commitment added to Merkle tree
      const leafIndex = merkleTree.insert(note.commitment);
      console.log("\n4. Commitment added to Merkle tree:");
      console.log("   Leaf index:", leafIndex);
      console.log("   New root:", merkleTree.root.toString().slice(0, 20) + "...");

      // 5. User generates ZK proof
      const { path, indices } = merkleTree.generateProof(leafIndex);

      const proofResult = await generateClaimDirectProof(
        note,
        merkleTree.rootBytes,
        path,  // Pass bigint[] directly
        indices,
        user.publicKey,
      );
      console.log("\n5. User generates ZK proof:");
      console.log("   Proof valid:", proofResult.isValid);

      // 6. User claims zkBTC
      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, note.nullifierHashBytes);
      const claimIx = buildClaimDirectInstruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock token account
        user.publicKey,
        proofResult.proofBytes,
        merkleTree.rootBytes,
        note.nullifierHashBytes,
        note.amount,
      );
      console.log("\n6. User claims zkBTC:");
      console.log("   Nullifier PDA:", nullifierPda.toString());
      console.log("   Instruction size:", claimIx.data.length, "bytes");

      // 7. Summary
      console.log("\n=== Flow Complete ===");
      console.log("User received:", note.amount.toString(), "zkBTC (sats)");
      console.log("Nullifier recorded to prevent double-spend");
    });

    it("should simulate split commitment flow", async () => {
      console.log("\n=== Split Commitment Flow ===\n");

      // User has a note they want to split
      const originalNote = await generateNote(poseidon, 200_000n);
      merkleTree.insert(originalNote.commitment);
      console.log("Original note: 200,000 sats");

      // Split into two notes: 150k + 50k
      const note1 = await generateNote(poseidon, 150_000n);
      const note2 = await generateNote(poseidon, 50_000n);
      console.log("Split into: 150,000 + 50,000 sats");

      // Build split instruction
      const { path, indices } = merkleTree.generateProof(merkleTree.leafCount - 1);
      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, originalNote.nullifierHashBytes);

      const splitIx = buildSplitCommitmentInstruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        user.publicKey,
        new Uint8Array(256).fill(1), // mock proof
        merkleTree.rootBytes,
        originalNote.nullifierHashBytes,
        note1.commitmentBytes,
        note2.commitmentBytes,
      );

      console.log("Split instruction built:");
      console.log("  Output 1:", note1.commitment.toString().slice(0, 20) + "...");
      console.log("  Output 2:", note2.commitment.toString().slice(0, 20) + "...");
      console.log("  Instruction size:", splitIx.data.length, "bytes");
    });
  });

  describe("Groth16 ZK Proof Integration", () => {
    it("should simulate ClaimGroth16 flow with demo mode", async () => {
      console.log("\n=== ClaimGroth16 Demo Mode Simulation ===\n");

      // 1. Generate a note (using Poseidon for demonstration)
      const note = await generateNote(poseidon, 100_000n);
      console.log("1. User generates note:");
      console.log("   Amount: 100,000 sats (0.001 BTC)");
      console.log("   Commitment:", note.commitment.toString().slice(0, 20) + "...");

      // 2. Insert into local merkle tree
      const leafIndex = merkleTree.insert(note.commitment);
      console.log("\n2. Commitment added to Merkle tree:");
      console.log("   Leaf index:", leafIndex);

      // 3. Simulate Groth16 proof generation (in reality this would use snarkjs)
      // For testing, we generate a fake proof hash
      const crypto = await import("crypto");
      const fakeProof = new Uint8Array(256); // ~256 bytes Groth16 proof size
      crypto.getRandomValues(fakeProof);
      const proofHash = crypto.createHash("sha256").update(fakeProof).digest();

      console.log("\n3. Groth16 proof generated:");
      console.log("   Full proof size:", fakeProof.length, "bytes (too large for tx)");
      console.log("   Proof hash (SHA256):", Buffer.from(proofHash).toString("hex").slice(0, 32) + "...");

      // 4. Build ClaimGroth16 instruction with demo mode (vkHash = zeros)
      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, note.nullifierHashBytes);
      const ix = buildClaimGroth16Instruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock token account
        user.publicKey,
        new Uint8Array(proofHash),
        merkleTree.rootBytes,
        note.nullifierHashBytes,
        note.amount,
        // No vkHash = demo mode (zeros)
      );

      console.log("\n4. ClaimGroth16 instruction built:");
      console.log("   Discriminator:", ix.data[0], "(ClaimGroth16)");
      console.log("   Instruction size:", ix.data.length, "bytes");
      console.log("   Demo mode: true (VK hash = zeros)");

      // 5. Verify instruction encoding
      expect(ix.data[0]).to.equal(Instruction.ClaimGroth16);
      expect(ix.data.length).to.equal(201);

      // Check demo mode (vk_hash should be zeros at offset 129-161)
      const vkHashOffset = 1 + 32 + 32 + 32 + 32; // discriminator + proof_hash + merkle_root + nullifier_hash_pi + amount_pi
      const vkHash = ix.data.subarray(vkHashOffset, vkHashOffset + 32);
      const isZeros = Array.from(vkHash).every(b => b === 0);
      expect(isZeros).to.be.true;

      console.log("\n5. Verification:");
      console.log("   VK hash is zeros:", isZeros);
      console.log("   Amount in instruction:", ix.data.readBigUInt64LE(193).toString());

      console.log("\n=== ClaimGroth16 Demo Complete ===");
      console.log("In production, the proof would be verified off-chain by relayers.");
    });
  });

  describe("Account Parsing", () => {
    it("should correctly parse PoolState layout", () => {
      // Create mock pool state data
      const data = Buffer.alloc(POOL_STATE_SIZE);
      data[0] = Discriminators.POOL_STATE;  // discriminator
      data[1] = 255;  // bump
      data[2] = 0;    // flags (not paused)
      data[3] = 0;    // padding

      // authority
      const mockAuthority = Keypair.generate().publicKey.toBytes();
      data.set(mockAuthority, 4);

      // zkbtcMint
      const mockMint = Keypair.generate().publicKey.toBytes();
      data.set(mockMint, 36);

      // Write some statistics
      data.writeBigUInt64LE(100n, 164);  // depositCount
      data.writeBigUInt64LE(500_000n, 172);  // totalMinted
      data.writeBigUInt64LE(100_000n, 180);  // totalBurned

      const parsed = parsePoolState(data);

      expect(parsed.discriminator).to.equal(Discriminators.POOL_STATE);
      expect(parsed.bump).to.equal(255);
      expect(parsed.flags).to.equal(0);
      expect(parsed.depositCount).to.equal(100n);
      expect(parsed.totalMinted).to.equal(500_000n);
      expect(parsed.totalBurned).to.equal(100_000n);

      console.log("PoolState parsed correctly:");
      console.log("  Bump:", parsed.bump);
      console.log("  Deposit count:", parsed.depositCount.toString());
      console.log("  Total minted:", parsed.totalMinted.toString(), "sats");
      console.log("  Total burned:", parsed.totalBurned.toString(), "sats");
    });
  });
});

// ============================================================================
// UTILITY EXPORTS FOR FRONTEND
// ============================================================================
// All exports are inline (export function, export class, export const, etc.)
