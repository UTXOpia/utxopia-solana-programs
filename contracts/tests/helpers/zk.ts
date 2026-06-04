import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";
import * as snarkjs from "snarkjs";
import { PublicKey } from "@solana/web3.js";

// Reuse the same TREE_DEPTH used on-chain.
import { TREE_DEPTH } from "./pda";

// Type returned by circomlibjs Poseidon builder.
// We only need the shape for tests, so we keep this local.
export type Poseidon = Awaited<
  ReturnType<typeof import("circomlibjs").buildPoseidon>
>;

// Circuit paths are external in the split-repo layout.
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const CIRCUIT_DIR = path.resolve(
  process.env.UTXOPIA_CIRCUITS_DIR ?? path.resolve(__dirname, "../../../../utxopia-circuits/circuits"),
  "build",
);
const CLAIM_WASM = path.join(CIRCUIT_DIR, "claim_direct_js/claim_direct.wasm");
const CLAIM_ZKEY = path.join(CIRCUIT_DIR, "claim_direct_final.zkey");
const CLAIM_VK = path.join(CIRCUIT_DIR, "claim_direct_vk.json");

// BN254 field prime
const FIELD_PRIME =
  21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Note structure for shielded amounts.
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
 * Convert bigint to 32-byte Uint8Array (big-endian).
 */
export function bigintToBytes(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let temp = value;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

/**
 * Convert Uint8Array to bigint (big-endian).
 */
export function bytesToBigint(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Generate random field element.
 */
export function randomFieldElement(): bigint {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytesToBigint(bytes) % FIELD_PRIME;
}

/**
 * Generate a note with Poseidon hashing.
 *
 * Circuit structure:
 *   note = Poseidon(nullifier, secret)
 *   commitment = Poseidon(note, amount)
 *   nullifierHash = Poseidon(nullifier)
 */
export async function generateNote(
  poseidon: Poseidon,
  amountSats: bigint,
): Promise<Note> {
  const nullifier = randomFieldElement();
  const secret = randomFieldElement();

  const note = poseidon.F.toObject(poseidon([nullifier, secret]));
  const commitment = poseidon.F.toObject(poseidon([note, amountSats]));
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
 * Groth16 proof result.
 */
export interface Groth16ProofResult {
  proofBytes: Uint8Array; // 256 bytes
  publicSignals: string[];
  isValid: boolean;
}

/**
 * Generate claim_direct proof.
 *
 * Circuit public inputs: root, nullifierHash, amount, recipient.
 * Circuit private inputs: nullifier, secret, pathElements[TREE_DEPTH], pathIndices[TREE_DEPTH].
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

  // Convert recipient pubkey to field element (take first 31 bytes to stay in field).
  const recipientBytes = recipient.toBytes();
  const recipientField = bytesToBigint(recipientBytes.slice(0, 31));

  const input = {
    root: bytesToBigint(merkleRoot).toString(),
    nullifierHash: note.nullifierHash.toString(),
    amount: note.amount.toString(),
    recipient: recipientField.toString(),
    nullifier: note.nullifier.toString(),
    secret: note.secret.toString(),
    pathElements: merklePath.map((p) => p.toString()),
    pathIndices: merkleIndices,
  };

  console.log("  Generating real Groth16 proof...");
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    input,
    CLAIM_WASM,
    CLAIM_ZKEY,
  );

  const proofBytes = groth16ProofToBytes(proof);

  // Verify locally.
  const vk = JSON.parse(fs.readFileSync(CLAIM_VK, "utf8"));
  const isValid = await snarkjs.groth16.verify(vk, publicSignals, proof);

  console.log("  Proof generated and verified:", isValid);

  return { proofBytes, publicSignals, isValid };
}

/**
 * Convert snarkjs Groth16 proof to 256 bytes.
 */
export function groth16ProofToBytes(
  proof: snarkjs.Groth16Proof,
): Uint8Array {
  const bytes = new Uint8Array(256);

  // A point (G1) - 64 bytes.
  const aX = hexPadStart(BigInt(proof.pi_a[0]).toString(16), 64);
  const aY = hexPadStart(BigInt(proof.pi_a[1]).toString(16), 64);
  bytes.set(hexToBytes(aX), 0);
  bytes.set(hexToBytes(aY), 32);

  // B point (G2) - 128 bytes (note: snarkjs uses different coordinate order).
  const bX1 = hexPadStart(BigInt(proof.pi_b[0][1]).toString(16), 64);
  const bX2 = hexPadStart(BigInt(proof.pi_b[0][0]).toString(16), 64);
  const bY1 = hexPadStart(BigInt(proof.pi_b[1][1]).toString(16), 64);
  const bY2 = hexPadStart(BigInt(proof.pi_b[1][0]).toString(16), 64);
  bytes.set(hexToBytes(bX1), 64);
  bytes.set(hexToBytes(bX2), 96);
  bytes.set(hexToBytes(bY1), 128);
  bytes.set(hexToBytes(bY2), 160);

  // C point (G1) - 64 bytes.
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

export { TREE_DEPTH };
