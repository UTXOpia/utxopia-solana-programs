#!/usr/bin/env bun
/**
 * SDK WASM Prover Test
 *
 * Tests the SDK prover without requiring on-chain interaction.
 * Run: bun run scripts/test-prover.ts
 */

import * as path from "path";
import { fileURLToPath } from "url";
import * as crypto from "crypto";

// Import directly from prover module to avoid React dependency
import {
  initProver,
  isProverAvailable,
  generateSpendSplitProof,
  generateClaimProof,
  setCircuitPath,
  cleanup,
  type SpendSplitInputs,
  type ClaimInputs,
} from "@utxopia/sdk/prover";

// Import poseidon for proper commitment computation
import {
  poseidon2Hash,
  computeUnifiedCommitment,
} from "@utxopia/sdk/poseidon2";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// BN254 scalar field modulus
const BN254_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

function randomFieldElement(): bigint {
  const bytes = crypto.randomBytes(32);
  return BigInt("0x" + bytes.toString("hex")) % BN254_MODULUS;
}

// Circuit tree depths (Unified Model uses 20-level tree)
const CLAIM_TREE_DEPTH = 20;
const SPLIT_TREE_DEPTH = 20;

/**
 * Create a valid merkle proof with the commitment at root
 * For testing, we put the commitment at leaf index 0 and compute the root
 */
async function createValidMerkleProof(commitment: bigint, treeDepth: number): Promise<{ siblings: bigint[]; indices: number[]; root: bigint }> {
  // Create random siblings
  const siblings: bigint[] = [];
  for (let i = 0; i < treeDepth; i++) {
    siblings.push(randomFieldElement());
  }

  // All indices are 0 (leftmost path)
  const indices = Array(treeDepth).fill(0);

  // Compute root by hashing up the tree (now async)
  let current = commitment;
  for (let i = 0; i < treeDepth; i++) {
    // For index 0, current is on the left, sibling on the right
    current = await poseidon2Hash([current, siblings[i]]);
  }

  return { siblings, indices, root: current };
}

async function testProverInit(): Promise<boolean> {
  console.log("\n[TEST] Initializing SDK WASM prover...");

  try {
    const circuitPath = path.resolve(__dirname, "../../sdk/circuits");
    console.log(`  Circuit path: ${circuitPath}`);

    setCircuitPath(circuitPath);
    await initProver();

    const available = await isProverAvailable();
    if (!available) {
      console.log("  ✗ Prover not available after init");
      return false;
    }

    console.log("  ✓ Prover initialized successfully");
    return true;
  } catch (err: any) {
    console.log(`  ✗ Error: ${err.message}`);
    return false;
  }
}

async function testClaimProof(): Promise<boolean> {
  console.log("\n[TEST] Claim proof generation (Unified Model)...");

  try {
    // Generate random private key (Baby Jubjub scalar)
    const privKey = randomFieldElement();
    // For testing, derive pubKeyX = hash(privKey) as approximation
    // In production, this would be Baby Jubjub scalar multiplication
    const pubKeyX = poseidon2Hash([privKey]);
    const amount = 100000n; // 0.001 BTC in sats
    const leafIndex = 0n;

    console.log("  Computing unified commitment: Poseidon2(pubKeyX, amount)...");

    // Compute commitment using unified model
    const commitment = computeUnifiedCommitment(pubKeyX, amount);
    console.log(`  Commitment: 0x${commitment.toString(16).slice(0, 16)}...`);

    // Create valid merkle proof (claim uses 10-level tree)
    console.log("  Creating merkle proof (10-level tree)...");
    const merkleProof = await createValidMerkleProof(commitment, CLAIM_TREE_DEPTH);
    console.log(`  Merkle root: 0x${merkleProof.root.toString(16).slice(0, 16)}...`);

    // Prepare claim inputs (Unified Model)
    const claimInputs: ClaimInputs = {
      privKey,
      pubKeyX,
      amount,
      leafIndex,
      merkleRoot: merkleProof.root,
      merkleProof: {
        siblings: merkleProof.siblings,
        indices: merkleProof.indices,
      },
    };

    console.log("  Generating claim proof (this may take a moment)...");
    const startTime = Date.now();
    const proofData = await generateClaimProof(claimInputs);
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    console.log(`  ✓ Claim proof generated in ${duration}s`);
    console.log(`  Proof size: ${proofData.proof.length} bytes`);

    return true;
  } catch (err: any) {
    console.log(`  ✗ Error: ${err.message}`);
    if (err.stack) {
      console.log(`  Stack: ${err.stack.split('\n').slice(0, 3).join('\n')}`);
    }
    return false;
  }
}

async function testSplitProof(): Promise<boolean> {
  console.log("\n[TEST] Spend Split proof generation (Unified Model)...");

  try {
    // Input note (Unified Model)
    const privKey = randomFieldElement();
    const pubKeyX = poseidon2Hash([privKey]); // Approximate pubKey derivation for testing
    const amount = 100000n; // Total amount
    const leafIndex = 0n;

    // Output 1 (new owner)
    const output1PrivKey = randomFieldElement();
    const output1PubKeyX = poseidon2Hash([output1PrivKey]);
    const output1Amount = 60000n;

    // Output 2 (change back to sender or another recipient)
    const output2PrivKey = randomFieldElement();
    const output2PubKeyX = poseidon2Hash([output2PrivKey]);
    const output2Amount = 40000n;

    console.log("  Computing commitments with Unified Model...");

    // Compute input commitment: Poseidon2(pubKeyX, amount)
    const inputCommitment = computeUnifiedCommitment(pubKeyX, amount);
    console.log(`  Input commitment: 0x${inputCommitment.toString(16).slice(0, 16)}...`);

    // Compute output commitments
    const output1Commitment = computeUnifiedCommitment(output1PubKeyX, output1Amount);
    const output2Commitment = computeUnifiedCommitment(output2PubKeyX, output2Amount);
    console.log(`  Output1 commitment: 0x${output1Commitment.toString(16).slice(0, 16)}...`);
    console.log(`  Output2 commitment: 0x${output2Commitment.toString(16).slice(0, 16)}...`);

    // Create valid merkle proof for input
    console.log(`  Creating merkle proof (${SPLIT_TREE_DEPTH}-level tree)...`);
    const merkleProof = await createValidMerkleProof(inputCommitment, SPLIT_TREE_DEPTH);

    // Prepare spend split inputs (Unified Model)
    const splitInputs: SpendSplitInputs = {
      // Input note
      privKey,
      pubKeyX,
      amount,
      leafIndex,
      merkleRoot: merkleProof.root,
      merkleProof: {
        siblings: merkleProof.siblings,
        indices: merkleProof.indices,
      },
      // Output notes (only need pubKeyX and amount)
      output1PubKeyX,
      output1Amount,
      output2PubKeyX,
      output2Amount,
    };

    console.log("  Generating spend_split proof (this may take a moment)...");
    const startTime = Date.now();
    const proofData = await generateSpendSplitProof(splitInputs);
    const duration = ((Date.now() - startTime) / 1000).toFixed(2);

    console.log(`  ✓ Split proof generated in ${duration}s`);
    console.log(`  Proof size: ${proofData.proof.length} bytes`);

    return true;
  } catch (err: any) {
    console.log(`  ✗ Error: ${err.message}`);
    if (err.stack) {
      console.log(`  Stack: ${err.stack.split('\n').slice(0, 3).join('\n')}`);
    }
    return false;
  }
}

async function main() {
  console.log("============================================================");
  console.log("SDK WASM Prover Test");
  console.log("============================================================");

  const results: { name: string; passed: boolean }[] = [];

  // Test 1: Initialize prover
  results.push({ name: "Prover initialization", passed: await testProverInit() });

  // Test 2: Generate claim proof
  results.push({ name: "Claim proof generation", passed: await testClaimProof() });

  // Test 3: Generate split proof
  results.push({ name: "Split proof generation", passed: await testSplitProof() });

  // Cleanup
  console.log("\n[CLEANUP] Releasing resources...");
  await cleanup();
  console.log("  ✓ Cleanup complete");

  // Summary
  console.log("\n============================================================");
  console.log("RESULTS");
  console.log("============================================================");

  let passed = 0;
  let failed = 0;

  for (const result of results) {
    const status = result.passed ? "✓" : "✗";
    const color = result.passed ? "\x1b[32m" : "\x1b[31m";
    console.log(`${color}${status}\x1b[0m ${result.name}`);

    if (result.passed) passed++;
    else failed++;
  }

  console.log(`\nSummary: ${passed} passed, ${failed} failed`);
  console.log("============================================================\n");

  process.exit(failed > 0 ? 1 : 0);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
