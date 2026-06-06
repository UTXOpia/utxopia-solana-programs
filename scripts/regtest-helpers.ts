/**
 * Bitcoin Regtest Helpers
 *
 * Utilities for managing a regtest Bitcoin node via the blockstream/esplora
 * Docker container and interacting with it through the Esplora REST API
 * and bitcoin-cli.
 */

import { execSync, spawnSync } from "child_process";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PROJECT_ROOT = path.resolve(__dirname, "../..");
const COMPOSE_FILE = path.join(PROJECT_ROOT, "docker-compose.regtest.yml");
const CONTAINER_NAME = "utxopia-esplora-regtest";

const DEFAULT_ESPLORA_URL = "http://localhost:3002/regtest/api";

// bitcoin-cli path inside the blockstream/esplora container
let bitcoinCliPath = "/srv/explorer/bitcoin/bin/bitcoin-cli";

// =============================================================================
// Docker lifecycle
// =============================================================================

export function startRegtestDocker(): void {
  console.log("  Starting regtest Docker (blockstream/esplora)...");
  execSync(`docker compose -f ${COMPOSE_FILE} up -d`, {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
}

export function stopRegtestDocker(): void {
  console.log("  Stopping regtest Docker...");
  execSync(`docker compose -f ${COMPOSE_FILE} down`, {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
}

// =============================================================================
// Wait for services
// =============================================================================

export async function waitForEsplora(
  baseUrl: string = DEFAULT_ESPLORA_URL,
  timeoutMs: number = 120_000,
): Promise<void> {
  const start = Date.now();
  const url = `${baseUrl}/blocks/tip/height`;
  console.log(`  Waiting for Esplora API at ${url}...`);
  while (Date.now() - start < timeoutMs) {
    try {
      const resp = await fetch(url);
      if (resp.ok) {
        const height = await resp.text();
        console.log(`  Esplora ready — tip height: ${height}`);
        return;
      }
    } catch {
      // not ready yet
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  throw new Error(`Esplora did not become ready within ${timeoutMs}ms`);
}

// =============================================================================
// bitcoin-cli wrapper
// =============================================================================

function detectBitcoinCliPath(): void {
  // Try the default path first, then fallback to searching
  const result = spawnSync("docker", [
    "exec", CONTAINER_NAME, "which", "bitcoin-cli",
  ], { encoding: "utf-8", timeout: 10_000 });
  if (result.status === 0 && result.stdout.trim()) {
    bitcoinCliPath = result.stdout.trim();
  }
  // else keep default
}

export function bitcoinCli(args: string): string {
  const cmd = `docker exec ${CONTAINER_NAME} ${bitcoinCliPath} -regtest -datadir=/data/bitcoin -rpcwallet=test ${args}`;
  const result = execSync(cmd, { encoding: "utf-8", timeout: 30_000, maxBuffer: 50 * 1024 * 1024 });
  return result.trim();
}

// =============================================================================
// Wallet & Mining
// =============================================================================

export function createWallet(): void {
  try {
    bitcoinCli("createwallet test");
    console.log("  Created regtest wallet 'test'");
  } catch (err: any) {
    if (err.message?.includes("already exists")) {
      // Try loading it instead
      try {
        bitcoinCli("loadwallet test");
      } catch {
        // Already loaded
      }
      console.log("  Wallet 'test' already exists");
    } else {
      throw err;
    }
  }
}

export function getNewAddress(type: string = "bech32"): string {
  return bitcoinCli(`getnewaddress '' ${type}`);
}

export function mineBlocks(n: number, address?: string): string[] {
  const addr = address || getNewAddress();
  const result = bitcoinCli(`generatetoaddress ${n} ${addr}`);
  // Returns JSON array of block hashes
  return JSON.parse(result) as string[];
}

// =============================================================================
// Transaction creation
// =============================================================================

/**
 * Create a Bitcoin transaction with:
 *   - Output 0: payment to `toAddress` for `amountSats`
 *   - Output 1: OP_RETURN with `payload` (hex-encoded)
 *
 * Uses createrawtransaction + fundrawtransaction + signrawtransactionwithwallet + sendrawtransaction.
 */
export function createOpReturnTx(
  toAddress: string,
  amountSats: number,
  payloadHex: string,
): string {
  const amountBtc = (amountSats / 1e8).toFixed(8);

  // Step 1: Create raw transaction with outputs only (no inputs — fundrawtx will add them)
  const outputsJson = JSON.stringify([
    { [toAddress]: parseFloat(amountBtc) },
    { data: payloadHex },
  ]);
  const rawHex = bitcoinCli(`createrawtransaction '[]' '${outputsJson}'`);

  // Step 2: Fund the transaction (adds inputs + change)
  const fundResultJson = bitcoinCli(`fundrawtransaction ${rawHex}`);
  const fundResult = JSON.parse(fundResultJson);
  const fundedHex: string = fundResult.hex;

  // Step 3: Sign
  const signResultJson = bitcoinCli(`signrawtransactionwithwallet ${fundedHex}`);
  const signResult = JSON.parse(signResultJson);
  if (!signResult.complete) {
    throw new Error(`Failed to sign transaction: ${JSON.stringify(signResult.errors)}`);
  }
  const signedHex: string = signResult.hex;

  // Step 4: Broadcast
  const txid = bitcoinCli(`sendrawtransaction ${signedHex}`);
  console.log(`  Broadcast tx: ${txid}`);
  return txid;
}

// =============================================================================
// Esplora REST API helpers
// =============================================================================

export async function waitForTxIndexed(
  txid: string,
  baseUrl: string = DEFAULT_ESPLORA_URL,
  timeoutMs: number = 60_000,
): Promise<void> {
  const start = Date.now();
  const url = `${baseUrl}/tx/${txid}/status`;
  while (Date.now() - start < timeoutMs) {
    try {
      const resp = await fetch(url);
      if (resp.ok) {
        const status = await resp.json() as { confirmed: boolean; block_height?: number };
        if (status.confirmed) {
          console.log(`  Tx ${txid.slice(0, 16)}... confirmed at height ${status.block_height}`);
          return;
        }
      }
    } catch {
      // not indexed yet
    }
    await new Promise((r) => setTimeout(r, 2000));
  }
  throw new Error(`Tx ${txid} not confirmed within ${timeoutMs}ms`);
}

export async function fetchBlockHeader(
  blockHash: string,
  baseUrl: string = DEFAULT_ESPLORA_URL,
): Promise<Buffer> {
  const resp = await fetch(`${baseUrl}/block/${blockHash}/header`);
  if (!resp.ok) throw new Error(`Failed to fetch block header: ${resp.status}`);
  const hex = await resp.text();
  return Buffer.from(hex, "hex");
}

export async function fetchMerkleProof(
  txid: string,
  baseUrl: string = DEFAULT_ESPLORA_URL,
): Promise<{ merkle: string[]; pos: number; block_height: number }> {
  const resp = await fetch(`${baseUrl}/tx/${txid}/merkle-proof`);
  if (!resp.ok) throw new Error(`Failed to fetch merkle proof: ${resp.status}`);
  return (await resp.json()) as { merkle: string[]; pos: number; block_height: number };
}

export async function fetchRawTx(
  txid: string,
  baseUrl: string = DEFAULT_ESPLORA_URL,
): Promise<Buffer> {
  const resp = await fetch(`${baseUrl}/tx/${txid}/hex`);
  if (!resp.ok) throw new Error(`Failed to fetch raw tx: ${resp.status}`);
  const hex = await resp.text();
  return Buffer.from(hex, "hex");
}

export async function fetchTipHeight(
  baseUrl: string = DEFAULT_ESPLORA_URL,
): Promise<number> {
  const resp = await fetch(`${baseUrl}/blocks/tip/height`);
  if (!resp.ok) throw new Error(`Failed to fetch tip height: ${resp.status}`);
  return parseInt(await resp.text(), 10);
}

export async function fetchTipHash(
  baseUrl: string = DEFAULT_ESPLORA_URL,
): Promise<string> {
  const resp = await fetch(`${baseUrl}/blocks/tip/hash`);
  if (!resp.ok) throw new Error(`Failed to fetch tip hash: ${resp.status}`);
  return (await resp.text()).trim();
}

export async function fetchBlockHash(
  height: number,
  baseUrl: string = DEFAULT_ESPLORA_URL,
): Promise<string> {
  const resp = await fetch(`${baseUrl}/block-height/${height}`);
  if (!resp.ok) throw new Error(`Failed to fetch block hash at height ${height}: ${resp.status}`);
  return (await resp.text()).trim();
}

export async function fetchTxStatus(
  txid: string,
  baseUrl: string = DEFAULT_ESPLORA_URL,
): Promise<{ confirmed: boolean; block_height?: number; block_hash?: string }> {
  const resp = await fetch(`${baseUrl}/tx/${txid}/status`);
  if (!resp.ok) throw new Error(`Failed to fetch tx status: ${resp.status}`);
  return (await resp.json()) as any;
}

// =============================================================================
// Segwit stripping — produce non-witness serialization for correct txid hashing
// =============================================================================

/**
 * Strip witness data from a segwit-serialized raw transaction.
 *
 * Segwit format:  version(4) + marker(1:0x00) + flag(1:0x01) + inputs + outputs + witness + locktime(4)
 * Non-witness txid serialization: version(4) + inputs + outputs + locktime(4)
 *
 * The on-chain compute_tx_hash does double_sha256(raw_tx), so we must provide
 * the non-witness serialization for segwit txs to get the correct txid.
 */
export function stripWitnessData(rawTx: Buffer): Buffer {
  // Check for segwit marker: byte 4 == 0x00 and byte 5 == 0x01
  if (rawTx[4] !== 0x00 || rawTx[5] !== 0x01) {
    // Already non-witness serialized.
    return rawTx;
  }

  const result: Buffer[] = [];

  // version (4 bytes)
  result.push(rawTx.subarray(0, 4));

  // Skip marker (0x00) and flag (0x01), parse from byte 6
  let off = 6;

  // Read varint helper
  function readVarint(): { value: number; bytes: number } {
    const first = rawTx[off];
    if (first < 0xfd) return { value: first, bytes: 1 };
    if (first === 0xfd) {
      return { value: rawTx.readUInt16LE(off + 1), bytes: 3 };
    }
    if (first === 0xfe) {
      return { value: rawTx.readUInt32LE(off + 1), bytes: 5 };
    }
    throw new Error("64-bit varint not supported");
  }

  // Input count
  const inputCountStart = off;
  const inputCount = readVarint();
  off += inputCount.bytes;

  // Read all inputs: prevhash(32) + previndex(4) + scriptSig(varint+data) + sequence(4)
  for (let i = 0; i < inputCount.value; i++) {
    off += 36; // prevhash + previndex
    const scriptLen = readVarint();
    off += scriptLen.bytes + scriptLen.value;
    off += 4; // sequence
  }

  // Output count
  const outputCountStart = off;
  const outputCount = readVarint();
  off += outputCount.bytes;

  // Read all outputs: value(8) + scriptPubKey(varint+data)
  for (let i = 0; i < outputCount.value; i++) {
    off += 8; // value
    const scriptLen = readVarint();
    off += scriptLen.bytes + scriptLen.value;
  }

  // Everything from inputCountStart to off is inputs+outputs (with their varints)
  result.push(rawTx.subarray(inputCountStart, off));

  // Skip witness data (off currently points to start of witness)
  // For each input, read witness stack
  for (let i = 0; i < inputCount.value; i++) {
    const stackItems = readVarint();
    off += stackItems.bytes;
    for (let j = 0; j < stackItems.value; j++) {
      const itemLen = readVarint();
      off += itemLen.bytes + itemLen.value;
    }
  }

  // locktime (last 4 bytes)
  result.push(rawTx.subarray(off, off + 4));

  return Buffer.concat(result);
}

// =============================================================================
// Serialization helpers for on-chain merkle proof format
// =============================================================================

/**
 * Serialize an Esplora merkle proof into the on-chain format expected by
 * the BTC light client's complete_deposit instruction.
 *
 * On-chain format:
 *   txid       (32 bytes) — internal byte order
 *   path_bits  (4 bytes LE) — tx position bit decomposition
 *   path_len   (1 byte) — number of sibling hashes
 *   tx_index   (4 bytes LE) — position of tx in block
 *   hashes     (32 * path_len bytes) — sibling hashes (internal byte order)
 */
export function serializeMerkleProof(
  txid: string,
  proof: { merkle: string[]; pos: number },
): Buffer {
  const pathLen = proof.merkle.length;
  const bufLen = 32 + 4 + 1 + 4 + 32 * pathLen;
  const buf = Buffer.alloc(bufLen);
  let off = 0;

  // txid in internal byte order (reverse of display hex)
  const txidBytes = Buffer.from(txid, "hex");
  txidBytes.reverse();
  txidBytes.copy(buf, off);
  off += 32;

  // path_bits (== pos)
  buf.writeUInt32LE(proof.pos, off);
  off += 4;

  // path_len
  buf[off++] = pathLen;

  // tx_index (== pos)
  buf.writeUInt32LE(proof.pos, off);
  off += 4;

  // sibling hashes — Esplora returns them in display (reversed) byte order,
  // so we must reverse each to internal byte order for on-chain verification
  for (const hashHex of proof.merkle) {
    const hashBytes = Buffer.from(hashHex, "hex");
    hashBytes.reverse();
    hashBytes.copy(buf, off);
    off += 32;
  }

  return buf;
}

// =============================================================================
// Setup helper (combines multiple steps)
// =============================================================================

/**
 * Full regtest setup:
 * 1. Start Docker
 * 2. Wait for Esplora
 * 3. Detect bitcoin-cli path
 * 4. Create wallet
 * 5. Mine 101 blocks for coinbase maturity
 *
 * Returns the block hash at height 101.
 */
export async function setupRegtest(): Promise<{
  tipHeight: number;
  tipHash: string;
}> {
  startRegtestDocker();
  await waitForEsplora();
  detectBitcoinCliPath();
  createWallet();

  console.log("  Mining 101 blocks for coinbase maturity...");
  mineBlocks(101);

  // Wait for Esplora to index
  await new Promise((r) => setTimeout(r, 5000));

  const tipHeight = await fetchTipHeight();
  const tipHash = await fetchTipHash();
  console.log(`  Regtest tip: height=${tipHeight}, hash=${tipHash.slice(0, 16)}...`);

  return { tipHeight, tipHash };
}
