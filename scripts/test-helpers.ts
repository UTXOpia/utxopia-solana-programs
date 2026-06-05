/**
 * Shared Test Helpers
 *
 * Common utilities used by current Solana maintenance scripts:
 *   - PDA derivation functions
 *   - On-chain state parsers
 *   - ChadBuffer upload
 *   - Instruction builders (extend_blockchain; legacy request_redemption is intentionally disabled)
 *   - Authority keypair loading
 *   - Shared constants
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { sha256 } from "@noble/hashes/sha2.js";
import * as fs from "fs";
import { execSync } from "child_process";

// =============================================================================
// Constants
// =============================================================================

export const BUFFER_HEADER_SIZE = 32; // ChadBuffer authority pubkey

export const Seeds = {
  POOL_STATE: "pool_state",
  COMMITMENT_TREE: "commitment_tree",
  VK_REGISTRY: "vk_registry",
  NULLIFIER: "nullifier",
  STEALTH_ANNOUNCEMENT: "stealth",
  REDEMPTION: "redemption",
  DEPOSIT: "deposit",
  BTC_LIGHT_CLIENT: "btc_light_client",
  BLOCK_HEADER: "block",
  HEIGHT_INDEX: "height_index",
} as const;

export const BTCRelayDisc = {
  EXTEND_BLOCKCHAIN: 1,
  VERIFY_TRANSACTION: 2,
  PRUNE_OBSOLETE_BLOCKS: 3,
  REINITIALIZE: 4,
} as const;

// =============================================================================
// PDA Derivations
// =============================================================================

export function derivePoolStatePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.POOL_STATE)],
    programId,
  );
}

export function deriveCommitmentTreePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.COMMITMENT_TREE)],
    programId,
  );
}

export function deriveVkRegistryPDA(programId: PublicKey, nInputs: number, nOutputs: number): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.VK_REGISTRY), Buffer.from([nInputs]), Buffer.from([nOutputs])],
    programId,
  );
}

export function deriveNullifierPDA(programId: PublicKey, nullifierHash: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.NULLIFIER), Buffer.from(nullifierHash)],
    programId,
  );
}

export function deriveStealthAnnouncementPDA(programId: PublicKey, ephemeralPub: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.STEALTH_ANNOUNCEMENT), Buffer.from(ephemeralPub)],
    programId,
  );
}

export function deriveRedemptionPDA(programId: PublicKey, user: PublicKey, nonce: bigint): [PublicKey, number] {
  const nonceBuf = Buffer.alloc(8);
  nonceBuf.writeBigUInt64LE(nonce);
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.REDEMPTION), user.toBuffer(), nonceBuf],
    programId,
  );
}

export function deriveDepositStealthPDA(programId: PublicKey, txid: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.STEALTH_ANNOUNCEMENT), Buffer.from(txid)],
    programId,
  );
}

export function deriveLightClientPDA(btcLightClientId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.BTC_LIGHT_CLIENT)],
    btcLightClientId,
  );
}

export function deriveBlockHeaderPDA(btcLightClientId: PublicKey, blockHash: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.BLOCK_HEADER), Buffer.from(blockHash)],
    btcLightClientId,
  );
}

export function deriveHeightIndexPDA(btcLightClientId: PublicKey, height: bigint): [PublicKey, number] {
  const heightBuf = Buffer.alloc(8);
  heightBuf.writeBigUInt64LE(height);
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.HEIGHT_INDEX), heightBuf],
    btcLightClientId,
  );
}

// =============================================================================
// On-chain State Parsers
// =============================================================================

export const TREE_DEPTH = 16;

export function parseCommitmentTree(data: Buffer) {
  if (data.length < 100 || data[0] !== 0x05) return null;
  return {
    discriminator: data[0],
    bump: data[1],
    currentRoot: data.subarray(8, 40),
    nextIndex: data.readBigUInt64LE(40),
    frontier: data.subarray(48, 48 + TREE_DEPTH * 32),
  };
}

export function parseCommitmentTreeNextIndex(data: Buffer): bigint | null {
  if (data.length < 48 || data[0] !== 0x05) return null;
  return data.readBigUInt64LE(40);
}

export interface PoolSnapshot {
  totalMinted: bigint;
  totalBurned: bigint;
  pendingRedemptions: bigint;
  totalShielded: bigint;
}

export function parsePoolState(data: Buffer): PoolSnapshot | null {
  if (data.length < 268 || data[0] !== 0x01) return null;
  return {
    totalMinted: data.readBigUInt64LE(140),
    totalBurned: data.readBigUInt64LE(148),
    pendingRedemptions: data.readBigUInt64LE(156),
    totalShielded: data.readBigUInt64LE(188),
  };
}

export interface RedemptionSnapshot {
  status: number;
  requester: PublicKey;
  amountSats: bigint;
  btcAddressLen: number;
}

export function parseRedemptionRequest(data: Buffer): RedemptionSnapshot | null {
  if (data.length < 90 || data[0] !== 0x04) return null;
  return {
    status: data[1],
    requester: new PublicKey(data.subarray(16, 48)),
    amountSats: data.readBigUInt64LE(48),
    btcAddressLen: data[2],
  };
}

export function parseLightClientTipHeight(data: Buffer): bigint | null {
  if (data.length < 144 || data[0] !== 0x06) return null;
  return data.readBigUInt64LE(136);
}

// =============================================================================
// ChadBuffer Account Creation
// =============================================================================

export async function createTxBufferAccount(
  connection: Connection,
  payer: Keypair,
  rawTx: Uint8Array,
  chadbufferId: PublicKey,
): Promise<Keypair> {
  const bufferKeypair = Keypair.generate();
  const space = BUFFER_HEADER_SIZE + rawTx.length;
  const lamports = await connection.getMinimumBalanceForRentExemption(space);

  // Step 1: Create account owned by ChadBuffer
  const createIx = SystemProgram.createAccount({
    fromPubkey: payer.publicKey,
    newAccountPubkey: bufferKeypair.publicKey,
    lamports,
    space,
    programId: chadbufferId,
  });
  const createTx = new Transaction().add(createIx);
  await sendAndConfirmTransaction(connection, createTx, [payer, bufferKeypair], { commitment: "confirmed" });

  // Step 2: Init with first chunk (disc=0)
  const MAX_CHUNK = 900;
  const firstChunk = rawTx.slice(0, MAX_CHUNK);
  const initData = new Uint8Array(1 + firstChunk.length);
  initData[0] = 0; // Init discriminator
  initData.set(firstChunk, 1);

  const initIx = new TransactionInstruction({
    programId: chadbufferId,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true },
    ],
    data: Buffer.from(initData),
  });
  const initTx = new Transaction().add(initIx);
  await sendAndConfirmTransaction(connection, initTx, [payer], { commitment: "confirmed" });

  // Step 3: Write remaining chunks (disc=2) if needed
  let offset = firstChunk.length;
  while (offset < rawTx.length) {
    const chunk = rawTx.slice(offset, offset + MAX_CHUNK);
    const writeData = new Uint8Array(1 + 3 + chunk.length);
    writeData[0] = 2; // Write discriminator
    writeData[1] = offset & 0xff;
    writeData[2] = (offset >> 8) & 0xff;
    writeData[3] = (offset >> 16) & 0xff;
    writeData.set(chunk, 4);

    const writeIx = new TransactionInstruction({
      programId: chadbufferId,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true },
      ],
      data: Buffer.from(writeData),
    });
    const writeTx = new Transaction().add(writeIx);
    await sendAndConfirmTransaction(connection, writeTx, [payer], { commitment: "confirmed" });
    offset += chunk.length;
  }

  return bufferKeypair;
}

// =============================================================================
// Instruction Builders
// =============================================================================

/**
 * Compute Bitcoin block hash from raw 80-byte header (double SHA-256).
 * Returns raw hash bytes matching the on-chain double_sha256 output.
 * This is the same byte order as prev_block_hash in Bitcoin's wire format.
 */
export function computeBlockHash(rawHeader: Uint8Array): Uint8Array {
  const hash1 = sha256(rawHeader);
  const hash2 = sha256(hash1);
  return new Uint8Array(hash2);
}

/**
 * Build extend_blockchain instruction (disc=1)
 * Data: num_headers(1) + N × raw_header(80)
 *
 * Accounts:
 *   0. [writable] LightClient PDA
 *   1. [signer, writable] Submitter (payer)
 *   2. [] System program
 *   3. [] Parent BlockHeader PDA (proves anchor exists)
 *   4..4+N-1 [writable] BlockHeader PDAs (one per new header)
 *   4+N..4+2N-1 [writable] HeightIndex PDAs (one per new header)
 */
export function buildExtendBlockchainIx(
  lightClient: PublicKey,
  submitter: PublicKey,
  parentBlockHeaderPda: PublicKey,
  blockHeaderPdas: PublicKey[],
  heightIndexPdas: PublicKey[],
  rawHeaders: Uint8Array[],
  btcLightClientId: PublicKey,
): TransactionInstruction {
  const numHeaders = rawHeaders.length;
  const data = Buffer.alloc(1 + 1 + numHeaders * 80);
  data[0] = BTCRelayDisc.EXTEND_BLOCKCHAIN; // disc=1
  data[1] = numHeaders;
  for (let i = 0; i < numHeaders; i++) {
    Buffer.from(rawHeaders[i]).copy(data, 2 + i * 80);
  }

  const keys = [
    { pubkey: lightClient, isSigner: false, isWritable: true },
    { pubkey: submitter, isSigner: true, isWritable: true },
    { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    { pubkey: parentBlockHeaderPda, isSigner: false, isWritable: false },
  ];

  for (const pda of blockHeaderPdas) {
    keys.push({ pubkey: pda, isSigner: false, isWritable: true });
  }
  for (const pda of heightIndexPdas) {
    keys.push({ pubkey: pda, isSigner: false, isWritable: true });
  }

  return new TransactionInstruction({
    keys,
    programId: btcLightClientId,
    data,
  });
}

/**
 * Legacy request_redemption was removed from the UTXOPIA program.
 *
 * Discriminator 16 is now reserved and the proof-checked BTC withdrawal path is
 * the REDEEM instruction. This helper remains only to make old scripts fail with
 * a clear error instead of accidentally sending a stale opcode.
 */
export function buildRequestRedemptionIx(
  _programId: PublicKey,
  _poolState: PublicKey,
  _commitmentTree: PublicKey,
  _nullifierRecord: PublicKey,
  _redemptionRequest: PublicKey,
  _user: PublicKey,
  _params: {
    proofHash: Uint8Array;
    merkleRoot: Uint8Array;
    nullifierHash: Uint8Array;
    amountSats: bigint;
    vkHash: Uint8Array;
    btcAddress: string;
    nonce: bigint;
  },
): TransactionInstruction {
  throw new Error("request_redemption was removed; use the proof-checked REDEEM instruction instead");
}

// =============================================================================
// Header Batch Submission
// =============================================================================

/**
 * Fetch grandparent/parent/target headers from Esplora and submit them
 * via extend_blockchain. This pattern is needed because extend_blockchain
 * requires the grandparent block header PDA as an anchor.
 *
 * Returns the target block's BlockHeader PDA.
 */
export async function fetchAndSubmitHeaders(
  connection: Connection,
  submitter: Keypair,
  targetBlockHeight: bigint,
  targetRawHeader: Uint8Array,
  btcLightClientId: PublicKey,
  esploraUrl: string,
  fetchBlockHeaderFn: (hash: string, url: string) => Promise<Buffer>,
): Promise<PublicKey> {
  const [lightClient] = deriveLightClientPDA(btcLightClientId);
  const targetBlockHash = computeBlockHash(targetRawHeader);
  const [targetBlockHeaderPda] = deriveBlockHeaderPDA(btcLightClientId, targetBlockHash);

  // Check if already submitted
  const existing = await connection.getAccountInfo(targetBlockHeaderPda);
  if (existing) {
    return targetBlockHeaderPda;
  }

  const prevHeight = targetBlockHeight - 1n;
  const grandparentHeight = prevHeight - 1n;

  // Fetch parent header
  const parentHashResp = await fetch(`${esploraUrl}/block-height/${Number(prevHeight)}`);
  if (!parentHashResp.ok) throw new Error(`Failed to fetch block hash at height ${prevHeight}`);
  const parentHashHex = (await parentHashResp.text()).trim();
  const parentRawHeader = await fetchBlockHeaderFn(parentHashHex, esploraUrl);
  const parentHash = computeBlockHash(new Uint8Array(parentRawHeader));

  // Fetch grandparent hash (anchor) -- only need the hash, not the raw header
  const gpResp = await fetch(`${esploraUrl}/block-height/${Number(grandparentHeight)}`);
  if (!gpResp.ok) throw new Error(`Failed to fetch block hash at height ${grandparentHeight}`);
  const gpHashHex = (await gpResp.text()).trim();
  const gpHashBytes = Buffer.from(gpHashHex, "hex");
  gpHashBytes.reverse(); // display order -> internal byte order
  const [anchorBlockHeaderPda] = deriveBlockHeaderPDA(btcLightClientId, new Uint8Array(gpHashBytes));

  // Derive PDAs for the 2 new headers
  const [parentBlockHeaderPda] = deriveBlockHeaderPDA(btcLightClientId, parentHash);
  const [parentHeightIndexPda] = deriveHeightIndexPDA(btcLightClientId, prevHeight);
  const [targetHeightIndexPda] = deriveHeightIndexPDA(btcLightClientId, targetBlockHeight);

  const extendIx = buildExtendBlockchainIx(
    lightClient,
    submitter.publicKey,
    anchorBlockHeaderPda,
    [parentBlockHeaderPda, targetBlockHeaderPda],
    [parentHeightIndexPda, targetHeightIndexPda],
    [new Uint8Array(parentRawHeader), targetRawHeader],
    btcLightClientId,
  );

  const tx = new Transaction().add(extendIx);
  await sendAndConfirmTransaction(connection, tx, [submitter], { commitment: "confirmed" });

  return targetBlockHeaderPda;
}

// =============================================================================
// Authority Keypair Loading
// =============================================================================

export function loadAuthorityKeypair(): Keypair {
  const keypairPath = process.env.KEYPAIR || `${process.env.HOME}/.config/solana/id.json`;
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(keypairPath, "utf-8"))),
  );
}
