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
import { BTCNetwork, BTCRelayDisc } from "./constants";
import {
  deriveBlockHeaderPDA,
  deriveHeightIndexPDA,
  deriveLightClientPDA,
  deriveVerifiedTransactionPDA,
} from "./pdas";
import { parseLightClientTipHeight } from "./state-parsing";

export {
  BTCNetwork,
  BTCRelayDisc,
  deriveBlockHeaderPDA,
  deriveHeightIndexPDA,
  deriveLightClientPDA,
  deriveVerifiedTransactionPDA,
  parseLightClientTipHeight,
};

/**
 * Compute Bitcoin block hash from raw 80-byte header (double SHA-256).
 * Returns raw hash bytes matching the on-chain double_sha256 output.
 */
export function computeBlockHash(rawHeader: Uint8Array): Uint8Array {
  const hash1 = sha256(rawHeader);
  const hash2 = sha256(hash1);
  return new Uint8Array(hash2);
}

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
  data[0] = BTCRelayDisc.EXTEND_BLOCKCHAIN;
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

export interface BuildVerifyTransactionIxArgs {
  verifiedTx: PublicKey;
  lightClient: PublicKey;
  blockHeader: PublicKey;
  heightIndex: PublicKey;
  txBuffer: PublicKey;
  payer: PublicKey;
  txid: Uint8Array;
  blockHash: Uint8Array;
  txSize: number;
  merkleProof: Uint8Array;
  btcLightClientId: PublicKey;
}

export function buildVerifyTransactionIx(args: BuildVerifyTransactionIxArgs): TransactionInstruction {
  const data = Buffer.alloc(1 + 32 + 32 + 4 + args.merkleProof.length);
  data[0] = BTCRelayDisc.VERIFY_TRANSACTION;
  Buffer.from(args.txid).copy(data, 1);
  Buffer.from(args.blockHash).copy(data, 33);
  data.writeUInt32LE(args.txSize, 65);
  Buffer.from(args.merkleProof).copy(data, 69);

  return new TransactionInstruction({
    programId: args.btcLightClientId,
    keys: [
      { pubkey: args.verifiedTx, isSigner: false, isWritable: true },
      { pubkey: args.lightClient, isSigner: false, isWritable: false },
      { pubkey: args.blockHeader, isSigner: false, isWritable: false },
      { pubkey: args.heightIndex, isSigner: false, isWritable: false },
      { pubkey: args.txBuffer, isSigner: false, isWritable: false },
      { pubkey: args.payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

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

  const existing = await connection.getAccountInfo(targetBlockHeaderPda);
  if (existing) return targetBlockHeaderPda;

  const prevHeight = targetBlockHeight - 1n;
  const grandparentHeight = prevHeight - 1n;

  const parentHashResp = await fetch(`${esploraUrl}/block-height/${Number(prevHeight)}`);
  if (!parentHashResp.ok) throw new Error(`Failed to fetch block hash at height ${prevHeight}`);
  const parentHashHex = (await parentHashResp.text()).trim();
  const parentRawHeader = await fetchBlockHeaderFn(parentHashHex, esploraUrl);
  const parentHash = computeBlockHash(new Uint8Array(parentRawHeader));

  const gpResp = await fetch(`${esploraUrl}/block-height/${Number(grandparentHeight)}`);
  if (!gpResp.ok) throw new Error(`Failed to fetch block hash at height ${grandparentHeight}`);
  const gpHashBytes = Buffer.from((await gpResp.text()).trim(), "hex");
  gpHashBytes.reverse();
  const [anchorBlockHeaderPda] = deriveBlockHeaderPDA(btcLightClientId, new Uint8Array(gpHashBytes));

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

  await sendAndConfirmTransaction(connection, new Transaction().add(extendIx), [submitter], { commitment: "confirmed" });
  return targetBlockHeaderPda;
}
