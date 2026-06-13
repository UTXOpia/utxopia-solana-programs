import {
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID } from "@solana/spl-token";
import { createTxBufferAccount } from "./chadbuffer";
import { createSolanaTestContext } from "./solana-context";
import {
  fetchBlockHash,
  fetchBlockHeader,
  fetchMerkleProof,
  fetchRawTx,
  fetchTxStatus,
  serializeMerkleProof,
  stripWitnessData,
} from "./bitcoin-regtest";
import {
  buildVerifyTransactionIx,
  computeBlockHash,
  deriveBlockHeaderPDA,
  deriveHeightIndexPDA,
  deriveLightClientPDA,
  deriveVerifiedTransactionPDA,
  fetchAndSubmitHeaders,
} from "./light-client";
import {
  deriveDepositIntentPDA,
  deriveDepositReceiptPDA,
  deriveDepositStealthPDA,
  derivePoolConfigPDA,
  deriveStealthAnnouncementPDA,
  deriveTokenConfigPDA,
  deriveUtxoRecordPDA,
} from "./pdas";

export const UTXOPIA_DISC = {
  COMPLETE_DEPOSIT: 11,
  REGISTER_DEPOSIT_INTENT: 24,
  VERIFY_DEPOSIT: 25,
} as const;

export interface CommonDepositAccounts {
  utxopiaProgramId: PublicKey;
  poolState: PublicKey;
  verifiedTx: PublicKey;
  lightClient: PublicKey;
  commitmentTree: PublicKey;
  sweepTxBuffer: PublicKey;
  authority: PublicKey;
  zkbtcMint: PublicKey;
  poolVault: PublicKey;
  tokenProgram?: PublicKey;
  depositReceipt: PublicKey;
  tokenConfig: PublicKey;
  poolConfig: PublicKey;
  depositTxBuffer: PublicKey;
}

export interface BuildCompleteDepositIxArgs extends CommonDepositAccounts {
  depositTxid: Uint8Array;
  sweepTxid: Uint8Array;
  blockHeight: bigint;
  sweepTxSize: number;
  depositTxSize: number;
  sweepVout: number;
}

export interface BuildVerifyDepositIxArgs extends CommonDepositAccounts {
  depositIntent: PublicKey;
  depositTxid: Uint8Array;
  sweepTxid: Uint8Array;
  blockHeight: bigint;
  sweepTxSize: number;
  depositTxSize: number;
}

export interface BuildRegisterDepositIntentIxArgs {
  utxopiaProgramId: PublicKey;
  authority: PublicKey;
  depositIntent: PublicKey;
  ephemeralPubkey: Uint8Array;
  npk: Uint8Array;
}

export interface RelayDepositCliOptions {
  mode?: "complete" | "verify";
  txid?: string;
  sweepTxid?: string;
  depositTxid?: string;
  blockHash?: string;
  blockHeight?: number;
  sweepVout?: number;
  zkbtcMint?: string;
  poolVault?: string;
  tokenProgram?: string;
  poolConfig?: string;
  depositIntent?: string;
  npk?: string;
  ephemeralPubkey?: string;
  esploraUrl?: string;
  submitHeaders?: boolean;
}

const DEFAULT_ESPLORA_URL = "http://localhost:3002/regtest/api";

function hexToInternal32(label: string, hex: string): Buffer {
  const clean = hex.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(clean)) {
    throw new Error(`${label} must be a 32-byte hex string`);
  }
  return Buffer.from(clean, "hex").reverse();
}

function hexToBytes(label: string, hex: string, length: number): Buffer {
  const clean = hex.replace(/^0x/, "");
  const bytes = Buffer.from(clean, "hex");
  if (bytes.length !== length) throw new Error(`${label} must be ${length} bytes`);
  return bytes;
}

function requiredPublicKey(label: string, value: string | undefined): PublicKey {
  if (!value) throw new Error(`${label} is required`);
  return new PublicKey(value);
}

function writeU64LE(buf: Buffer, value: bigint, offset: number): void {
  if (value < 0n || value > 0xffff_ffff_ffff_ffffn) {
    throw new Error(`u64 out of range: ${value}`);
  }
  buf.writeBigUInt64LE(value, offset);
}

export function buildRegisterDepositIntentIx(args: BuildRegisterDepositIntentIxArgs): TransactionInstruction {
  if (args.ephemeralPubkey.length !== 32) throw new Error("ephemeralPubkey must be 32 bytes");
  if (args.npk.length !== 32) throw new Error("npk must be 32 bytes");

  const data = Buffer.alloc(1 + 64);
  data[0] = UTXOPIA_DISC.REGISTER_DEPOSIT_INTENT;
  Buffer.from(args.ephemeralPubkey).copy(data, 1);
  Buffer.from(args.npk).copy(data, 33);

  return new TransactionInstruction({
    programId: args.utxopiaProgramId,
    keys: [
      { pubkey: args.authority, isSigner: true, isWritable: true },
      { pubkey: args.depositIntent, isSigner: false, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export function buildCompleteDepositIx(args: BuildCompleteDepositIxArgs): TransactionInstruction {
  const data = Buffer.alloc(1 + 80);
  data[0] = UTXOPIA_DISC.COMPLETE_DEPOSIT;
  Buffer.from(args.sweepTxid).copy(data, 1);
  writeU64LE(data, args.blockHeight, 33);
  data.writeUInt32LE(args.sweepTxSize, 41);
  data.writeUInt32LE(args.depositTxSize, 45);
  Buffer.from(args.depositTxid).copy(data, 49);

  const utxoRecord = deriveUtxoRecordPDA(args.utxopiaProgramId, args.sweepTxid, args.sweepVout)[0];

  return new TransactionInstruction({
    programId: args.utxopiaProgramId,
    keys: [
      { pubkey: args.poolState, isSigner: false, isWritable: true },
      { pubkey: args.verifiedTx, isSigner: false, isWritable: false },
      { pubkey: args.lightClient, isSigner: false, isWritable: false },
      { pubkey: args.commitmentTree, isSigner: false, isWritable: true },
      { pubkey: args.sweepTxBuffer, isSigner: false, isWritable: false },
      { pubkey: args.authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: args.zkbtcMint, isSigner: false, isWritable: true },
      { pubkey: args.poolVault, isSigner: false, isWritable: true },
      { pubkey: args.tokenProgram ?? TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: args.depositTxBuffer, isSigner: false, isWritable: false },
      { pubkey: args.depositReceipt, isSigner: false, isWritable: true },
      { pubkey: utxoRecord, isSigner: false, isWritable: true },
      { pubkey: args.tokenConfig, isSigner: false, isWritable: true },
      { pubkey: args.poolConfig, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export function buildVerifyDepositIx(args: BuildVerifyDepositIxArgs): TransactionInstruction {
  const data = Buffer.alloc(1 + 80);
  data[0] = UTXOPIA_DISC.VERIFY_DEPOSIT;
  Buffer.from(args.sweepTxid).copy(data, 1);
  writeU64LE(data, args.blockHeight, 33);
  data.writeUInt32LE(args.sweepTxSize, 41);
  Buffer.from(args.depositTxid).copy(data, 45);
  data.writeUInt32LE(args.depositTxSize, 77);

  return new TransactionInstruction({
    programId: args.utxopiaProgramId,
    keys: [
      { pubkey: args.poolState, isSigner: false, isWritable: true },
      { pubkey: args.verifiedTx, isSigner: false, isWritable: false },
      { pubkey: args.lightClient, isSigner: false, isWritable: false },
      { pubkey: args.commitmentTree, isSigner: false, isWritable: true },
      { pubkey: args.sweepTxBuffer, isSigner: false, isWritable: false },
      { pubkey: args.authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: args.zkbtcMint, isSigner: false, isWritable: true },
      { pubkey: args.poolVault, isSigner: false, isWritable: true },
      { pubkey: args.tokenProgram ?? TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: args.depositIntent, isSigner: false, isWritable: true },
      { pubkey: args.depositReceipt, isSigner: false, isWritable: true },
      { pubkey: args.tokenConfig, isSigner: false, isWritable: true },
      { pubkey: args.poolConfig, isSigner: false, isWritable: false },
      { pubkey: args.depositTxBuffer, isSigner: false, isWritable: false },
    ],
    data,
  });
}

export async function relayDepositCli(options: RelayDepositCliOptions): Promise<void> {
  const mode = options.mode ?? "complete";
  const sweepTxidDisplay = options.sweepTxid ?? options.txid;
  if (!sweepTxidDisplay) throw new Error("Provide --txid or --sweep-txid");

  const depositTxidDisplay = options.depositTxid ?? sweepTxidDisplay;
  const directToPool = depositTxidDisplay === sweepTxidDisplay;
  const esploraUrl = options.esploraUrl ?? DEFAULT_ESPLORA_URL;
  const ctx = createSolanaTestContext();
  const zkbtcMint = requiredPublicKey("--zkbtc-mint", options.zkbtcMint);
  const poolVault = requiredPublicKey("--pool-vault", options.poolVault);
  const tokenProgram = options.tokenProgram ? new PublicKey(options.tokenProgram) : TOKEN_2022_PROGRAM_ID;
  const poolConfig = options.poolConfig ? new PublicKey(options.poolConfig) : derivePoolConfigPDA(ctx.programs.utxopiaProgramId)[0];
  const tokenConfig = deriveTokenConfigPDA(ctx.programs.utxopiaProgramId, zkbtcMint)[0];

  const sweepStatus = await fetchTxStatus(sweepTxidDisplay, esploraUrl);
  if (!sweepStatus.confirmed) throw new Error(`Sweep tx is not confirmed: ${sweepTxidDisplay}`);
  const blockHeight = BigInt(options.blockHeight ?? sweepStatus.block_height ?? 0);
  if (blockHeight === 0n) throw new Error("Unable to determine block height; pass --block-height");
  const blockHashDisplay = options.blockHash ?? sweepStatus.block_hash ?? await fetchBlockHash(Number(blockHeight), esploraUrl);

  const sweepTxid = hexToInternal32("sweep txid", sweepTxidDisplay);
  const depositTxid = hexToInternal32("deposit txid", depositTxidDisplay);
  const blockHash = hexToInternal32("block hash", blockHashDisplay);

  const sweepRaw = stripWitnessData(await fetchRawTx(sweepTxidDisplay, esploraUrl));
  const sweepTxBuffer = await createTxBufferAccount(ctx.connection, ctx.payer, sweepRaw, ctx.programs.chadbufferProgramId ?? requiredPublicKey("CHADBUFFER_PROGRAM_ID", undefined));

  let depositRaw: Buffer<ArrayBufferLike> = Buffer.alloc(0);
  let depositTxBuffer = sweepTxBuffer;
  if (!directToPool || mode === "verify") {
    depositRaw = stripWitnessData(await fetchRawTx(depositTxidDisplay, esploraUrl));
    depositTxBuffer = await createTxBufferAccount(ctx.connection, ctx.payer, depositRaw, ctx.programs.chadbufferProgramId ?? requiredPublicKey("CHADBUFFER_PROGRAM_ID", undefined));
  }

  if (options.submitHeaders) {
    const rawHeader = await fetchBlockHeader(blockHashDisplay, esploraUrl);
    await fetchAndSubmitHeaders(
      ctx.connection,
      ctx.payer,
      blockHeight,
      new Uint8Array(rawHeader),
      ctx.programs.btcLightClientProgramId,
      esploraUrl,
      fetchBlockHeader,
    );
  }

  const merkleProof = serializeMerkleProof(sweepTxidDisplay, await fetchMerkleProof(sweepTxidDisplay, esploraUrl));
  const [verifiedTx] = deriveVerifiedTransactionPDA(ctx.programs.btcLightClientProgramId, blockHash, sweepTxid);
  const [blockHeader] = deriveBlockHeaderPDA(ctx.programs.btcLightClientProgramId, blockHash);
  const [heightIndex] = deriveHeightIndexPDA(ctx.programs.btcLightClientProgramId, blockHeight);
  const [lightClient] = deriveLightClientPDA(ctx.programs.btcLightClientProgramId);

  const verifyTxIx = buildVerifyTransactionIx({
    verifiedTx,
    lightClient,
    blockHeader,
    heightIndex,
    txBuffer: sweepTxBuffer.publicKey,
    payer: ctx.payer.publicKey,
    txid: sweepTxid,
    blockHash,
    txSize: sweepRaw.length,
    merkleProof,
    btcLightClientId: ctx.programs.btcLightClientProgramId,
  });
  const verifyTxSig = await sendAndConfirmTransaction(ctx.connection, new Transaction().add(verifyTxIx), [ctx.payer], { commitment: "confirmed" });
  console.log(`Verified BTC transaction PDA: ${verifiedTx.toBase58()}`);
  console.log(`verify_transaction signature: ${verifyTxSig}`);

  const depositReceipt = deriveDepositReceiptPDA(ctx.programs.utxopiaProgramId, depositTxid)[0];
  const common = {
    utxopiaProgramId: ctx.programs.utxopiaProgramId,
    poolState: ctx.pdas.poolState,
    verifiedTx,
    lightClient,
    commitmentTree: ctx.pdas.commitmentTree,
    sweepTxBuffer: sweepTxBuffer.publicKey,
    authority: ctx.payer.publicKey,
    zkbtcMint,
    poolVault,
    tokenProgram,
    depositReceipt,
    tokenConfig,
    poolConfig,
    depositTxBuffer: depositTxBuffer.publicKey,
  };

  const depositIx = mode === "verify"
    ? buildVerifyDepositIx({
      ...common,
      depositIntent: options.depositIntent
        ? new PublicKey(options.depositIntent)
        : deriveDepositIntentPDA(ctx.programs.utxopiaProgramId, hexToBytes("--npk", options.npk ?? "", 32))[0],
      sweepTxid,
      depositTxid,
      blockHeight,
      sweepTxSize: sweepRaw.length,
      depositTxSize: depositRaw.length,
    })
    : buildCompleteDepositIx({
      ...common,
      sweepTxid,
      depositTxid,
      blockHeight,
      sweepTxSize: sweepRaw.length,
      depositTxSize: directToPool ? 0 : depositRaw.length,
      sweepVout: options.sweepVout ?? (() => { throw new Error("--sweep-vout is required for complete_deposit to derive the UTXO PDA"); })(),
    });

  const depositSig = await sendAndConfirmTransaction(ctx.connection, new Transaction().add(depositIx), [ctx.payer], { commitment: "confirmed" });
  console.log(`${mode === "verify" ? "verify_deposit" : "complete_deposit"} signature: ${depositSig}`);
}

export {
  createTxBufferAccount,
  computeBlockHash,
  deriveDepositStealthPDA,
  deriveStealthAnnouncementPDA,
};
