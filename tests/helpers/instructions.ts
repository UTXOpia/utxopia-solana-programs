import {
  PublicKey,
  SystemProgram,
  TransactionInstruction,
} from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID } from "@solana/spl-token";

import { Instruction } from "./program";

/**
 * Build Initialize instruction.
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
 * Build RecordDeposit instruction.
 *
 * Data layout: discriminator (1) + commitment (32) + amount (8) = 41 bytes.
 */
export function buildRecordDepositInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  depositRecord: PublicKey,
  authority: PublicKey,
  commitment: Uint8Array,
  amountSats: bigint,
): TransactionInstruction {
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
 * Build ClaimDirect instruction.
 *
 * Data layout:
 * discriminator (1) + proof (256) + root (32) + nullifier_hash (32) + amount (8) = 329 bytes.
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
 * Build MintToCommitment instruction (1-in-1-out transfer).
 *
 * Data layout:
 * discriminator (1) + proof (256) + root (32) + nullifier_hash (32) + output_commitment (32) = 353 bytes.
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
 * Build SplitCommitment instruction (1-in-2-out).
 *
 * Data layout:
 * discriminator (1) + proof (256) + root (32) + nullifier_hash (32)
 * + output_1 (32) + output_2 (32) = 385 bytes.
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
 * Build RequestRedemption instruction.
 *
 * Data layout:
 * discriminator (1) + amount (8) + btc_address_len (1) + btc_address + nonce (8).
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
 * Build SetPaused instruction.
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
 * Build ProposePoolUpdate instruction.
 *
 * Data layout: discriminator(1) + min_deposit(8) + max_deposit(8) + service_fee(8) = 25 bytes.
 */
export function buildProposePoolUpdateInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  authority: PublicKey,
  minDeposit: bigint,
  maxDeposit: bigint,
  serviceFee: bigint,
): TransactionInstruction {
  const data = Buffer.alloc(25);
  data[0] = Instruction.ProposePoolUpdate;
  data.writeBigUInt64LE(minDeposit, 1);
  data.writeBigUInt64LE(maxDeposit, 9);
  data.writeBigUInt64LE(serviceFee, 17);

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
 * Build ExecutePoolUpdate instruction.
 *
 * Data layout: discriminator(1) = 1 byte. Permissionless.
 */
export function buildExecutePoolUpdateInstruction(
  programId: PublicKey,
  poolState: PublicKey,
): TransactionInstruction {
  const data = Buffer.alloc(1);
  data[0] = Instruction.ExecutePoolUpdate;

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
    ],
    programId,
    data,
  });
}

/**
 * Build CancelPoolUpdate instruction.
 *
 * Data layout: discriminator(1) = 1 byte.
 */
export function buildCancelPoolUpdateInstruction(
  programId: PublicKey,
  poolState: PublicKey,
  authority: PublicKey,
): TransactionInstruction {
  const data = Buffer.alloc(1);
  data[0] = Instruction.CancelPoolUpdate;

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
 * Build ClaimGroth16 instruction.
 *
 * Data layout (200 bytes payload + discriminator = 201 total):
 * - proof_hash: [u8; 32]
 * - merkle_root: [u8; 32]
 * - nullifier_hash_pi: [u8; 32]
 * - amount_pi: [u8; 32]
 * - vk_hash: [u8; 32]
 * - nullifier_hash: [u8; 32]
 * - amount: u64
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
  vkHash?: Uint8Array,
): TransactionInstruction {
  const data = Buffer.alloc(201);
  let offset = 0;

  data[offset++] = Instruction.ClaimGroth16;

  // proof_hash (32 bytes)
  data.set(proofHash, offset);
  offset += 32;

  // merkle_root (32 bytes)
  data.set(merkleRoot, offset);
  offset += 32;

  // nullifier_hash_pi (32 bytes)
  data.set(nullifierHash, offset);
  offset += 32;

  // amount_pi (32 bytes) - big-endian in last 8 bytes
  const amountPi = new Uint8Array(32);
  const amountBytes = new Uint8Array(8);
  let tempAmount = amount;
  for (let i = 7; i >= 0; i--) {
    amountBytes[i] = Number(tempAmount & 0xffn);
    tempAmount >>= 8n;
  }
  amountPi.set(amountBytes, 24);
  data.set(amountPi, offset);
  offset += 32;

  // vk_hash (32 bytes) - zeros = demo mode
  if (vkHash) {
    data.set(vkHash, offset);
  }
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

