import { PublicKey } from "@solana/web3.js";

import { Seeds, Discriminators, Constants } from "./program";

/**
 * PoolState account layout (264 bytes).
 */
export interface PoolStateLayout {
  discriminator: number;
  bump: number;
  flags: number;
  _padding: number;
  authority: Uint8Array;
  zkbtcMint: Uint8Array;
  poolVault: Uint8Array;
  frostVault: Uint8Array;
  depositCount: bigint;
  totalMinted: bigint;
  totalBurned: bigint;
  pendingRedemptions: bigint;
  directClaims: bigint;
  splitCount: bigint;
  lastUpdate: bigint;
  minDeposit: bigint;
  maxDeposit: bigint;
  pendingMinDeposit: bigint;
  pendingMaxDeposit: bigint;
  pendingServiceFee: bigint;
  pendingExecuteAfter: bigint;
  _reserved: Uint8Array;
}

export const POOL_STATE_SIZE = 264;

/**
 * Parse PoolState from account data.
 */
export function parsePoolState(data: Buffer): PoolStateLayout {
  if (data.length < POOL_STATE_SIZE) {
    throw new Error(
      `Invalid PoolState size: ${data.length} < ${POOL_STATE_SIZE}`,
    );
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
    // offsets 204-227: totalShielded, serviceFeeSats, feePool (skipped)
    pendingMinDeposit: data.readBigUInt64LE(212),
    pendingMaxDeposit: data.readBigUInt64LE(220),
    pendingServiceFee: data.readBigUInt64LE(228),
    pendingExecuteAfter: data.readBigInt64LE(236),
    _reserved: data.subarray(244, 268),
  };
}

/**
 * Derive PoolState PDA.
 */
export function derivePoolStatePda(
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync([Seeds.POOL_STATE], programId);
}

/**
 * Derive CommitmentTree PDA.
 */
export function deriveCommitmentTreePda(
  programId: PublicKey,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Seeds.COMMITMENT_TREE],
    programId,
  );
}

/**
 * Derive Deposit Stealth Announcement PDA (unified: ["stealth", txid]).
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
 * Derive NullifierRecord PDA.
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
 * Derive RedemptionRequest PDA.
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

export const TREE_DEPTH = Constants.TREE_DEPTH;

