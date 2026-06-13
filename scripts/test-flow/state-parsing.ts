import { TREE_DEPTH } from "./constants";

export interface PoolSnapshot {
  totalMinted: bigint;
  totalBurned: bigint;
  pendingRedemptions: bigint;
  totalShielded: bigint;
}

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

export function parsePoolState(data: Buffer): PoolSnapshot | null {
  if (data.length < 268 || data[0] !== 0x01) return null;
  return {
    totalMinted: data.readBigUInt64LE(140),
    totalBurned: data.readBigUInt64LE(148),
    pendingRedemptions: data.readBigUInt64LE(156),
    totalShielded: data.readBigUInt64LE(188),
  };
}

export function parseLightClientTipHeight(data: Buffer): bigint | null {
  if (data.length < 144 || data[0] !== 0x06) return null;
  return data.readBigUInt64LE(136);
}
