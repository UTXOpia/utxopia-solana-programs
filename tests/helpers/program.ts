import { PublicKey } from "@solana/web3.js";

/**
 * Program ID for UTXOpia Pinocchio.
 * Update this after deployment if the program ID changes.
 */
export const PROGRAM_ID = new PublicKey(
  "AtztELZfz3GHA8hFQCv7aT9Mt47Xhknv3ZCNb3fmXsgf",
);

/**
 * Instruction discriminators (single byte for gas efficiency).
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
  ProposePoolUpdate: 21,
  ExecutePoolUpdate: 22,
  CancelPoolUpdate: 23,
} as const;

/**
 * Account seeds for PDA derivation.
 */
export const Seeds = {
  POOL_STATE: Buffer.from("pool_state"),
  COMMITMENT_TREE: Buffer.from("commitment_tree"),
  DEPOSIT: Buffer.from("deposit"),
  STEALTH: Buffer.from("stealth"),
  NULLIFIER: Buffer.from("nullifier"),
  REDEMPTION: Buffer.from("redemption"),
} as const;

/**
 * Account discriminators (first byte of account data).
 */
export const Discriminators = {
  POOL_STATE: 0x01,
  COMMITMENT_TREE: 0x02,
  DEPOSIT_RECORD: 0x03,
  NULLIFIER_RECORD: 0x04,
  REDEMPTION_REQUEST: 0x05,
} as const;

/**
 * Program-wide constants used in tests.
 */
export const Constants = {
  MIN_DEPOSIT_SATS: 10_000n, // 0.0001 BTC
  MAX_DEPOSIT_SATS: 100_000_000_000n, // 1000 BTC
  PROOF_SIZE: 256,
  MAX_BTC_ADDRESS_LEN: 62,
  TREE_DEPTH: 20,
} as const;

