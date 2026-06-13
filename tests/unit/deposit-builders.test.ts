import { describe, expect, it } from "bun:test";
import { Keypair, PublicKey } from "@solana/web3.js";
import {
  UTXOPIA_DISC,
  buildCompleteDepositIx,
  buildRegisterDepositIntentIx,
  buildVerifyDepositIx,
} from "../../scripts/test-flow/deposit";
import {
  deriveDepositIntentPDA,
  deriveDepositReceiptPDA,
  derivePoolConfigPDA,
  deriveTokenConfigPDA,
  deriveUtxoRecordPDA,
} from "../../scripts/test-flow/pdas";

function pk(): PublicKey {
  return Keypair.generate().publicKey;
}

const programId = pk();
const authority = pk();
const mint = pk();
const common = {
  utxopiaProgramId: programId,
  poolState: pk(),
  verifiedTx: pk(),
  lightClient: pk(),
  commitmentTree: pk(),
  sweepTxBuffer: pk(),
  authority,
  zkbtcMint: mint,
  poolVault: pk(),
  depositReceipt: deriveDepositReceiptPDA(programId, Buffer.alloc(32, 2))[0],
  tokenConfig: deriveTokenConfigPDA(programId, mint)[0],
  poolConfig: derivePoolConfigPDA(programId)[0],
  depositTxBuffer: pk(),
};

describe("deposit instruction builders", () => {
  it("serializes register_deposit_intent", () => {
    const npk = Buffer.alloc(32, 7);
    const ephemeralPubkey = Buffer.alloc(32, 8);
    const depositIntent = deriveDepositIntentPDA(programId, npk)[0];

    const ix = buildRegisterDepositIntentIx({
      utxopiaProgramId: programId,
      authority,
      depositIntent,
      ephemeralPubkey,
      npk,
    });

    expect(ix.programId).toEqual(programId);
    expect(ix.data.length).toBe(65);
    expect(ix.data[0]).toBe(UTXOPIA_DISC.REGISTER_DEPOSIT_INTENT);
    expect(ix.data.subarray(1, 33).equals(ephemeralPubkey)).toBe(true);
    expect(ix.data.subarray(33, 65).equals(npk)).toBe(true);
  });

  it("serializes complete_deposit and derives the UTXO PDA", () => {
    const sweepTxid = Buffer.alloc(32, 1);
    const depositTxid = Buffer.alloc(32, 2);
    const sweepVout = 3;
    const expectedUtxo = deriveUtxoRecordPDA(programId, sweepTxid, sweepVout)[0];

    const ix = buildCompleteDepositIx({
      ...common,
      sweepTxid,
      depositTxid,
      blockHeight: 123n,
      sweepTxSize: 456,
      depositTxSize: 0,
      sweepVout,
    });

    expect(ix.data.length).toBe(81);
    expect(ix.data[0]).toBe(UTXOPIA_DISC.COMPLETE_DEPOSIT);
    expect(ix.data.subarray(1, 33).equals(sweepTxid)).toBe(true);
    expect(ix.data.readBigUInt64LE(33)).toBe(123n);
    expect(ix.data.readUInt32LE(41)).toBe(456);
    expect(ix.data.readUInt32LE(45)).toBe(0);
    expect(ix.data.subarray(49, 81).equals(depositTxid)).toBe(true);
    expect(ix.keys[12].pubkey).toEqual(expectedUtxo);
  });

  it("serializes verify_deposit with deposit intent and raw deposit size", () => {
    const sweepTxid = Buffer.alloc(32, 1);
    const depositTxid = Buffer.alloc(32, 2);
    const depositIntent = pk();

    const ix = buildVerifyDepositIx({
      ...common,
      depositIntent,
      sweepTxid,
      depositTxid,
      blockHeight: 999n,
      sweepTxSize: 111,
      depositTxSize: 222,
    });

    expect(ix.data.length).toBe(81);
    expect(ix.data[0]).toBe(UTXOPIA_DISC.VERIFY_DEPOSIT);
    expect(ix.data.subarray(1, 33).equals(sweepTxid)).toBe(true);
    expect(ix.data.readBigUInt64LE(33)).toBe(999n);
    expect(ix.data.readUInt32LE(41)).toBe(111);
    expect(ix.data.subarray(45, 77).equals(depositTxid)).toBe(true);
    expect(ix.data.readUInt32LE(77)).toBe(222);
    expect(ix.keys[10].pubkey).toEqual(depositIntent);
  });
});
