import { describe, it, beforeAll } from "bun:test";
import { Keypair, PublicKey } from "@solana/web3.js";
import { expect } from "chai";

import { PROGRAM_ID, Discriminators } from "../helpers/program";
import {
  buildInitializeInstruction,
  buildRecordDepositInstruction,
  buildClaimDirectInstruction,
  buildSplitCommitmentInstruction,
  buildRequestRedemptionInstruction,
  buildSetPausedInstruction,
  buildClaimGroth16Instruction,
  buildProposePoolUpdateInstruction,
  buildExecutePoolUpdateInstruction,
  buildCancelPoolUpdateInstruction,
} from "../helpers/instructions";
import {
  derivePoolStatePda,
  deriveCommitmentTreePda,
  deriveDepositStealthPda,
  deriveNullifierRecordPda,
  deriveRedemptionRequestPda,
  parsePoolState,
  POOL_STATE_SIZE,
} from "../helpers/pda";

describe("UTXOpia Instruction Encoding", function () {
  let authority: Keypair;
  let user: Keypair;
  let poolStatePda: PublicKey;
  let poolStateBump: number;
  let commitmentTreePda: PublicKey;
  let commitmentTreeBump: number;

  beforeAll(() => {
    authority = Keypair.generate();
    user = Keypair.generate();

    [poolStatePda, poolStateBump] = derivePoolStatePda(PROGRAM_ID);
    [commitmentTreePda, commitmentTreeBump] = deriveCommitmentTreePda(
      PROGRAM_ID,
    );
  });

  describe("IDL-like Interface Tests", () => {
    it("should correctly encode Initialize instruction", () => {
      const ix = buildInitializeInstruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock vault
        Keypair.generate().publicKey, // mock frost vault
        authority.publicKey,
        poolStateBump,
        commitmentTreeBump,
      );

      expect(ix.data[0]).to.equal(0); // Instruction.Initialize
      expect(ix.data[1]).to.equal(poolStateBump);
      expect(ix.data[2]).to.equal(commitmentTreeBump);
      expect(ix.keys.length).to.equal(7);
    });

    it("should correctly encode RecordDeposit instruction", () => {
      const commitment = new Uint8Array(32).fill(0xab);
      const amount = 100_000n;

      const [depositPda] = deriveDepositStealthPda(PROGRAM_ID, commitment);
      const ix = buildRecordDepositInstruction(
        PROGRAM_ID,
        poolStatePda,
        depositPda,
        authority.publicKey,
        commitment,
        amount,
      );

      expect(ix.data[0]).to.equal(1); // Instruction.RecordDeposit
      expect(ix.data.readBigUInt64LE(33)).to.equal(amount);
    });

    it("should correctly encode ClaimDirect instruction", () => {
      const proof = new Uint8Array(256).fill(1);
      const root = new Uint8Array(32).fill(2);
      const nullifierHash = new Uint8Array(32).fill(3);
      const amount = 50_000n;

      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, nullifierHash);
      const ix = buildClaimDirectInstruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock token account
        user.publicKey,
        proof,
        root,
        nullifierHash,
        amount,
      );

      expect(ix.data[0]).to.equal(2); // Instruction.ClaimDirect
      expect(ix.data.length).to.equal(329);
      expect(ix.data.readBigUInt64LE(321)).to.equal(amount);
    });

    it("should correctly encode SplitCommitment instruction", () => {
      const proof = new Uint8Array(256).fill(1);
      const root = new Uint8Array(32).fill(2);
      const nullifierHash = new Uint8Array(32).fill(3);
      const output1 = new Uint8Array(32).fill(4);
      const output2 = new Uint8Array(32).fill(5);

      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, nullifierHash);
      const ix = buildSplitCommitmentInstruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        user.publicKey,
        proof,
        root,
        nullifierHash,
        output1,
        output2,
      );

      expect(ix.data[0]).to.equal(4); // Instruction.SplitCommitment
      expect(ix.data.length).to.equal(385);
    });

    it("should correctly encode RequestRedemption instruction", () => {
      const btcAddress = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
      const amount = 100_000n;
      const nonce = 1n;

      const [redemptionPda] = deriveRedemptionRequestPda(
        PROGRAM_ID,
        user.publicKey,
        nonce,
      );
      const ix = buildRequestRedemptionInstruction(
        PROGRAM_ID,
        poolStatePda,
        redemptionPda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock token account
        user.publicKey,
        amount,
        btcAddress,
        nonce,
      );

      expect(ix.data[0]).to.equal(5); // Instruction.RequestRedemption
      expect(ix.data.readBigUInt64LE(1)).to.equal(amount);
    });

    it("should correctly encode SetPaused instruction", () => {
      const ix = buildSetPausedInstruction(
        PROGRAM_ID,
        poolStatePda,
        authority.publicKey,
        true,
      );

      expect(ix.data[0]).to.equal(7); // Instruction.SetPaused
      expect(ix.data[1]).to.equal(1);
    });

    it("should correctly encode ClaimGroth16 instruction", () => {
      const proofHash = new Uint8Array(32).fill(0xab);
      const merkleRoot = new Uint8Array(32).fill(0xcd);
      const nullifierHash = new Uint8Array(32).fill(0xef);
      const amount = 100_000n;

      const [nullifierPda] = deriveNullifierRecordPda(PROGRAM_ID, nullifierHash);
      const ix = buildClaimGroth16Instruction(
        PROGRAM_ID,
        poolStatePda,
        commitmentTreePda,
        nullifierPda,
        Keypair.generate().publicKey, // mock mint
        Keypair.generate().publicKey, // mock token account
        user.publicKey,
        proofHash,
        merkleRoot,
        nullifierHash,
        amount,
      );

      expect(ix.data[0]).to.equal(11); // Instruction.ClaimGroth16
      expect(ix.data.length).to.equal(201);
      expect(ix.data.readBigUInt64LE(193)).to.equal(amount);
    });
  });

  describe("Timelocked Pool Update Tests", () => {
    it("should correctly encode ProposePoolUpdate instruction", () => {
      const minDeposit = 10_000n;
      const maxDeposit = 100_000_000_000n;
      const serviceFee = 500n;

      const ix = buildProposePoolUpdateInstruction(
        PROGRAM_ID,
        poolStatePda,
        authority.publicKey,
        minDeposit,
        maxDeposit,
        serviceFee,
      );

      expect(ix.data[0]).to.equal(21); // Instruction.ProposePoolUpdate
      expect(ix.data.length).to.equal(25);
      expect(ix.data.readBigUInt64LE(1)).to.equal(minDeposit);
      expect(ix.data.readBigUInt64LE(9)).to.equal(maxDeposit);
      expect(ix.data.readBigUInt64LE(17)).to.equal(serviceFee);
      expect(ix.keys.length).to.equal(2);
      expect(ix.keys[1].isSigner).to.equal(true);
    });

    it("should correctly encode ExecutePoolUpdate instruction", () => {
      const ix = buildExecutePoolUpdateInstruction(
        PROGRAM_ID,
        poolStatePda,
      );

      expect(ix.data[0]).to.equal(22); // Instruction.ExecutePoolUpdate
      expect(ix.data.length).to.equal(1);
      expect(ix.keys.length).to.equal(1);
      // Permissionless — no signer required
      expect(ix.keys[0].isSigner).to.equal(false);
    });

    it("should correctly encode CancelPoolUpdate instruction", () => {
      const ix = buildCancelPoolUpdateInstruction(
        PROGRAM_ID,
        poolStatePda,
        authority.publicKey,
      );

      expect(ix.data[0]).to.equal(23); // Instruction.CancelPoolUpdate
      expect(ix.data.length).to.equal(1);
      expect(ix.keys.length).to.equal(2);
      expect(ix.keys[1].isSigner).to.equal(true);
    });
  });

  describe("Account Parsing", () => {
    it("should correctly parse PoolState layout", () => {
      const data = Buffer.alloc(POOL_STATE_SIZE);
      data[0] = Discriminators.POOL_STATE;
      data[1] = 255;
      data[2] = 0;
      data[3] = 0;

      const mockAuthority = Keypair.generate().publicKey.toBytes();
      data.set(mockAuthority, 4);

      const mockMint = Keypair.generate().publicKey.toBytes();
      data.set(mockMint, 36);

      data.writeBigUInt64LE(100n, 132);
      data.writeBigUInt64LE(500_000n, 140);
      data.writeBigUInt64LE(100_000n, 148);

      const parsed = parsePoolState(data);

      expect(parsed.discriminator).to.equal(Discriminators.POOL_STATE);
      expect(parsed.bump).to.equal(255);
      expect(parsed.flags).to.equal(0);
      expect(parsed.depositCount).to.equal(100n);
      expect(parsed.totalMinted).to.equal(500_000n);
      expect(parsed.totalBurned).to.equal(100_000n);
    });
  });
});

