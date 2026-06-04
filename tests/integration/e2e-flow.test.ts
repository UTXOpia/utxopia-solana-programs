import { describe, it, beforeAll } from "bun:test";
import { Keypair } from "@solana/web3.js";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";

import { PROGRAM_ID } from "../helpers/program";
import {
  deriveDepositStealthPda,
  deriveNullifierRecordPda,
} from "../helpers/pda";
import { PoseidonMerkleTree } from "../helpers/merkle";
import {
  type Poseidon,
  generateNote,
  generateClaimDirectProof,
} from "../helpers/zk";
import {
  buildRecordDepositInstruction,
  buildClaimDirectInstruction,
  buildSplitCommitmentInstruction,
} from "../helpers/instructions";

describe("UTXOpia E2E Flow Simulation", function () {
  let authority: Keypair;
  let user: Keypair;
  let poseidon: Poseidon;
  let merkleTree: PoseidonMerkleTree;

  beforeAll(async () => {
    authority = Keypair.generate();
    user = Keypair.generate();

    poseidon = (await buildPoseidon()) as Poseidon;
    merkleTree = new PoseidonMerkleTree(poseidon);
  });

  it("should simulate complete deposit -> claim flow", async () => {
    const note = await generateNote(poseidon, 100_000n);

    const [depositPda] = deriveDepositStealthPda(PROGRAM_ID, note.commitmentBytes);
    const recordDepositIx = buildRecordDepositInstruction(
      PROGRAM_ID,
      Keypair.generate().publicKey, // mock pool state
      depositPda,
      authority.publicKey,
      note.commitmentBytes,
      note.amount,
    );

    const leafIndex = merkleTree.insert(note.commitment);

    const { path, indices } = merkleTree.generateProof(leafIndex);

    const proofResult = await generateClaimDirectProof(
      note,
      merkleTree.rootBytes,
      path,
      indices,
      user.publicKey,
    );

    const [nullifierPda] = deriveNullifierRecordPda(
      PROGRAM_ID,
      note.nullifierHashBytes,
    );
    const claimIx = buildClaimDirectInstruction(
      PROGRAM_ID,
      Keypair.generate().publicKey, // mock pool state
      Keypair.generate().publicKey, // mock commitment tree
      nullifierPda,
      Keypair.generate().publicKey, // mock mint
      Keypair.generate().publicKey, // mock token account
      user.publicKey,
      proofResult.proofBytes,
      merkleTree.rootBytes,
      note.nullifierHashBytes,
      note.amount,
    );

    expect(recordDepositIx.data.length).to.be.greaterThan(0);
    expect(claimIx.data.length).to.be.greaterThan(0);
  });

  it("should simulate split commitment flow", async () => {
    const originalNote = await generateNote(poseidon, 200_000n);
    merkleTree.insert(originalNote.commitment);

    const note1 = await generateNote(poseidon, 150_000n);
    const note2 = await generateNote(poseidon, 50_000n);

    const { indices } = merkleTree.generateProof(merkleTree.leafCount - 1);
    expect(indices.length).to.be.greaterThan(0);

    const [nullifierPda] = deriveNullifierRecordPda(
      PROGRAM_ID,
      originalNote.nullifierHashBytes,
    );

    const splitIx = buildSplitCommitmentInstruction(
      PROGRAM_ID,
      Keypair.generate().publicKey, // mock pool state
      Keypair.generate().publicKey, // mock commitment tree
      nullifierPda,
      user.publicKey,
      new Uint8Array(256).fill(1), // mock proof
      merkleTree.rootBytes,
      originalNote.nullifierHashBytes,
      note1.commitmentBytes,
      note2.commitmentBytes,
    );

    expect(splitIx.data.length).to.be.greaterThan(0);
  });
});

