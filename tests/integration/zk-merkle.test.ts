import { describe, it, beforeAll } from "bun:test";
import { Keypair } from "@solana/web3.js";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";

import { PoseidonMerkleTree } from "../helpers/merkle";
import {
  TREE_DEPTH,
  type Poseidon,
  generateNote,
  generateClaimDirectProof,
} from "../helpers/zk";

describe("UTXOpia Circom ZK Proof Integration", function () {
  let user: Keypair;
  let poseidon: Poseidon;
  let merkleTree: PoseidonMerkleTree;

  beforeAll(async () => {
    user = Keypair.generate();
    poseidon = (await buildPoseidon()) as Poseidon;
    merkleTree = new PoseidonMerkleTree(poseidon);
  });

  it("should generate a valid note with Poseidon", async () => {
    const note = await generateNote(poseidon, 100_000n);

    expect(note.amount).to.equal(100_000n);
    expect(note.nullifierBytes.length).to.equal(32);
    expect(note.secretBytes.length).to.equal(32);
    expect(note.commitmentBytes.length).to.equal(32);
    expect(note.nullifierHashBytes.length).to.equal(32);

    const noteHash = poseidon.F.toObject(
      poseidon([note.nullifier, note.secret]),
    );
    const recomputed = poseidon.F.toObject(
      poseidon([noteHash, note.amount]),
    );
    expect(note.commitment).to.equal(recomputed);
  });

  it("should insert commitments into Merkle tree", async () => {
    const note1 = await generateNote(poseidon, 50_000n);
    const note2 = await generateNote(poseidon, 75_000n);

    const idx1 = merkleTree.insert(note1.commitment);
    const idx2 = merkleTree.insert(note2.commitment);

    expect(idx1).to.equal(0);
    expect(idx2).to.equal(1);
    expect(merkleTree.leafCount).to.equal(2);
  });

  it("should generate and verify Merkle proofs", async () => {
    const note = await generateNote(poseidon, 100_000n);
    const leafIndex = merkleTree.insert(note.commitment);

    const { path, indices } = merkleTree.generateProof(leafIndex);

    expect(path.length).to.equal(TREE_DEPTH);
    expect(indices.length).to.equal(TREE_DEPTH);
    expect(merkleTree.isValidRoot(merkleTree.root)).to.be.true;
  });

  it("should generate claim_direct proof (mock or real)", async () => {
    const note = await generateNote(poseidon, 100_000n);
    merkleTree.insert(note.commitment);

    const { path, indices } = merkleTree.generateProof(
      merkleTree.leafCount - 1,
    );

    const result = await generateClaimDirectProof(
      note,
      merkleTree.rootBytes,
      path,
      indices,
      user.publicKey,
    );

    expect(result.proofBytes.length).to.equal(256);
    expect(result.isValid).to.be.true;
  });
});

