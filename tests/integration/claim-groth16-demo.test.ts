import { describe, it, beforeAll } from "bun:test";
import { Keypair } from "@solana/web3.js";
import { expect } from "chai";
import { buildPoseidon } from "circomlibjs";

import { PROGRAM_ID } from "../helpers/program";
import {
  deriveCommitmentTreePda,
  deriveNullifierRecordPda,
} from "../helpers/pda";
import { PoseidonMerkleTree } from "../helpers/merkle";
import { type Poseidon, generateNote } from "../helpers/zk";
import { buildClaimGroth16Instruction } from "../helpers/instructions";

describe("UTXOpia Groth16 ZK Proof Integration (demo mode)", function () {
  let user: Keypair;
  let poseidon: Poseidon;
  let merkleTree: PoseidonMerkleTree;
  let commitmentTreePdaBump: [ReturnType<typeof deriveCommitmentTreePda>[0], number];

  beforeAll(async () => {
    user = Keypair.generate();
    poseidon = (await buildPoseidon()) as Poseidon;
    merkleTree = new PoseidonMerkleTree(poseidon);

    commitmentTreePdaBump = deriveCommitmentTreePda(PROGRAM_ID);
  });

  it("should simulate ClaimGroth16 flow with demo mode", async () => {
    const note = await generateNote(poseidon, 100_000n);

    const leafIndex = merkleTree.insert(note.commitment);
    expect(leafIndex).to.equal(0);

    // Use a deterministic fake proof hash; randomness is not required for this layout test.
    const proofHash = new Uint8Array(32).fill(7);

    const [nullifierPda] = deriveNullifierRecordPda(
      PROGRAM_ID,
      note.nullifierHashBytes,
    );
    const [commitmentTreePda] = commitmentTreePdaBump;

    const ix = buildClaimGroth16Instruction(
      PROGRAM_ID,
      Keypair.generate().publicKey, // mock pool state
      commitmentTreePda,
      nullifierPda,
      Keypair.generate().publicKey, // mock mint
      Keypair.generate().publicKey, // mock token account
      user.publicKey,
      proofHash,
      merkleTree.rootBytes,
      note.nullifierHashBytes,
      note.amount,
    );

    expect(ix.data[0]).to.equal(11);
    expect(ix.data.length).to.equal(201);

    const vkHashOffset = 1 + 32 + 32 + 32 + 32;
    const vkHash = ix.data.subarray(vkHashOffset, vkHashOffset + 32);
    const isZeros = Array.from(vkHash).every((b) => b === 0);
    expect(isZeros).to.be.true;
  });
});

