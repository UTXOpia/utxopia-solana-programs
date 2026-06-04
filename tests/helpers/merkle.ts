import { bigintToBytes, Poseidon, TREE_DEPTH } from "./zk";

const ZERO_VALUE = 0n;

export class PoseidonMerkleTree {
  private readonly poseidon: Poseidon;
  private readonly leaves: bigint[] = [];
  private readonly filledSubtrees: bigint[] = [];
  private readonly zeros: bigint[] = [];
  public root: bigint;
  private readonly rootHistory: bigint[] = [];

  constructor(poseidon: Poseidon) {
    this.poseidon = poseidon;

    // Compute zero values for each level.
    let currentZero = ZERO_VALUE;
    this.zeros.push(currentZero);
    for (let i = 0; i < TREE_DEPTH; i++) {
      currentZero = this.hash(currentZero, currentZero);
      this.zeros.push(currentZero);
      this.filledSubtrees.push(this.zeros[i]);
    }
    this.root = this.zeros[TREE_DEPTH];
  }

  private hash(left: bigint, right: bigint): bigint {
    return this.poseidon.F.toObject(this.poseidon([left, right]));
  }

  insert(commitment: bigint): number {
    const leafIndex = this.leaves.length;
    this.leaves.push(commitment);

    let currentHash = commitment;
    let currentIndex = leafIndex;

    for (let level = 0; level < TREE_DEPTH; level++) {
      if (currentIndex % 2 === 0) {
        this.filledSubtrees[level] = currentHash;
        currentHash = this.hash(currentHash, this.zeros[level]);
      } else {
        currentHash = this.hash(this.filledSubtrees[level], currentHash);
      }
      currentIndex = Math.floor(currentIndex / 2);
    }

    this.root = currentHash;
    this.rootHistory.push(currentHash);
    if (this.rootHistory.length > 30) {
      this.rootHistory.shift();
    }

    return leafIndex;
  }

  isValidRoot(root: bigint): boolean {
    if (root === this.root) return true;
    return this.rootHistory.includes(root);
  }

  generateProof(leafIndex: number): { path: bigint[]; indices: number[] } {
    const path: bigint[] = [];
    const indices: number[] = [];
    let currentIndex = leafIndex;

    for (let level = 0; level < TREE_DEPTH; level++) {
      const siblingIndex = currentIndex % 2 === 0 ? currentIndex + 1 : currentIndex - 1;
      indices.push(currentIndex % 2);

      if (siblingIndex < this.leaves.length && level === 0) {
        path.push(this.leaves[siblingIndex]);
      } else if (currentIndex % 2 === 0) {
        path.push(this.zeros[level]);
      } else {
        path.push(this.filledSubtrees[level]);
      }

      currentIndex = Math.floor(currentIndex / 2);
    }

    return { path, indices };
  }

  get rootBytes(): Uint8Array {
    return bigintToBytes(this.root);
  }

  get leafCount(): number {
    return this.leaves.length;
  }
}

