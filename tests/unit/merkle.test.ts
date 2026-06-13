import { describe, expect, it } from "bun:test";
import { serializeMerkleProof } from "../../scripts/test-flow/merkle";

describe("merkle proof serialization", () => {
  it("serializes Esplora merkle proofs into on-chain byte order", () => {
    const txid = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const siblingA = "1111111111111111111111111111111111111111111111111111111111111111";
    const siblingB = "2222222222222222222222222222222222222222222222222222222222222222";

    const serialized = serializeMerkleProof(txid, {
      merkle: [siblingA, siblingB],
      pos: 5,
    });

    expect(serialized.length).toBe(32 + 4 + 1 + 4 + 32 * 2);
    expect(serialized.subarray(0, 32).toString("hex")).toBe(
      "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
    );
    expect(serialized.readUInt32LE(32)).toBe(5);
    expect(serialized[36]).toBe(2);
    expect(serialized.readUInt32LE(37)).toBe(5);
    expect(serialized.subarray(41, 73).toString("hex")).toBe(siblingA);
    expect(serialized.subarray(73, 105).toString("hex")).toBe(siblingB);
  });
});
