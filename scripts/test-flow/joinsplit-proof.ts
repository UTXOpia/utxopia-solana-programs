import * as fs from "fs";

export interface JoinSplitProofFixture {
  proof: Buffer;
  publicInputs: Buffer[];
}

export function loadJoinSplitProofFixture(filePath: string): JoinSplitProofFixture {
  const json = JSON.parse(fs.readFileSync(filePath, "utf-8")) as {
    proof: string;
    publicInputs: string[];
  };

  return {
    proof: Buffer.from(json.proof.replace(/^0x/, ""), "hex"),
    publicInputs: json.publicInputs.map((input) => Buffer.from(input.replace(/^0x/, ""), "hex")),
  };
}

export async function generateJoinSplitProof(): Promise<JoinSplitProofFixture> {
  throw new Error("Real JoinSplit proof generation is intentionally excluded from hermetic tests; use fixtures or run the full regtest scenario.");
}
