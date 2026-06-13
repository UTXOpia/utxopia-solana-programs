/**
 * Compatibility barrel for older scripts.
 *
 * New test-flow code should import directly from scripts/test-flow/* modules.
 */

import { Keypair } from "@solana/web3.js";
import * as fs from "fs";

export * from "./test-flow/constants";
export * from "./test-flow/pdas";
export * from "./test-flow/state-parsing";
export * from "./test-flow/chadbuffer";
export * from "./test-flow/light-client";

export function loadAuthorityKeypair(): Keypair {
  const keypairPath = process.env.KEYPAIR || `${process.env.HOME}/.config/solana/id.json`;
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(fs.readFileSync(keypairPath, "utf-8"))),
  );
}
