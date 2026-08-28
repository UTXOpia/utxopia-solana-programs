/**
 * The devnet (testnet4) BTC light client program id is written down in five
 * places: baked into the utxopia program, in the ops network config, in the
 * relay compose env, in the web network map, and in the SDK's DEVNET_CONFIG.
 * Only the first is enforced at runtime — the rest fail as "the SPV proof does
 * not verify" long after the wrong address was read.
 *
 * The testnet4 deploy on 2026-08-26 left the SDK pointing at a retired id for
 * exactly this reason. This asserts all five agree.
 */
import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../..");
const read = (rel: string) => readFileSync(join(ROOT, rel), "utf8");

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function toBase58(bytes: number[]): string {
  let n = 0n;
  for (const b of bytes) n = (n << 8n) | BigInt(b);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  return out;
}

/** The `devnet` (not devnet-regtest, not localnet) arm of the baked constant. */
function bakedDevnetId(): string {
  const src = read("programs/utxopia/src/constants.rs");
  const arm = /#\[cfg\(all\(feature = "devnet", not\(feature = "devnet-regtest"\)\)\)\]\s*pub const BTC_LIGHT_CLIENT_PROGRAM_ID: \[u8; 32\] = \[([^\]]+)\]/.exec(src);
  if (!arm) throw new Error("could not find the devnet BTC_LIGHT_CLIENT_PROGRAM_ID arm");
  const bytes = arm[1].match(/0x[0-9a-f]{2}/g)!.map((h) => parseInt(h, 16));
  expect(bytes.length).toBe(32);
  return toBase58(bytes);
}

describe("devnet BTC light client program id", () => {
  const onchain = bakedDevnetId();

  it("matches the ops network config", () => {
    const ops = JSON.parse(read("../ops/config/networks.json"));
    expect(ops.devnet.solana.btcLightClientId).toBe(onchain);
  });

  it("matches the ops pool config and relay env", () => {
    expect(JSON.parse(read("../ops/config/pools.devnet.json")).btcLightClientId).toBe(onchain);
    for (const env of ["pool.devnet.open.env", "pool.devnet.verified.env"]) {
      expect(read(`../ops/compose/${env}`)).toContain(`BTC_LIGHT_CLIENT_PROGRAM_ID=${onchain}`);
    }
  });

  it("matches the web network map", () => {
    const web = JSON.parse(read("../web/src/lib/networks.json"));
    expect(web.devnet.solana.btcLightClientId).toBe(onchain);
  });

  it("matches the test-flow program registry", () => {
    // scripts/test-flow/config.ts reads this for UTXOPIA_PROGRAM_ID /
    // BTC_LIGHT_CLIENT_PROGRAM_ID when no env var is set.
    const cfg = JSON.parse(read("config.json"));
    expect(cfg.programs.devnet.btc_light_client).toBe(onchain);
    const ops = JSON.parse(read("../ops/config/pools.devnet.json"));
    expect(cfg.programs.devnet.UTXOpia).toBe(ops.programId);
    expect(cfg.programs.devnet.chadbuffer).toBe(ops.chadbufferId);
  });

  it("matches the SDK devnet config", () => {
    const sdk = read("../utxopia-sdk/packages/sdk/src/config.ts");
    const block = /export const DEVNET_CONFIG[\s\S]*?\n\};/.exec(sdk)![0];
    const id = /btcLightClientProgramId: address\("([1-9A-HJ-NP-Za-km-z]+)"\)/.exec(block)![1];
    expect(id).toBe(onchain);
  });
});
