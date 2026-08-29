/**
 * The SDK hard-codes every instruction discriminant. Nothing at build time ties
 * those numbers to lib.rs, so a renumbered instruction ships as a silently
 * mis-routed call. This reads both sides and compares.
 *
 * Slot 16 drifted once already: the SDK called it RESERVED_REQUEST_REDEMPTION
 * while the program had been using it for FREEZE_VK_REGISTRY.
 */
import { describe, expect, it } from "bun:test";
import { readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../..");

function rustDiscriminants(): Map<string, number> {
  const src = readFileSync(join(ROOT, "programs/utxopia/src/lib.rs"), "utf8");
  const out = new Map<string, number>();
  for (const m of src.matchAll(/pub const ([A-Z_]+): u8 = (\d+)/g)) {
    out.set(m[1], Number(m[2]));
  }
  return out;
}

function sdkDiscriminants(): Map<string, number> {
  const src = readFileSync(
    join(ROOT, "../utxopia-sdk/packages/sdk/src/instructions.ts"),
    "utf8",
  );
  const out = new Map<string, number>();
  for (const block of src.matchAll(/const (?:INSTRUCTION|PERMISSIONED_DISC) = \{([\s\S]*?)\n\} as const;/g)) {
    for (const m of block[1].matchAll(/^\s+([A-Z_]+): (\d+),/gm)) {
      out.set(m[1], Number(m[2]));
    }
  }
  return out;
}

describe("instruction discriminator parity", () => {
  const rust = rustDiscriminants();
  const sdk = sdkDiscriminants();

  it("finds both sides", () => {
    expect(rust.size).toBeGreaterThan(30);
    expect(sdk.size).toBeGreaterThan(30);
  });

  it("agrees on every name the SDK declares", () => {
    const drift: string[] = [];
    for (const [name, value] of sdk) {
      const onchain = rust.get(name);
      if (onchain === undefined) drift.push(`${name}=${value} is not an instruction in lib.rs`);
      else if (onchain !== value) drift.push(`${name}: sdk=${value} program=${onchain}`);
    }
    expect(drift).toEqual([]);
  });

  it("leaves no program slot claimed by a different SDK name", () => {
    const byValue = new Map([...rust].map(([n, v]) => [v, n]));
    const drift: string[] = [];
    for (const [name, value] of sdk) {
      const onchain = byValue.get(value);
      if (onchain && onchain !== name) drift.push(`slot ${value}: sdk calls it ${name}, program calls it ${onchain}`);
    }
    expect(drift).toEqual([]);
  });
});
