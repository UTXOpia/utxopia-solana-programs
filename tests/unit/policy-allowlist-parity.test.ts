/**
 * A permissioned instruction needs an entry in TWO allowlists that live in different crates:
 * `utxopia-policy`'s numeric `matches!` (which gates creating the PolicyApproval) and
 * utxopia's `is_permissioned_action` (which gates consuming it). An action missing from
 * either can never obtain an approval, so the instruction reverts on every call — fail-closed,
 * but silently, and no existing test catches it.
 *
 * That is exactly how disc 26 (verify_deposit_permissioned) shipped dead: the sibling
 * discriminator-parity test pins the instruction *numbers* across the SDK boundary, not the
 * *membership* of these two lists.
 */
import { describe, expect, it } from "bun:test";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const ROOT = join(import.meta.dir, "../..");

/** `pub const NAME: u8 = N` from the program's instruction module. */
function discriminants(): Map<string, number> {
  const src = readFileSync(join(ROOT, "programs/utxopia/src/lib.rs"), "utf8");
  return new Map(
    [...src.matchAll(/pub const ([A-Z_]+): u8 = (\d+)/g)].map((m) => [m[1], Number(m[2])]),
  );
}

/** The numeric `matches!(data[0], 13 | 14 | ...)` gate in the policy program. */
function policyProgramAllowlist(): Set<number> {
  const src = readFileSync(join(ROOT, "programs/utxopia-policy/src/lib.rs"), "utf8");
  const m = src.match(/matches!\(\s*data\[0\],\s*([\d\s|]+)\)/);
  if (!m) throw new Error("policy allowlist not found — did the matches! shape change?");
  return new Set(m[1].split("|").map((n) => Number(n.trim())));
}

/** The named `is_permissioned_action` mirror inside utxopia. */
function utxopiaAllowlist(disc: Map<string, number>): Set<number> {
  const src = readFileSync(
    join(ROOT, "programs/utxopia/src/instructions/policy_approval.rs"),
    "utf8",
  );
  const m = src.match(/fn is_permissioned_action[\s\S]*?matches!\(([\s\S]*?)\n\s*\)\n\s*\}/);
  if (!m) throw new Error("is_permissioned_action not found");
  const names = [...m[1].matchAll(/crate::instruction::([A-Z_]+)/g)].map((x) => x[1]);
  return new Set(
    names.map((n) => {
      const v = disc.get(n);
      if (v === undefined) throw new Error(`unknown instruction constant ${n}`);
      return v;
    }),
  );
}

/** Actions actually passed to `consume_policy_approval`, read from the handlers. */
function consumingActions(): Map<string, number> {
  const disc = discriminants();
  const dir = join(ROOT, "programs/utxopia/src/instructions");
  const out = new Map<string, number>();
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".rs"))) {
    const src = readFileSync(join(dir, file), "utf8");
    for (const m of src.matchAll(
      /consume_policy_approval\(([\s\S]{0,400}?)\)\?;/g,
    )) {
      const a = m[1].match(/crate::instruction::([A-Z_]+)/);
      if (!a) continue;
      const v = disc.get(a[1]);
      if (v === undefined) throw new Error(`unknown instruction constant ${a[1]}`);
      out.set(a[1], v);
    }
  }
  if (out.size === 0) throw new Error("no consume_policy_approval call sites found");
  return out;
}

describe("policy allowlist parity", () => {
  const disc = discriminants();
  const policy = policyProgramAllowlist();
  const utxopia = utxopiaAllowlist(disc);

  it("parses both sides", () => {
    expect(policy.size).toBeGreaterThan(0);
    expect(utxopia.size).toBeGreaterThan(0);
  });

  it("both allowlists accept exactly the same actions", () => {
    expect([...utxopia].sort((a, b) => a - b)).toEqual([...policy].sort((a, b) => a - b));
  });

  it("every action that consumes an approval appears in both lists", () => {
    // Derived from the actual call sites rather than a naming convention: INITIALIZE_PERMISSIONED
    // is named _PERMISSIONED but *creates* a permissioned pool, it never consumes an approval.
    // An action passed to consume_policy_approval and absent from either list is unreachable.
    for (const [name, value] of consumingActions()) {
      expect(policy.has(value), `${name} (${value}) missing from utxopia-policy allowlist`).toBe(
        true,
      );
      expect(utxopia.has(value), `${name} (${value}) missing from is_permissioned_action`).toBe(
        true,
      );
    }
  });
});
