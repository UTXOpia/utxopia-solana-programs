#!/usr/bin/env bun
/**
 * Hermetic local-validator scenario entrypoint.
 *
 * Keep orchestration in scripts/test-flow/scenario.ts so this file stays thin.
 */

import { runLocalValidatorScenario } from "./test-flow/scenario";

async function main(): Promise<void> {
  console.log("=".repeat(60));
  console.log("UTXOpia Local Validator Scenario");
  console.log("=".repeat(60));

  await runLocalValidatorScenario();
  console.log("\nLocal validator scenario completed");
}

main().catch((err) => {
  console.error("\nLocal validator scenario failed");
  console.error(err);
  process.exit(1);
});
