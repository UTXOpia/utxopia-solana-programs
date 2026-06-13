#!/usr/bin/env bun
/**
 * Full regtest scenario entrypoint.
 *
 * This is intentionally explicit and not part of the default test command.
 */

import { runRegtestScenario } from "./test-flow/scenario";

async function main(): Promise<void> {
  console.log("=".repeat(60));
  console.log("UTXOpia Full Regtest Scenario");
  console.log("=".repeat(60));

  await runRegtestScenario();
  console.log("\nRegtest scenario completed");
}

main().catch((err) => {
  console.error("\nRegtest scenario failed");
  console.error(err);
  process.exit(1);
});
