import { assertAccountExists } from "./assertions";
import { relayDepositCli, RelayDepositCliOptions } from "./deposit";
import { setupRegtest } from "./bitcoin-regtest";
import { createSolanaTestContext } from "./solana-context";
import { writeFlowState } from "./state-recording";

export async function runLocalValidatorScenario(): Promise<void> {
  const ctx = createSolanaTestContext({ cluster: "localnet" });
  await ctx.connection.getVersion();
  await assertAccountExists(ctx.connection, ctx.pdas.poolState, "pool state");
  await assertAccountExists(ctx.connection, ctx.pdas.commitmentTree, "commitment tree");
  await assertAccountExists(ctx.connection, ctx.pdas.lightClient, "BTC light client");

  writeFlowState({
    name: "local-validator",
    cluster: ctx.config.cluster,
    data: {
      poolState: ctx.pdas.poolState.toBase58(),
      commitmentTree: ctx.pdas.commitmentTree.toBase58(),
      lightClient: ctx.pdas.lightClient.toBase58(),
    },
  });
}

export interface RegtestScenarioOptions extends RelayDepositCliOptions {
  setupBitcoin?: boolean;
}

function envFlag(name: string): boolean {
  return process.env[name] === "1" || process.env[name]?.toLowerCase() === "true";
}

export function loadRegtestScenarioOptionsFromEnv(): RegtestScenarioOptions {
  return {
    setupBitcoin: envFlag("REGTEST_SETUP"),
    submitHeaders: envFlag("SUBMIT_HEADERS"),
    mode: (process.env.DEPOSIT_MODE as RegtestScenarioOptions["mode"] | undefined) ?? "complete",
    txid: process.env.TXID,
    sweepTxid: process.env.SWEEP_TXID,
    depositTxid: process.env.DEPOSIT_TXID,
    blockHash: process.env.BLOCK_HASH,
    blockHeight: process.env.BLOCK_HEIGHT ? Number(process.env.BLOCK_HEIGHT) : undefined,
    sweepVout: process.env.SWEEP_VOUT ? Number(process.env.SWEEP_VOUT) : undefined,
    zkbtcMint: process.env.ZKBTC_MINT,
    poolVault: process.env.POOL_VAULT,
    tokenProgram: process.env.TOKEN_PROGRAM,
    poolConfig: process.env.POOL_CONFIG,
    depositIntent: process.env.DEPOSIT_INTENT,
    npk: process.env.NPK,
    ephemeralPubkey: process.env.EPHEMERAL_PUBKEY,
    esploraUrl: process.env.ESPLORA_URL,
  };
}

export async function runRegtestScenario(options: RegtestScenarioOptions = loadRegtestScenarioOptionsFromEnv()): Promise<void> {
  if (options.setupBitcoin) {
    await setupRegtest();
  }

  await relayDepositCli(options);

  writeFlowState({
    name: "regtest",
    cluster: process.env.NETWORK ?? "localnet",
    data: {
      mode: options.mode ?? "complete",
      txid: options.txid,
      sweepTxid: options.sweepTxid,
      depositTxid: options.depositTxid,
    },
  });
}
