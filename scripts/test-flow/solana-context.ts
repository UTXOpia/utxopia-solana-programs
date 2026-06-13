import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import {
  deriveBlockHeaderPDA,
  deriveCommitmentTreePDA,
  deriveHeightIndexPDA,
  deriveLightClientPDA,
  derivePoolStatePDA,
} from "./pdas";
import {
  parseCommitmentTree,
  parseLightClientTipHeight,
  parsePoolState,
} from "./state-parsing";
import { createConnection, loadKeypair, loadTestFlowConfig, TestFlowConfig } from "./config";

export interface SolanaTestContext {
  config: TestFlowConfig;
  connection: Connection;
  payer: Keypair;
  programs: TestFlowConfig["programs"];
  pdas: {
    poolState: PublicKey;
    poolBump: number;
    commitmentTree: PublicKey;
    treeBump: number;
    lightClient: PublicKey;
    lightClientBump: number;
  };
}

export function createSolanaTestContext(overrides: Partial<TestFlowConfig> = {}): SolanaTestContext {
  const config = loadTestFlowConfig(overrides);
  const [poolState, poolBump] = derivePoolStatePDA(config.programs.utxopiaProgramId);
  const [commitmentTree, treeBump] = deriveCommitmentTreePDA(config.programs.utxopiaProgramId);
  const [lightClient, lightClientBump] = deriveLightClientPDA(config.programs.btcLightClientProgramId);

  return {
    config,
    connection: createConnection(config),
    payer: loadKeypair(config.keypairPath),
    programs: config.programs,
    pdas: {
      poolState,
      poolBump,
      commitmentTree,
      treeBump,
      lightClient,
      lightClientBump,
    },
  };
}

export async function loadPoolSnapshot(ctx: Pick<SolanaTestContext, "connection" | "pdas">) {
  const account = await ctx.connection.getAccountInfo(ctx.pdas.poolState);
  return account ? parsePoolState(account.data) : null;
}

export async function loadCommitmentTree(ctx: Pick<SolanaTestContext, "connection" | "pdas">) {
  const account = await ctx.connection.getAccountInfo(ctx.pdas.commitmentTree);
  return account ? parseCommitmentTree(account.data) : null;
}

export async function loadLightClientTipHeight(ctx: Pick<SolanaTestContext, "connection" | "pdas">) {
  const account = await ctx.connection.getAccountInfo(ctx.pdas.lightClient);
  return account ? parseLightClientTipHeight(account.data) : null;
}

export { deriveBlockHeaderPDA, deriveHeightIndexPDA };
