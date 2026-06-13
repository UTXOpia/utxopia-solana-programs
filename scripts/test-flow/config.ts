import { Connection, Keypair, PublicKey } from "@solana/web3.js";
import * as fs from "fs";
import * as path from "path";

export type SolanaCluster = "localnet" | "devnet" | "devnet2" | "mainnet";

export interface ProgramRefs {
  utxopiaProgramId: PublicKey;
  btcLightClientProgramId: PublicKey;
  chadbufferProgramId?: PublicKey;
  groth16VerifierProgramId?: PublicKey;
}

export interface TestFlowConfig {
  cluster: SolanaCluster;
  rpcUrl: string;
  keypairPath: string;
  programs: ProgramRefs;
  btcNetwork: "regtest" | "testnet" | "mainnet";
  btcStartHeight?: number;
  btcStartHash?: string;
}

const DEFAULT_RPC_BY_CLUSTER: Record<SolanaCluster, string> = {
  localnet: "http://127.0.0.1:8899",
  devnet: "https://api.devnet.solana.com",
  devnet2: "https://api.devnet.solana.com",
  mainnet: "https://api.mainnet-beta.solana.com",
};

function expandHome(filePath: string): string {
  if (filePath === "~") return process.env.HOME ?? filePath;
  if (filePath.startsWith("~/")) return path.join(process.env.HOME ?? "", filePath.slice(2));
  return filePath;
}

function readJsonFile<T>(filePath: string): T | null {
  if (!fs.existsSync(filePath)) return null;
  return JSON.parse(fs.readFileSync(filePath, "utf-8")) as T;
}

function requiredPublicKey(name: string, value: string | undefined): PublicKey {
  if (!value) throw new Error(`${name} is required`);
  return new PublicKey(value);
}

function optionalPublicKey(value: string | undefined): PublicKey | undefined {
  return value ? new PublicKey(value) : undefined;
}

export function loadTestFlowConfig(overrides: Partial<TestFlowConfig> = {}): TestFlowConfig {
  const rootConfig = readJsonFile<{
    defaultCluster?: SolanaCluster;
    wallet?: { path?: string };
    programs?: Record<string, Record<string, string>>;
  }>(path.resolve("config.json"));

  const cluster = overrides.cluster ?? (process.env.NETWORK as SolanaCluster | undefined) ?? rootConfig?.defaultCluster ?? "localnet";
  const programsForCluster = rootConfig?.programs?.[cluster] ?? {};
  const rpcUrl = overrides.rpcUrl ?? process.env.RPC_URL ?? DEFAULT_RPC_BY_CLUSTER[cluster];
  const keypairPath = expandHome(overrides.keypairPath ?? process.env.KEYPAIR ?? rootConfig?.wallet?.path ?? "~/.config/solana/id.json");

  return {
    cluster,
    rpcUrl,
    keypairPath,
    programs: overrides.programs ?? {
      utxopiaProgramId: requiredPublicKey(
        "UTXOPIA_PROGRAM_ID",
        process.env.UTXOPIA_PROGRAM_ID ?? process.env.PROGRAM_ID ?? programsForCluster.UTXOpia,
      ),
      btcLightClientProgramId: requiredPublicKey(
        "BTC_LIGHT_CLIENT_PROGRAM_ID",
        process.env.BTC_LIGHT_CLIENT_PROGRAM_ID ?? programsForCluster.btc_light_client,
      ),
      chadbufferProgramId: optionalPublicKey(process.env.CHADBUFFER_PROGRAM_ID ?? programsForCluster.chadbuffer),
      groth16VerifierProgramId: optionalPublicKey(process.env.GROTH16_VERIFIER_PROGRAM_ID ?? programsForCluster.groth16_verifier),
    },
    btcNetwork: overrides.btcNetwork ?? (process.env.BTC_NETWORK as TestFlowConfig["btcNetwork"] | undefined) ?? "regtest",
    btcStartHeight: overrides.btcStartHeight ?? (process.env.BTC_START_HEIGHT ? Number(process.env.BTC_START_HEIGHT) : undefined),
    btcStartHash: overrides.btcStartHash ?? process.env.BTC_START_HASH,
  };
}

export function createConnection(config: Pick<TestFlowConfig, "rpcUrl">): Connection {
  return new Connection(config.rpcUrl, "confirmed");
}

export function loadKeypair(filePath: string): Keypair {
  return Keypair.fromSecretKey(Uint8Array.from(JSON.parse(fs.readFileSync(expandHome(filePath), "utf-8"))));
}
