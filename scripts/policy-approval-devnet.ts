#!/usr/bin/env bun
/**
 * Run one complete UTXOpia PolicyApproval lifecycle on MagicBlock PER devnet.
 *
 * Asset state is never delegated. Only the one-time approval PDA moves to the
 * TEE validator, receives a private decision, and commits back to Solana.
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  DELEGATION_PROGRAM_ID,
  EPHEMERAL_VAULT_ID,
  MAGIC_CONTEXT_ID,
  MAGIC_PROGRAM_ID,
  PERMISSION_PROGRAM_ID,
  ConnectionMagicRouter,
  delegateBufferPdaFromDelegatedAccountAndOwnerProgram,
  delegationMetadataPdaFromDelegatedAccount,
  delegationRecordPdaFromDelegatedAccount,
  getAuthToken,
  permissionPdaFromAccount,
  verifyTeeRpcIntegrity,
} from "@magicblock-labs/ephemeral-rollups-sdk";
import nacl from "tweetnacl";
import { createHash, randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const DEFAULT_ROUTER_URL = "https://devnet-router.magicblock.app";
const DEFAULT_TEE_URL = "https://devnet-tee-as.magicblock.app";
const DEFAULT_BASE_RPC = "https://rpc.magicblock.app/devnet";
const DEFAULT_POLICY_PROGRAM = "9asWYKVriWGpExW5xM44ChHjZtispkLCiWKkM8SQi8Rs";
const TEE_VALIDATOR = new PublicKey("MTEWGuqxUpYZGFJQcp8tLN7x5v9BSeoFHYWQQ3n3xzo");
const ACTION_TRANSACT = 13;
const POLICY_PENDING = 0;
const POLICY_APPROVED = 1;

interface DeploymentConfig {
  rpcUrl?: string;
  programs: { UTXOpia: string };
  accounts: { poolState: string; authority: string };
}

function arg(name: string): string | undefined {
  const index = process.argv.indexOf(name);
  return index >= 0 ? process.argv[index + 1] : undefined;
}

function loadKeypair(filename: string): Keypair {
  const pathname = filename.startsWith("~/")
    ? resolve(homedir(), filename.slice(2))
    : resolve(filename);
  return Keypair.fromSecretKey(
    Uint8Array.from(JSON.parse(readFileSync(pathname, "utf8")) as number[]),
  );
}

function u64le(value: bigint): Buffer {
  const result = Buffer.alloc(8);
  result.writeBigUInt64LE(value);
  return result;
}

function policyHash(
  program: PublicKey,
  pool: PublicKey,
  actor: PublicKey,
  instructionData: Buffer,
): Buffer {
  return createHash("sha256")
    .update("UTXOPIA_POLICY_APPROVAL_V1")
    .update(program.toBuffer())
    .update(pool.toBuffer())
    .update(actor.toBuffer())
    .update(instructionData)
    .digest();
}

async function send(
  connection: Connection,
  payer: Keypair,
  instructions: TransactionInstruction[],
): Promise<string> {
  return sendAndConfirmTransaction(
    connection,
    new Transaction().add(...instructions),
    [payer],
    { commitment: "confirmed", skipPreflight: false },
  );
}

async function waitForDelegation(
  router: ConnectionMagicRouter,
  approval: PublicKey,
): Promise<Record<string, unknown>> {
  for (let attempt = 0; attempt < 45; attempt += 1) {
    const status = await router.getDelegationStatus(approval) as unknown as Record<string, unknown>;
    if (status.isDelegated === true) return status;
    await Bun.sleep(1_000);
  }
  throw new Error(`Delegation did not become active for ${approval.toBase58()}`);
}

async function waitForBaseOwner(
  connection: Connection,
  approval: PublicKey,
  owner: PublicKey,
): Promise<Buffer> {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    const account = await connection.getAccountInfo(approval, "confirmed");
    if (account?.owner.equals(owner)) return Buffer.from(account.data);
    await Bun.sleep(1_000);
  }
  throw new Error(`Approval did not settle back to Solana: ${approval.toBase58()}`);
}

async function main(): Promise<void> {
  const configPath = resolve(arg("--config") ?? ".devnet-permissioned-config.json");
  const config = JSON.parse(readFileSync(configPath, "utf8")) as DeploymentConfig;
  const keypair = loadKeypair(arg("--keypair") ?? "~/.config/solana/id.json");
  const baseRpc = arg("--rpc") ?? config.rpcUrl ?? DEFAULT_BASE_RPC;
  const routerUrl = arg("--router") ?? DEFAULT_ROUTER_URL;
  const fallbackTeeUrl = (arg("--tee") ?? DEFAULT_TEE_URL).replace(/\/$/, "");
  const assetProgram = new PublicKey(config.programs.UTXOpia);
  const program = new PublicKey(arg("--policy-program") ?? DEFAULT_POLICY_PROGRAM);
  const pool = new PublicKey(config.accounts.poolState);
  const authority = new PublicKey(config.accounts.authority);
  if (!authority.equals(keypair.publicKey)) {
    throw new Error(`Keypair ${keypair.publicKey} is not pool authority ${authority}`);
  }

  const base = new Connection(baseRpc, "confirmed");
  const router = new ConnectionMagicRouter(routerUrl, "confirmed");
  const slot = await base.getSlot("confirmed");
  const expiresAt = BigInt(slot + 15_000);
  const nonce = randomBytes(32);
  // This lifecycle smoke test binds a harmless placeholder transact payload.
  // A real asset transaction must supply its exact complete instruction bytes.
  const assetInstructionData = Buffer.from([ACTION_TRANSACT, 0x50, 0x45, 0x52]);
  const requestHash = policyHash(assetProgram, pool, keypair.publicKey, assetInstructionData);
  const [freshApproval] = PublicKey.findProgramAddressSync(
    [Buffer.from("policy_approval"), pool.toBuffer(), requestHash, nonce],
    program,
  );
  const resumeAddress = arg("--resume");
  const approval = resumeAddress ? new PublicKey(resumeAddress) : freshApproval;
  let initializeSignature = "resumed";
  let delegateSignature = "resumed";
  let delegation: Record<string, unknown>;

  if (resumeAddress) {
    delegation = await waitForDelegation(router, approval);
  } else {
    const initializeData = Buffer.concat([
      Buffer.from([36, ACTION_TRANSACT]),
      u64le(expiresAt),
      keypair.publicKey.toBuffer(),
      requestHash,
      nonce,
    ]);
    const initialize = new TransactionInstruction({
      programId: program,
      keys: [
        { pubkey: keypair.publicKey, isSigner: true, isWritable: true },
        { pubkey: pool, isSigner: false, isWritable: false },
        { pubkey: approval, isSigner: false, isWritable: true },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      ],
      data: initializeData,
    });
    initializeSignature = await send(base, keypair, [initialize]);
    const initialized = await base.getAccountInfo(approval, "confirmed");
    if (!initialized || initialized.data[2] !== POLICY_PENDING) {
      throw new Error("PolicyApproval was not initialized as pending");
    }

    const delegate = new TransactionInstruction({
      programId: program,
      keys: [
        { pubkey: keypair.publicKey, isSigner: true, isWritable: true },
        { pubkey: keypair.publicKey, isSigner: true, isWritable: false },
        { pubkey: pool, isSigner: false, isWritable: false },
        { pubkey: approval, isSigner: false, isWritable: true },
        { pubkey: program, isSigner: false, isWritable: false },
        {
          pubkey: delegateBufferPdaFromDelegatedAccountAndOwnerProgram(approval, program),
          isSigner: false,
          isWritable: true,
        },
        {
          pubkey: delegationRecordPdaFromDelegatedAccount(approval),
          isSigner: false,
          isWritable: true,
        },
        {
          pubkey: delegationMetadataPdaFromDelegatedAccount(approval),
          isSigner: false,
          isWritable: true,
        },
        { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
        { pubkey: DELEGATION_PROGRAM_ID, isSigner: false, isWritable: false },
      ],
      data: Buffer.concat([
        Buffer.from([32, 2]),
        Buffer.from(Uint32Array.of(1_000).buffer),
        TEE_VALIDATOR.toBuffer(),
      ]),
    });
    delegateSignature = await send(base, keypair, [delegate]);
    delegation = await waitForDelegation(router, approval);
  }

  const teeUrl = (
    typeof delegation.fqdn === "string" ? delegation.fqdn : fallbackTeeUrl
  ).replace(/\/$/, "");
  const identity = await new ConnectionMagicRouter(teeUrl, "confirmed").getClosestValidator();
  if (identity.identity !== TEE_VALIDATOR.toBase58()) {
    throw new Error(`Unexpected TEE validator identity: ${identity.identity}`);
  }
  await verifyTeeRpcIntegrity(teeUrl);
  const { token, expiresAt: authExpiresAt } = await getAuthToken(
    teeUrl,
    keypair.publicKey,
    async (message) => nacl.sign.detached(message, keypair.secretKey),
  );
  const authenticatedUrl = `${teeUrl}?token=${encodeURIComponent(token)}`;
  const per = new Connection(authenticatedUrl, "confirmed");
  const permission = permissionPdaFromAccount(approval);
  const allVisibilityFlags = 0x1f;
  const createPermission = new TransactionInstruction({
    programId: program,
    keys: [
      { pubkey: keypair.publicKey, isSigner: true, isWritable: false },
      { pubkey: pool, isSigner: false, isWritable: false },
      { pubkey: approval, isSigner: false, isWritable: true },
      { pubkey: permission, isSigner: false, isWritable: true },
      { pubkey: EPHEMERAL_VAULT_ID, isSigner: false, isWritable: true },
      { pubkey: MAGIC_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: PERMISSION_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    data: Buffer.concat([
      Buffer.from([34, 0, 2, 1, allVisibilityFlags]),
      keypair.publicKey.toBuffer(),
    ]),
  });
  const permissionSignature = await send(per, keypair, [createPermission]);

  const decision = new TransactionInstruction({
    programId: program,
    keys: [
      { pubkey: keypair.publicKey, isSigner: true, isWritable: false },
      { pubkey: approval, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([37, 1]),
  });
  const decisionSignature = await send(per, keypair, [decision]);
  const approved = await per.getAccountInfo(approval, "confirmed");
  if (!approved || approved.data[2] !== POLICY_APPROVED) {
    throw new Error("PER decision did not approve the PolicyApproval");
  }

  const closePermission = new TransactionInstruction({
    programId: program,
    keys: createPermission.keys,
    data: Buffer.from([34, 2, 2, 0]),
  });
  const commit = new TransactionInstruction({
    programId: program,
    keys: [
      { pubkey: keypair.publicKey, isSigner: true, isWritable: false },
      { pubkey: MAGIC_CONTEXT_ID, isSigner: false, isWritable: true },
      { pubkey: MAGIC_PROGRAM_ID, isSigner: false, isWritable: false },
      { pubkey: approval, isSigner: false, isWritable: true },
    ],
    data: Buffer.from([38]),
  });
  const commitSignature = await send(per, keypair, [closePermission, commit]);
  const settled = await waitForBaseOwner(base, approval, program);
  if (settled[2] !== POLICY_APPROVED) {
    throw new Error(`Settled PolicyApproval has unexpected status ${settled[2]}`);
  }

  const result = {
    completedAt: new Date().toISOString(),
    assetProgram: assetProgram.toBase58(),
    policyProgram: program.toBase58(),
    pool: pool.toBase58(),
    policyApproval: approval.toBase58(),
    validator: identity.identity,
    teeIntegrityVerified: true,
    authExpiresAt,
    delegation,
    signatures: {
      initialize: initializeSignature,
      delegate: delegateSignature,
      permission: permissionSignature,
      decision: decisionSignature,
      closePermissionAndCommit: commitSignature,
    },
    settledStatus: "approved",
  };
  writeFileSync(".devnet-per-e2e.json", `${JSON.stringify(result, null, 2)}\n`, {
    mode: 0o600,
  });
  console.log(JSON.stringify(result, null, 2));
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
