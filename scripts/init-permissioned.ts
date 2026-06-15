#!/usr/bin/env bun
/**
 * Initialize an already-deployed UTXOpia program in PERMISSIONED mode.
 *
 * SINGLE-POOL CONSTRAINT
 * ──────────────────────
 * The Solana UTXOpia program uses a singleton PDA: seeds=[b"pool_state"].
 * There is exactly ONE pool per program deployment. The choice between
 * permissioned and permissionless is made at initialization time and is
 * irreversible without redeploying the program.
 *
 * If you need MULTIPLE permissioned pools you MUST deploy separate program
 * instances (each with a unique program ID). This script initializes THE ONE
 * pool as permissioned — do not attempt to call it twice on the same program.
 *
 * DISC-21 DATA LAYOUT (initialize_permissioned)
 * ──────────────────────────────────────────────
 * Byte  0        : discriminator = 21
 * Byte  1        : pool_bump (u8)
 * Byte  2        : tree_bump (u8)
 * Bytes 3–4      : deposit_fee_bps (u16 LE)
 * Bytes 5–6      : withdrawal_fee_bps (u16 LE)
 * Bytes 7–38     : auditor pubkey (32 bytes)
 * Bytes 39–70    : auditor_viewing_pubkey (32 bytes)
 * Total          : 71 bytes
 *
 * Source: programs/utxopia/src/instructions/initialize_permissioned.rs
 *         InitializePermissionedData::from_bytes (MIN_LEN = 70 for the payload,
 *         +1 byte for the leading discriminator passed by the router).
 *
 * The installed @utxopia/sdk does NOT expose buildInitializePermissionedInstruction,
 * so the instruction is built inline here from the Rust data layout above.
 *
 * USAGE
 * ─────
 *   bun scripts/init-permissioned.ts <auditorPubkey> [--viewing-pubkey <base58|hex>] \
 *     [--deposit-fee <bps>] [--withdrawal-fee <bps>] \
 *     [--rpc <url>] [--keypair <path>] [--program <id>] [--network <name>]
 *
 * EXAMPLE
 *   bun scripts/init-permissioned.ts 9xDef...abc \
 *     --viewing-pubkey 0xdeadbeef... \
 *     --deposit-fee 10 --withdrawal-fee 20
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
  TOKEN_2022_PROGRAM_ID,
  createMint,
  getOrCreateAssociatedTokenAccount,
} from "@solana/spl-token";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ─── Defaults ───────────────────────────────────────────────────────────────

const DEFAULT_RPC_URL = "https://api.devnet.solana.com";
const DEFAULT_KEYPAIR = "~/.config/solana/johnny.json";
const DEFAULT_PROGRAM_ID = "7JJeVjVCy1fZqCDWvf41R7LuTWirTjX7Tp6suC2WVUMQ";
const DEFAULT_NETWORK = "devnet";
const DEFAULT_DEPOSIT_FEE_BPS = 0;
const DEFAULT_WITHDRAWAL_FEE_BPS = 0;

// disc 21 — initialize_permissioned
const DISCRIMINATOR_INITIALIZE_PERMISSIONED = 21;

// ─── Helpers ─────────────────────────────────────────────────────────────────

function loadKeypair(keyPath: string): Keypair {
  const absolutePath = keyPath.replace("~", process.env.HOME ?? "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8")) as number[];
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

/**
 * Decode a viewing pubkey that may be provided as:
 *  - 32-byte hex string (with or without "0x" prefix)
 *  - base58 Solana pubkey (decoded to 32 bytes)
 *  - undefined → returns 32 zero bytes
 */
function decodeViewingPubkey(input: string | undefined): Uint8Array {
  if (!input) return new Uint8Array(32);

  const clean = input.startsWith("0x") || input.startsWith("0X")
    ? input.slice(2)
    : input;

  // If it looks like hex (64 hex chars = 32 bytes)
  if (/^[0-9a-fA-F]{64}$/.test(clean)) {
    const buf = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      buf[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return buf;
  }

  // Otherwise try base58 via PublicKey
  try {
    return new PublicKey(input).toBytes();
  } catch {
    throw new Error(
      `--viewing-pubkey must be a 32-byte hex string or a valid base58 Solana pubkey; got: ${input}`
    );
  }
}

/**
 * Build the initialize_permissioned instruction (discriminator 21).
 *
 * Data layout (71 bytes total):
 *   [0]     disc = 21
 *   [1]     pool_bump
 *   [2]     tree_bump
 *   [3..4]  deposit_fee_bps (u16 LE)
 *   [5..6]  withdrawal_fee_bps (u16 LE)
 *   [7..38] auditor (32 bytes)
 *   [39..70] auditor_viewing_pubkey (32 bytes)
 *
 * Accounts (same order as initialize):
 *   0  pool_state          writable
 *   1  commitment_tree     writable
 *   2  zkbtc_mint          readonly
 *   3  pool_vault          readonly
 *   4  deposit_vault       readonly
 *   5  authority           signer + writable
 *   6  system_program      readonly
 */
function buildInitializePermissionedIx(
  poolState: PublicKey,
  commitmentTree: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
  depositVault: PublicKey,
  authority: PublicKey,
  programId: PublicKey,
  poolBump: number,
  treeBump: number,
  depositFeeBps: number,
  withdrawalFeeBps: number,
  auditor: Uint8Array,
  auditorViewingPubkey: Uint8Array
): TransactionInstruction {
  // 1 (disc) + 1 (pool_bump) + 1 (tree_bump) + 2 (deposit_fee_bps) + 2 (withdrawal_fee_bps)
  // + 32 (auditor) + 32 (auditor_viewing_pubkey) = 71
  const data = Buffer.alloc(71);
  data[0] = DISCRIMINATOR_INITIALIZE_PERMISSIONED;
  data[1] = poolBump;
  data[2] = treeBump;
  data.writeUInt16LE(depositFeeBps, 3);
  data.writeUInt16LE(withdrawalFeeBps, 5);
  data.set(auditor, 7);
  data.set(auditorViewingPubkey, 39);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState,       isSigner: false, isWritable: true },
      { pubkey: commitmentTree,  isSigner: false, isWritable: true },
      { pubkey: zkbtcMint,       isSigner: false, isWritable: false },
      { pubkey: poolVault,       isSigner: false, isWritable: false },
      { pubkey: depositVault,    isSigner: false, isWritable: false },
      { pubkey: authority,       isSigner: true,  isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data,
  });
}

// ─── CLI arg parsing ──────────────────────────────────────────────────────────

function parseArgs() {
  const argv = process.argv.slice(2);

  if (argv.length === 0 || argv[0] === "--help" || argv[0] === "-h") {
    console.log(`
Usage:
  bun scripts/init-permissioned.ts <auditorPubkey> [options]

Required:
  <auditorPubkey>               Base58 Solana pubkey of the auditor

Options:
  --viewing-pubkey <base58|hex> Auditor viewing pubkey (32-byte hex or base58; default: zero bytes)
  --deposit-fee <bps>           Deposit fee in basis points (default: ${DEFAULT_DEPOSIT_FEE_BPS})
  --withdrawal-fee <bps>        Withdrawal fee in basis points (default: ${DEFAULT_WITHDRAWAL_FEE_BPS})
  --rpc <url>                   RPC endpoint (default: ${DEFAULT_RPC_URL})
  --keypair <path>              Authority keypair path (default: ${DEFAULT_KEYPAIR})
  --program <id>                Program ID (default: ${DEFAULT_PROGRAM_ID})
  --network <name>              Network label for the config file (default: ${DEFAULT_NETWORK})
  --help                        Show this help message

NOTE: Solana UTXOpia is single-pool per program deployment. Initializing as
      permissioned is permanent for this program ID. For multiple permissioned
      pools, deploy separate program instances.
`);
    process.exit(0);
  }

  const auditorPubkeyStr = argv[0];
  if (!auditorPubkeyStr || auditorPubkeyStr.startsWith("--")) {
    console.error("Error: <auditorPubkey> is required as the first positional argument.");
    process.exit(1);
  }

  // Validate auditor pubkey early
  let auditorPubkey: PublicKey;
  try {
    auditorPubkey = new PublicKey(auditorPubkeyStr);
  } catch {
    console.error(`Error: Invalid auditor pubkey: ${auditorPubkeyStr}`);
    process.exit(1);
  }

  let viewingPubkeyStr: string | undefined;
  let depositFeeBps = DEFAULT_DEPOSIT_FEE_BPS;
  let withdrawalFeeBps = DEFAULT_WITHDRAWAL_FEE_BPS;
  let rpcUrl = DEFAULT_RPC_URL;
  let keypairPath = DEFAULT_KEYPAIR;
  let programIdStr = DEFAULT_PROGRAM_ID;
  let network = DEFAULT_NETWORK;

  for (let i = 1; i < argv.length; i++) {
    const flag = argv[i];
    const next = argv[i + 1];
    switch (flag) {
      case "--viewing-pubkey":
        viewingPubkeyStr = next;
        i++;
        break;
      case "--deposit-fee":
        depositFeeBps = parseInt(next ?? "", 10);
        if (isNaN(depositFeeBps)) { console.error("Error: --deposit-fee must be a number"); process.exit(1); }
        i++;
        break;
      case "--withdrawal-fee":
        withdrawalFeeBps = parseInt(next ?? "", 10);
        if (isNaN(withdrawalFeeBps)) { console.error("Error: --withdrawal-fee must be a number"); process.exit(1); }
        i++;
        break;
      case "--rpc":
        rpcUrl = next ?? rpcUrl;
        i++;
        break;
      case "--keypair":
        keypairPath = next ?? keypairPath;
        i++;
        break;
      case "--program":
        programIdStr = next ?? programIdStr;
        i++;
        break;
      case "--network":
        network = next ?? network;
        i++;
        break;
      default:
        console.error(`Unknown flag: ${flag}`);
        process.exit(1);
    }
  }

  return {
    auditorPubkey,
    viewingPubkeyStr,
    depositFeeBps,
    withdrawalFeeBps,
    rpcUrl,
    keypairPath,
    programIdStr,
    network,
  };
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const {
    auditorPubkey,
    viewingPubkeyStr,
    depositFeeBps,
    withdrawalFeeBps,
    rpcUrl,
    keypairPath,
    programIdStr,
    network,
  } = parseArgs();

  const PROGRAM_ID = new PublicKey(programIdStr);
  const auditorBytes = auditorPubkey.toBytes();
  const auditorViewingBytes = decodeViewingPubkey(viewingPubkeyStr);

  const connection = new Connection(rpcUrl, "confirmed");
  const authority = loadKeypair(keypairPath);

  console.log("=".repeat(60));
  console.log("UTXOpia — init-permissioned");
  console.log("=".repeat(60));
  console.log(`Authority:        ${authority.publicKey.toBase58()}`);
  console.log(`Program:          ${PROGRAM_ID.toBase58()}`);
  console.log(`Auditor:          ${auditorPubkey.toBase58()}`);
  console.log(
    `Viewing pubkey:   ${
      auditorViewingBytes.every((b) => b === 0)
        ? "(zero — not set)"
        : Buffer.from(auditorViewingBytes).toString("hex")
    }`
  );
  console.log(`Deposit fee:      ${depositFeeBps} bps`);
  console.log(`Withdrawal fee:   ${withdrawalFeeBps} bps`);
  console.log(`RPC:              ${rpcUrl}`);
  console.log();
  console.log(
    "NOTE: This program is SINGLE-POOL. Initializing as permissioned is an\n" +
    "      irreversible init-time choice. For multiple permissioned pools, deploy\n" +
    "      separate program instances with distinct program IDs."
  );
  console.log();

  // Derive PDAs
  const [poolStatePda, poolBump] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_state")],
    PROGRAM_ID
  );
  const [commitmentTreePda, treeBump] = PublicKey.findProgramAddressSync(
    [Buffer.from("commitment_tree"), Buffer.from(new Uint8Array(4))], // index 0 as u32 LE
    PROGRAM_ID
  );

  console.log(`Pool State PDA:   ${poolStatePda.toBase58()} (bump: ${poolBump})`);
  console.log(`Commitment Tree:  ${commitmentTreePda.toBase58()} (bump: ${treeBump})`);

  // Create zkBTC Token-2022 mint
  console.log("\nCreating zkBTC Token-2022 mint...");
  const zkbtcMint = await createMint(
    connection,
    authority,
    poolStatePda,
    null,
    8,
    Keypair.generate(),
    undefined,
    TOKEN_2022_PROGRAM_ID
  );
  console.log(`  zkBTC Mint:     ${zkbtcMint.toBase58()}`);

  // Create pool vault (owned by pool_state PDA)
  console.log("Creating pool vault...");
  const poolVaultAccount = await getOrCreateAssociatedTokenAccount(
    connection,
    authority,
    zkbtcMint,
    poolStatePda,
    true,
    undefined,
    undefined,
    TOKEN_2022_PROGRAM_ID
  );
  console.log(`  Pool Vault:     ${poolVaultAccount.address.toBase58()}`);

  // Create deposit vault (owned by authority)
  console.log("Creating deposit vault...");
  const depositVaultAccount = await getOrCreateAssociatedTokenAccount(
    connection,
    authority,
    zkbtcMint,
    authority.publicKey,
    false,
    undefined,
    undefined,
    TOKEN_2022_PROGRAM_ID
  );
  console.log(`  Deposit Vault:  ${depositVaultAccount.address.toBase58()}`);

  // Build and send initialize_permissioned instruction (disc 21)
  console.log("\nSending initialize_permissioned (disc 21)...");
  const ix = buildInitializePermissionedIx(
    poolStatePda,
    commitmentTreePda,
    zkbtcMint,
    poolVaultAccount.address,
    depositVaultAccount.address,
    authority.publicKey,
    PROGRAM_ID,
    poolBump,
    treeBump,
    depositFeeBps,
    withdrawalFeeBps,
    auditorBytes,
    auditorViewingBytes
  );

  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
    commitment: "confirmed",
  });
  console.log(`  Tx signature:   ${sig}`);
  console.log("  UTXOpia permissioned pool initialized.");

  // Compute hex of viewing pubkey for the config file
  const auditorViewingPubkeyHex = Buffer.from(auditorViewingBytes).toString("hex");

  // Write config JSON — mirrors .devnet-config.json + adds permissioned fields
  const configFilename = `.${network}-config.json`;
  const outConfig = {
    network,
    rpcUrl,
    permissioned: true,
    auditor: auditorPubkey.toBase58(),
    auditorViewingPubkey: auditorViewingPubkeyHex,
    programs: {
      UTXOpia: PROGRAM_ID.toBase58(),
    },
    accounts: {
      poolState: poolStatePda.toBase58(),
      commitmentTree: commitmentTreePda.toBase58(),
      zkbtcMint: zkbtcMint.toBase58(),
      poolVault: poolVaultAccount.address.toBase58(),
      depositVault: depositVaultAccount.address.toBase58(),
      authority: authority.publicKey.toBase58(),
    },
    createdAt: new Date().toISOString(),
  };

  const outPath = path.join(__dirname, "..", configFilename);
  fs.writeFileSync(outPath, JSON.stringify(outConfig, null, 2) + "\n");
  console.log(`\n  Saved ${configFilename}`);

  // Summary
  console.log("\n" + "=".repeat(60));
  console.log("Permissioned Initialization Complete!");
  console.log("=".repeat(60));
  console.log(`  Program ID:         ${PROGRAM_ID.toBase58()}`);
  console.log(`  Pool State:         ${poolStatePda.toBase58()}`);
  console.log(`  Commitment Tree:    ${commitmentTreePda.toBase58()}`);
  console.log(`  zkBTC Mint:         ${zkbtcMint.toBase58()}`);
  console.log(`  Pool Vault:         ${poolVaultAccount.address.toBase58()}`);
  console.log(`  Auditor:            ${auditorPubkey.toBase58()}`);
  console.log(`  Viewing Pubkey:     ${auditorViewingPubkeyHex}`);
  console.log(`  Permissioned:       true`);
  console.log();
  console.log(`  NEXT_PUBLIC_UTXOPIA_PROGRAM_ID=${PROGRAM_ID.toBase58()}`);
  console.log(`  NEXT_PUBLIC_ZKBTC_MINT=${zkbtcMint.toBase58()}`);
  console.log(`  NEXT_PUBLIC_UTXOPIA_PERMISSIONED=true`);
  console.log(`  NEXT_PUBLIC_UTXOPIA_AUDITOR=${auditorPubkey.toBase58()}`);
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
