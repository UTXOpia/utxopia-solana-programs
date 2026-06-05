#!/usr/bin/env bun
/**
 * Deploy Fresh UTXOpia to Devnet
 *
 * Creates a completely new deployment with:
 * - New program ID (fresh keypair)
 * - New pool state, commitment tree, mint, vault
 * - Keeps existing chadbuffer and verifier program IDs
 *
 * This is needed because the current devnet deployment has
 * an outdated commitment tree account size (3312 vs 3952 bytes).
 */

import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, sendAndConfirmTransaction } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID, createMint, getOrCreateAssociatedTokenAccount } from "@solana/spl-token";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const RPC_URL = "https://api.devnet.solana.com";

// Keep these existing programs
const CHADBUFFER_ID = new PublicKey("C5RpjtTMFXKVZCtXSzKXD4CDNTaWBg3dVeMfYvjZYHDF");
const GROTH16_VERIFIER_ID = new PublicKey("5uAoTLSexeKKLU3ZXniWFE2CsCWGPzMiYPpKiywCGqsd");

const SEEDS = {
  POOL_STATE: "pool_state",
  COMMITMENT_TREE: "commitment_tree",
};

function loadKeypair(keyPath: string): Keypair {
  const absolutePath = keyPath.replace("~", process.env.HOME || "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

function derivePoolStatePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEEDS.POOL_STATE)],
    programId
  );
}

function deriveCommitmentTreePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(SEEDS.COMMITMENT_TREE), Buffer.from([0, 0, 0, 0])],
    programId
  );
}

function buildInitializeIx(
  poolState: PublicKey,
  commitmentTree: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
  frostVault: PublicKey,
  authority: PublicKey,
  programId: PublicKey,
  poolBump: number,
  treeBump: number
): TransactionInstruction {
  const data = Buffer.alloc(7);
  data[0] = 0; // INITIALIZE discriminator
  data[1] = poolBump;
  data[2] = treeBump;
  data.writeUInt16LE(0, 3); // deposit_fee_bps
  data.writeUInt16LE(0, 5); // withdrawal_fee_bps

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: zkbtcMint, isSigner: false, isWritable: false },
      { pubkey: poolVault, isSigner: false, isWritable: false },
      { pubkey: frostVault, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data,
  });
}

// Parse --env flag (default: "devnet")
const envArg = process.argv.find((a) => a.startsWith("--env="))?.split("=")[1]
  || process.argv[process.argv.indexOf("--env") + 1]
  || "devnet";

async function main() {
  console.log("=".repeat(60));
  console.log(`Deploy Fresh UTXOpia to Devnet (env: ${envArg})`);
  console.log("=".repeat(60));
  console.log();
  console.log("This will:");
  console.log("1. Generate a new program keypair");
  console.log("2. Build the program with devnet features");
  console.log("3. Deploy to devnet with new program ID");
  console.log("4. Initialize pool state, commitment tree, mint, vault");
  console.log();

  const connection = new Connection(RPC_URL, "confirmed");

  // Load authority keypair (johnny.json)
  const authority = loadKeypair("~/.config/solana/johnny.json");
  console.log(`Authority: ${authority.publicKey.toBase58()}`);

  // Check balance
  const balance = await connection.getBalance(authority.publicKey);
  console.log(`Balance: ${balance / 1e9} SOL`);

  if (balance < 3 * 1e9) {
    console.log("\n⚠️  Low balance! Need at least 3 SOL for deployment.");
    console.log("Request airdrop or transfer SOL to continue.");
    return;
  }

  // Generate new program keypair
  const programKeypair = Keypair.generate();
  const programKeypairPath = path.join(__dirname, "..", "target", "deploy", "aegis-new-keypair.json");

  console.log(`\nNew Program ID: ${programKeypair.publicKey.toBase58()}`);

  // Save program keypair
  fs.writeFileSync(
    programKeypairPath,
    JSON.stringify(Array.from(programKeypair.secretKey))
  );
  console.log(`Saved keypair to: ${programKeypairPath}`);

  // Build program
  console.log("\nBuilding program with devnet features...");
  try {
    execSync(
      "cargo build-sbf --features devnet",
      { cwd: path.join(__dirname, ".."), stdio: "inherit" }
    );
  } catch (error) {
    console.error("Build failed!");
    return;
  }

  // Deploy program
  console.log("\nDeploying program...");
  try {
    execSync(
      `solana program deploy ` +
      `--url ${RPC_URL} ` +
      `--program-id ${programKeypairPath} ` +
      `--keypair ~/.config/solana/johnny.json ` +
      `target/deploy/utxopia.so`,
      { cwd: path.join(__dirname, ".."), stdio: "inherit" }
    );
  } catch (error) {
    console.error("Deployment failed!");
    return;
  }

  const programId = programKeypair.publicKey;
  console.log(`\n✓ Program deployed: ${programId.toBase58()}`);

  // Derive PDAs
  const [poolStatePda, poolBump] = derivePoolStatePDA(programId);
  const [commitmentTreePda, treeBump] = deriveCommitmentTreePDA(programId);

  console.log(`\nPool State PDA: ${poolStatePda.toBase58()} (bump: ${poolBump})`);
  console.log(`Commitment Tree PDA: ${commitmentTreePda.toBase58()} (bump: ${treeBump})`);

  // Create zkBTC Token-2022 mint
  console.log("\nCreating zkBTC Token-2022 mint...");
  const zkbtcMint = await createMint(
    connection,
    authority,
    poolStatePda, // Mint authority is pool PDA
    null,
    8, // 8 decimals like BTC
    Keypair.generate(),
    undefined,
    TOKEN_2022_PROGRAM_ID
  );
  console.log(`✓ zkBTC Mint: ${zkbtcMint.toBase58()}`);

  // Create pool vault
  console.log("Creating pool vault...");
  const poolVaultAccount = await getOrCreateAssociatedTokenAccount(
    connection,
    authority,
    zkbtcMint,
    poolStatePda,
    true, // allowOwnerOffCurve (PDA)
    undefined,
    undefined,
    TOKEN_2022_PROGRAM_ID
  );
  console.log(`✓ Pool Vault: ${poolVaultAccount.address.toBase58()}`);

  // Create frost vault (authority's token account for now)
  console.log("Creating frost vault...");
  const frostVaultAccount = await getOrCreateAssociatedTokenAccount(
    connection,
    authority,
    zkbtcMint,
    authority.publicKey,
    false,
    undefined,
    undefined,
    TOKEN_2022_PROGRAM_ID
  );
  console.log(`✓ Frost Vault: ${frostVaultAccount.address.toBase58()}`);

  // Initialize UTXOpia
  console.log("\nInitializing UTXOpia pool...");
  const ix = buildInitializeIx(
    poolStatePda,
    commitmentTreePda,
    zkbtcMint,
    poolVaultAccount.address,
    frostVaultAccount.address,
    authority.publicKey,
    programId,
    poolBump,
    treeBump
  );

  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
    commitment: "confirmed",
  });
  console.log(`✓ UTXOpia initialized: ${sig}`);

  // Verify commitment tree size
  const treeInfo = await connection.getAccountInfo(commitmentTreePda);
  console.log(`\nCommitment Tree size: ${treeInfo?.data.length} bytes (expected: 3952)`);

  // Save new devnet config
  const devnetConfig = {
    network: "devnet",
    rpcUrl: RPC_URL,
    programs: {
      UTXOpia: programId.toBase58(),
      groth16Verifier: GROTH16_VERIFIER_ID.toBase58(),
      chadbuffer: CHADBUFFER_ID.toBase58(),
    },
    accounts: {
      poolState: poolStatePda.toBase58(),
      commitmentTree: commitmentTreePda.toBase58(),
      zkbtcMint: zkbtcMint.toBase58(),
      poolVault: poolVaultAccount.address.toBase58(),
      authority: authority.publicKey.toBase58(),
    },
    createdAt: new Date().toISOString(),
  };

  const configFileName = `.${envArg}-config.json`;
  fs.writeFileSync(
    path.join(__dirname, "..", configFileName),
    JSON.stringify(devnetConfig, null, 2) + "\n"
  );
  console.log(`\n✓ Saved ${configFileName}`);

  console.log("\n" + "=".repeat(60));
  console.log("Deployment Complete!");
  console.log("=".repeat(60));
  console.log(`  Environment:   ${envArg}`);
  console.log(`  Program ID:    ${programId.toBase58()}`);
  console.log(`  Pool State:    ${poolStatePda.toBase58()}`);
  console.log(`  Commit Tree:   ${commitmentTreePda.toBase58()}`);
  console.log(`  zkBTC Mint:    ${zkbtcMint.toBase58()}`);
  console.log(`  Pool Vault:    ${poolVaultAccount.address.toBase58()}`);
  console.log();
  console.log("Set these env vars to use this deployment:");
  console.log();
  console.log("  # Frontend (utxopia-app/.env.local):");
  console.log(`  NEXT_PUBLIC_UTXOPIA_PROGRAM_ID=${programId.toBase58()}`);
  console.log(`  NEXT_PUBLIC_ZKBTC_MINT=${zkbtcMint.toBase58()}`);
  console.log();
  console.log("  # Backend (.env):");
  console.log(`  UTXOPIA_PROGRAM_ID=${programId.toBase58()}`);
  console.log(`  UTXOPIA_ZKBTC_MINT=${zkbtcMint.toBase58()}`);
  console.log();
  console.log("  # Scripts:");
  console.log(`  UTXOPIA_PROGRAM_ID=${programId.toBase58()}`);
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
