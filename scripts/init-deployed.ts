#!/usr/bin/env bun
/**
 * Initialize an already-deployed UTXOpia program.
 * Creates mint, vault, deposit vault, and calls initialize instruction.
 */

import { Connection, Keypair, PublicKey, SystemProgram, Transaction, TransactionInstruction, sendAndConfirmTransaction } from "@solana/web3.js";
import { TOKEN_2022_PROGRAM_ID, createMint, getOrCreateAssociatedTokenAccount } from "@solana/spl-token";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const RPC_URL = "https://api.devnet.solana.com";
const CHADBUFFER_ID = new PublicKey("C5RpjtTMFXKVZCtXSzKXD4CDNTaWBg3dVeMfYvjZYHDF");
const GROTH16_VERIFIER_ID = new PublicKey("5uAoTLSexeKKLU3ZXniWFE2CsCWGPzMiYPpKiywCGqsd");

const PROGRAM_ID = new PublicKey("7JJeVjVCy1fZqCDWvf41R7LuTWirTjX7Tp6suC2WVUMQ");

function loadKeypair(keyPath: string): Keypair {
  const absolutePath = keyPath.replace("~", process.env.HOME || "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

function buildInitializeIx(
  poolState: PublicKey, commitmentTree: PublicKey, zkbtcMint: PublicKey,
  poolVault: PublicKey, depositVault: PublicKey, authority: PublicKey,
  programId: PublicKey, poolBump: number, treeBump: number
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
      { pubkey: depositVault, isSigner: false, isWritable: false },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
    ],
    programId,
    data,
  });
}

async function main() {
  const connection = new Connection(RPC_URL, "confirmed");
  const authority = loadKeypair("~/.config/solana/johnny.json");
  console.log(`Authority: ${authority.publicKey.toBase58()}`);
  console.log(`Program:   ${PROGRAM_ID.toBase58()}`);

  const [poolStatePda, poolBump] = PublicKey.findProgramAddressSync(
    [Buffer.from("pool_state")], PROGRAM_ID
  );
  const [commitmentTreePda, treeBump] = PublicKey.findProgramAddressSync(
    [Buffer.from("commitment_tree")], PROGRAM_ID
  );

  console.log(`Pool State PDA: ${poolStatePda.toBase58()} (bump: ${poolBump})`);
  console.log(`Commitment Tree PDA: ${commitmentTreePda.toBase58()} (bump: ${treeBump})`);

  // Create zkBTC Token-2022 mint
  console.log("\nCreating zkBTC Token-2022 mint...");
  const zkbtcMint = await createMint(
    connection, authority, poolStatePda, null, 8,
    Keypair.generate(), undefined, TOKEN_2022_PROGRAM_ID
  );
  console.log(`✓ zkBTC Mint: ${zkbtcMint.toBase58()}`);

  // Create pool vault
  console.log("Creating pool vault...");
  const poolVaultAccount = await getOrCreateAssociatedTokenAccount(
    connection, authority, zkbtcMint, poolStatePda, true,
    undefined, undefined, TOKEN_2022_PROGRAM_ID
  );
  console.log(`✓ Pool Vault: ${poolVaultAccount.address.toBase58()}`);

  // Create deposit vault
  console.log("Creating deposit vault...");
  const depositVaultAccount = await getOrCreateAssociatedTokenAccount(
    connection, authority, zkbtcMint, authority.publicKey, false,
    undefined, undefined, TOKEN_2022_PROGRAM_ID
  );
  console.log(`✓ Deposit Vault: ${depositVaultAccount.address.toBase58()}`);

  // Initialize UTXOpia
  console.log("\nInitializing UTXOpia pool...");
  const ix = buildInitializeIx(
    poolStatePda, commitmentTreePda, zkbtcMint,
    poolVaultAccount.address, depositVaultAccount.address,
    authority.publicKey, PROGRAM_ID, poolBump, treeBump
  );
  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [authority], { commitment: "confirmed" });
  console.log(`✓ UTXOpia initialized: ${sig}`);

  // Save config
  const devnetConfig = {
    network: "devnet",
    rpcUrl: RPC_URL,
    programs: {
      UTXOpia: PROGRAM_ID.toBase58(),
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

  fs.writeFileSync(
    path.join(__dirname, "..", ".devnet-config.json"),
    JSON.stringify(devnetConfig, null, 2) + "\n"
  );
  console.log(`\n✓ Saved .devnet-config.json`);

  console.log("\n" + "=".repeat(60));
  console.log("Initialization Complete!");
  console.log("=".repeat(60));
  console.log(`  Program ID:    ${PROGRAM_ID.toBase58()}`);
  console.log(`  Pool State:    ${poolStatePda.toBase58()}`);
  console.log(`  Commit Tree:   ${commitmentTreePda.toBase58()}`);
  console.log(`  zkBTC Mint:    ${zkbtcMint.toBase58()}`);
  console.log(`  Pool Vault:    ${poolVaultAccount.address.toBase58()}`);
  console.log();
  console.log(`  NEXT_PUBLIC_UTXOPIA_PROGRAM_ID=${PROGRAM_ID.toBase58()}`);
  console.log(`  NEXT_PUBLIC_ZKBTC_MINT=${zkbtcMint.toBase58()}`);
}

main().catch((err) => { console.error("Error:", err); process.exit(1); });
