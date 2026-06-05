#!/usr/bin/env bun
/**
 * Initialize Fresh UTXOpia Devnet Program
 *
 * For the new program ID: GFV24P4Ne3AMcuZJELaKQeuFQzCe7T3Ne8CdKPL7X7mM
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

// Fresh program ID (zKey vanity address)
const UTXOPIA_PROGRAM_ID = new PublicKey("zKeyrLmpT8W9o8iRvhizuSihLAFLhfAGBvfM638Pbw8");
const GROTH16_VERIFIER_ID = new PublicKey("5uAoTLSexeKKLU3ZXniWFE2CsCWGPzMiYPpKiywCGqsd");
const CHADBUFFER_ID = new PublicKey("C5RpjtTMFXKVZCtXSzKXD4CDNTaWBg3dVeMfYvjZYHDF");

const RPC_URL = "https://solana-devnet.g.alchemy.com/v2/y1zYW-ovVofq7OzZo0Z6IHenRnyq_Pbd";

const SEEDS = {
  POOL_STATE: "pool_state",
  COMMITMENT_TREE: "commitment_tree",
};

async function loadKeypair(keyPath: string): Promise<Keypair> {
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

async function main() {
  console.log("============================================================");
  console.log("Initialize Fresh UTXOpia on Devnet");
  console.log("============================================================\n");

  const connection = new Connection(RPC_URL, "confirmed");

  // Load wallet
  const authority = await loadKeypair("~/.config/solana/johnny.json");
  console.log(`Authority: ${authority.publicKey.toBase58()}`);
  console.log(`Program ID: ${UTXOPIA_PROGRAM_ID.toBase58()}`);

  // Check balance
  const balance = await connection.getBalance(authority.publicKey);
  console.log(`Balance: ${balance / 1e9} SOL`);

  // Derive PDAs
  const [poolStatePda, poolBump] = derivePoolStatePDA(UTXOPIA_PROGRAM_ID);
  const [commitmentTreePda, treeBump] = deriveCommitmentTreePDA(UTXOPIA_PROGRAM_ID);

  console.log(`\nPool State PDA: ${poolStatePda.toBase58()} (bump: ${poolBump})`);
  console.log(`Commitment Tree PDA: ${commitmentTreePda.toBase58()} (bump: ${treeBump})`);

  // Check if already initialized
  const poolAccount = await connection.getAccountInfo(poolStatePda);
  if (poolAccount) {
    console.log("\n✓ Pool already initialized!");

    // Parse existing state (pool_vault at offset 68 after removing privacy_cash_pool)
    const mintPubkey = new PublicKey(poolAccount.data.subarray(36, 68));
    const vaultPubkey = new PublicKey(poolAccount.data.subarray(68, 100));

    console.log(`  zkBTC Mint: ${mintPubkey.toBase58()}`);
    console.log(`  Pool Vault: ${vaultPubkey.toBase58()}`);

    // Save config
    const config = {
      network: "devnet",
      rpcUrl: RPC_URL,
      programs: {
        UTXOpia: UTXOPIA_PROGRAM_ID.toBase58(),
        groth16Verifier: GROTH16_VERIFIER_ID.toBase58(),
        chadbuffer: CHADBUFFER_ID.toBase58(),
      },
      accounts: {
        poolState: poolStatePda.toBase58(),
        commitmentTree: commitmentTreePda.toBase58(),
        zkbtcMint: mintPubkey.toBase58(),
        poolVault: vaultPubkey.toBase58(),
        authority: authority.publicKey.toBase58(),
      },
      createdAt: new Date().toISOString(),
    };

    fs.writeFileSync(
      path.join(__dirname, "..", ".devnet-config.json"),
      JSON.stringify(config, null, 2) + "\n"
    );
    console.log("\n✓ Updated .devnet-config.json");
    return;
  }

  // Create zkBTC Token-2022 mint
  console.log("\nCreating zkBTC Token-2022 mint...");
  const zkbtcMint = await createMint(
    connection,
    authority,
    authority.publicKey,
    null,
    8, // 8 decimals
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

  // Create frost vault
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
    UTXOPIA_PROGRAM_ID,
    poolBump,
    treeBump
  );

  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
    commitment: "confirmed",
  });
  console.log(`✓ UTXOpia initialized: ${sig}`);

  // Save devnet config
  const devnetConfig = {
    network: "devnet",
    rpcUrl: RPC_URL,
    programs: {
      UTXOpia: UTXOPIA_PROGRAM_ID.toBase58(),
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
  console.log("\n✓ Saved .devnet-config.json");

  console.log("\n============================================================");
  console.log("Initialization Complete!");
  console.log("============================================================");
  console.log(`  Program ID:    ${UTXOPIA_PROGRAM_ID.toBase58()}`);
  console.log(`  Pool State:    ${poolStatePda.toBase58()}`);
  console.log(`  Commit Tree:   ${commitmentTreePda.toBase58()}`);
  console.log(`  zkBTC Mint:    ${zkbtcMint.toBase58()}`);
  console.log(`  Pool Vault:    ${poolVaultAccount.address.toBase58()}`);
}

main().catch((err) => {
  console.error("Error:", err);
  process.exit(1);
});
