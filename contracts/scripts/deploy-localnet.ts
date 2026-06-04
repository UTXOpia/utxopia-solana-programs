#!/usr/bin/env bun
/**
 * Deploy and Initialize UTXOpia on Localnet
 *
 * This script:
 * 1. Deploys both UTXOpia and BTC Light Client programs
 * 2. Initializes the BTC Light Client with a test block
 * 3. Creates the zkBTC Token-2022 mint
 * 4. Initializes the UTXOpia pool state and commitment tree
 * 5. Adds demo notes for testing
 *
 * Prerequisites:
 *   - solana-test-validator running with Poseidon feature enabled:
 *
 *     # Option 1: Clone feature set from devnet (recommended)
 *     solana-test-validator --clone-feature-set --url devnet --reset
 *
 *     # Option 2: Use localnet feature (SHA256 fallback, for testing only)
 *     # Build with: cargo build-sbf --features localnet
 *     # Then run: solana-test-validator --reset
 *
 *   - Programs built (run: cargo build-sbf --features devnet)
 *
 * Usage:
 *   bun run scripts/deploy-localnet.ts
 *   bun run scripts/deploy-localnet.ts --skip-deploy  # Skip deployment, only initialize
 *   bun run scripts/deploy-localnet.ts --skip-demo    # Skip demo notes
 */

import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  LAMPORTS_PER_SOL,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  getOrCreateAssociatedTokenAccount,
  createInitializeMintInstruction,
  getMintLen,
  ExtensionType,
} from "@solana/spl-token";
import { sha256 } from "@noble/hashes/sha2.js";
import * as fs from "fs";
import * as path from "path";
import { fileURLToPath } from "url";

// SDK imports for demo stealth instruction
import {
  buildAddDemoStealthData,
  initPoseidon,
  computeUnifiedCommitmentSync,
  ed25519GenerateKeyPair,
  x25519Ecdh,
  encryptAmount,
  babyJubMul,
  BABYJUB_BASE8,
  randomFieldElement,
} from "@utxopia/sdk";
import { execSync } from "child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// =============================================================================
// Configuration
// =============================================================================

const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const CONTRACTS_DIR = path.join(__dirname, "..");
const TARGET_DIR = path.join(CONTRACTS_DIR, "target/deploy");
const CONFIG_PATH = path.join(CONTRACTS_DIR, "config.json");

// Load config to get program paths
const config = JSON.parse(fs.readFileSync(CONFIG_PATH, "utf-8"));

// Seeds for UTXOpia PDAs
const PC_Seeds = {
  POOL_STATE: "pool_state",
  COMMITMENT_TREE: "commitment_tree",
};

// Seeds for BTC Light Client PDAs
const BTCLCSeeds = {
  LIGHT_CLIENT: "btc_light_client",
  BLOCK: "block",
  HEIGHT_INDEX: "height_index",
};

// Instruction discriminators
const PC_Instruction = {
  INITIALIZE: 0,
  ADD_DEMO_STEALTH: 13,
};

const BTCLCInstruction = {
  INITIALIZE: 0,
};

// Discriminators for parsing
const Discriminators = {
  POOL_STATE: 0x01,
  COMMITMENT_TREE: 0x05,
  LIGHT_CLIENT: 0x06,
};

// Bitcoin block for light client initialization
// For regtest: use a recent regtest block hash
// For testnet: use a known testnet block
const BTC_NETWORK = { mainnet: 0, testnet: 1, testnet4: 2, regtest: 3 }[process.env.BTC_NETWORK || "testnet"] ?? 1;
const BTC_START_HEIGHT = process.env.BTC_START_HEIGHT
  ? BigInt(process.env.BTC_START_HEIGHT)
  : 2500000n;
const BTC_START_HASH = process.env.BTC_START_HASH
  || "0000000000000023b3a1a1e1d1c1b1a191817161514131211101f0e0d0c0b0a09";

// Block hash is stored in internal byte order (reversed from display)
function reverseHex(hex: string): Buffer {
  const buf = Buffer.from(hex, "hex");
  return Buffer.from(buf.reverse());
}

const TEST_BTC_BLOCK = {
  height: BTC_START_HEIGHT,
  hash: reverseHex(BTC_START_HASH),
  network: BTC_NETWORK,
};

// =============================================================================
// Types
// =============================================================================

interface DeployResult {
  utxopiaProgramId: PublicKey;
  btcLightClientProgramId: PublicKey;
  chadbufferProgramId: PublicKey;
  groth16VerifierProgramId: PublicKey;
}

interface InitResult {
  poolStatePda: PublicKey;
  commitmentTreePda: PublicKey;
  btcLightClientPda: PublicKey;
  zkbtcMint: PublicKey;
  poolVault: PublicKey;
  authority: PublicKey;
}

// =============================================================================
// Helpers
// =============================================================================

function log(msg: string) {
  console.log(`[${new Date().toISOString().split("T")[1].slice(0, 8)}] ${msg}`);
}

function logSection(title: string) {
  console.log("\n" + "=".repeat(60));
  console.log(title);
  console.log("=".repeat(60) + "\n");
}

async function loadKeypair(keyPath: string): Promise<Keypair> {
  const absolutePath = keyPath.replace("~", process.env.HOME || "");
  const secretKey = JSON.parse(fs.readFileSync(absolutePath, "utf-8"));
  return Keypair.fromSecretKey(Uint8Array.from(secretKey));
}

function generateSecret(): Uint8Array {
  const secret = new Uint8Array(32);
  crypto.getRandomValues(secret);
  return secret;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// =============================================================================
// Deployment Functions
// =============================================================================

async function deployPrograms(skipDeploy: boolean): Promise<DeployResult> {
  logSection("Program Deployment");

  // Get program IDs from keypairs
  const utxopiaKeypairPath = path.join(TARGET_DIR, "utxopia-keypair.json");
  const btclcKeypairPath = path.join(TARGET_DIR, "btc_light_client-keypair.json");
  const chadbufferKeypairPath = path.join(CONTRACTS_DIR, "programs/chadbuffer/chadbuffer-keypair.json");
  const groth16KeypairPath = path.join(TARGET_DIR, "groth16_verifier-keypair.json");
  const chadbufferSoPath = path.join(CONTRACTS_DIR, "programs/chadbuffer/chadbuffer.so");

  if (!fs.existsSync(utxopiaKeypairPath) || !fs.existsSync(btclcKeypairPath)) {
    throw new Error("Program keypairs not found. Run 'cargo build-sbf' first.");
  }

  const utxopiaKeypair = await loadKeypair(utxopiaKeypairPath);
  const btclcKeypair = await loadKeypair(btclcKeypairPath);

  // Load chadbuffer and groth16 keypairs
  let chadbufferKeypair: Keypair;
  let groth16Keypair: Keypair;

  if (fs.existsSync(chadbufferKeypairPath)) {
    chadbufferKeypair = await loadKeypair(chadbufferKeypairPath);
  } else {
    log("ChadBuffer keypair not found, generating new one...");
    chadbufferKeypair = Keypair.generate();
    fs.writeFileSync(chadbufferKeypairPath, JSON.stringify(Array.from(chadbufferKeypair.secretKey)));
  }

  if (fs.existsSync(groth16KeypairPath)) {
    groth16Keypair = await loadKeypair(groth16KeypairPath);
  } else {
    log("Groth16 keypair not found, generating new one...");
    groth16Keypair = Keypair.generate();
  }

  const utxopiaProgramId = utxopiaKeypair.publicKey;
  const btcLightClientProgramId = btclcKeypair.publicKey;
  const chadbufferProgramId = chadbufferKeypair.publicKey;
  const groth16VerifierProgramId = groth16Keypair.publicKey;

  log(`UTXOpia Program ID: ${utxopiaProgramId.toBase58()}`);
  log(`BTC Light Client Program ID: ${btcLightClientProgramId.toBase58()}`);
  log(`ChadBuffer Program ID: ${chadbufferProgramId.toBase58()}`);
  log(`Groth16 Verifier Program ID: ${groth16VerifierProgramId.toBase58()}`);

  if (skipDeploy) {
    log("Skipping deployment (--skip-deploy flag)");
    return { utxopiaProgramId, btcLightClientProgramId, chadbufferProgramId, groth16VerifierProgramId };
  }

  // Deploy via surfnet_writeProgram RPC (no Solana CLI needed)
  async function deployViaSurfpool(programId: string, soPath: string, label: string) {
    const soData = fs.readFileSync(soPath);
    const hexData = soData.toString("hex");
    const resp = await fetch("http://127.0.0.1:8899", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0", id: 1,
        method: "surfnet_writeProgram",
        params: [programId, hexData, 0],
      }),
    });
    const result = await resp.json() as any;
    if (result.error) throw new Error(`Failed to deploy ${label}: ${JSON.stringify(result.error)}`);
    log(`${label} deployed at ${programId}`);
  }

  // Deploy UTXOpia
  log("Deploying UTXOpia program...");
  await deployViaSurfpool(utxopiaProgramId.toBase58(), `${TARGET_DIR}/utxopia.so`, "UTXOpia");

  // Deploy BTC Light Client
  log("Deploying BTC Light Client program...");
  await deployViaSurfpool(btcLightClientProgramId.toBase58(), `${TARGET_DIR}/btc_light_client.so`, "BTC Light Client");

  // Deploy ChadBuffer
  if (fs.existsSync(chadbufferSoPath)) {
    log("Deploying ChadBuffer program...");
    await deployViaSurfpool(chadbufferProgramId.toBase58(), chadbufferSoPath, "ChadBuffer");
  } else {
    log(`ChadBuffer .so not found at ${chadbufferSoPath}`);
    log("To build ChadBuffer:");
    log("  git clone https://github.com/deanmlittle/chadbuffer");
    log("  cd chadbuffer && cargo build-sbf");
    log("  cp target/deploy/chadbuffer.so ../contracts/programs/chadbuffer/");
  }

  // Deploy Groth16 Verifier
  const groth16SoPath = path.join(TARGET_DIR, "groth16_verifier.so");
  if (fs.existsSync(groth16SoPath)) {
    log("Deploying Groth16 Verifier program...");
    await deployViaSurfpool(groth16VerifierProgramId.toBase58(), groth16SoPath, "Groth16 Verifier");
  } else {
    // Not critical — Groth16 verification uses syscalls, not a separate program
    if (false) {
    }
  } else {
    log(`Groth16 Verifier .so not found at ${groth16SoPath}, skipping...`);
  }

  // Wait for programs to be fully deployed
  log("Waiting for programs to be ready...");
  await sleep(3000);

  return { utxopiaProgramId, btcLightClientProgramId, chadbufferProgramId, groth16VerifierProgramId };
}

// =============================================================================
// PDA Derivation
// =============================================================================

function derivePoolStatePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(PC_Seeds.POOL_STATE)],
    programId
  );
}

function deriveCommitmentTreePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(PC_Seeds.COMMITMENT_TREE)],
    programId
  );
}

function deriveBTCRelayPDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(BTCLCSeeds.LIGHT_CLIENT)],
    programId
  );
}

// =============================================================================
// Instruction Builders
// =============================================================================

function deriveHeightIndexPDA(height: bigint, programId: PublicKey): [PublicKey, number] {
  const buf = Buffer.alloc(8);
  buf.writeBigUInt64LE(height);
  return PublicKey.findProgramAddressSync(
    [Buffer.from(BTCLCSeeds.HEIGHT_INDEX), buf],
    programId
  );
}

function deriveBlockHeaderPDA(blockHash: Buffer, programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(BTCLCSeeds.BLOCK), blockHash],
    programId
  );
}

function buildBTCLCInitializeIx(
  lightClientPda: PublicKey,
  payer: PublicKey,
  heightIndexPda: PublicKey,
  blockHeaderPda: PublicKey,
  programId: PublicKey,
  startHeight: bigint,
  startBlockHash: Buffer,
  network: number
): TransactionInstruction {
  // Instruction data: discriminator (1) + height (8) + hash (32) + network (1) = 42 bytes
  const data = Buffer.alloc(42);
  data[0] = BTCLCInstruction.INITIALIZE;
  data.writeBigUInt64LE(startHeight, 1);
  startBlockHash.copy(data, 9);
  data[41] = network;

  return new TransactionInstruction({
    keys: [
      { pubkey: lightClientPda, isSigner: false, isWritable: true },
      { pubkey: payer, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: heightIndexPda, isSigner: false, isWritable: true },
      { pubkey: blockHeaderPda, isSigner: false, isWritable: true },
    ],
    programId,
    data,
  });
}

function buildUTXOpiaInitializeIx(
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
  const data = Buffer.alloc(3);
  data[0] = PC_Instruction.INITIALIZE;
  data[1] = poolBump;
  data[2] = treeBump;

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

function buildAddDemoStealthIx(
  poolState: PublicKey,
  commitmentTree: PublicKey,
  stealthAnnouncement: PublicKey,
  authority: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
  programId: PublicKey,
  ephemeralPub: Uint8Array,
  commitment: Uint8Array,
  encryptedAmountBytes: Uint8Array
): TransactionInstruction {
  // Use SDK to build the instruction data
  const data = buildAddDemoStealthData(ephemeralPub, commitment, encryptedAmountBytes);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: commitmentTree, isSigner: false, isWritable: true },
      { pubkey: stealthAnnouncement, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: true },
      { pubkey: SystemProgram.programId, isSigner: false, isWritable: false },
      { pubkey: zkbtcMint, isSigner: false, isWritable: true },
      { pubkey: poolVault, isSigner: false, isWritable: true },
      { pubkey: TOKEN_2022_PROGRAM_ID, isSigner: false, isWritable: false },
    ],
    programId,
    data: Buffer.from(data),
  });
}

// Helper to derive stealth announcement PDA
function deriveStealthAnnouncementPDA(
  ephemeralPub: Uint8Array,
  programId: PublicKey
): [PublicKey, number] {
  // Ed25519 ephemeral pub is already 32 bytes
  const seeds = [
    Buffer.from("stealth"),
    Buffer.from(ephemeralPub),
  ];
  return PublicKey.findProgramAddressSync(seeds, programId);
}

// =============================================================================
// Initialization Functions
// =============================================================================

async function initializeBTCRelay(
  connection: Connection,
  authority: Keypair,
  programId: PublicKey
): Promise<PublicKey> {
  logSection("BTC Light Client Initialization");

  const [lightClientPda] = deriveBTCRelayPDA(programId);
  log(`BTC Light Client PDA: ${lightClientPda.toBase58()}`);

  // Check if already initialized
  const accountInfo = await connection.getAccountInfo(lightClientPda);
  if (accountInfo && accountInfo.data[0] === Discriminators.LIGHT_CLIENT) {
    log("BTC Light Client already initialized, skipping...");
    return lightClientPda;
  }

  log(`Initializing with block height: ${TEST_BTC_BLOCK.height}`);
  log(`Block hash: ${TEST_BTC_BLOCK.hash.toString("hex")}`);
  log(`Network: ${["mainnet", "testnet3", "testnet4", "regtest"][TEST_BTC_BLOCK.network]}`);

  const [heightIndexPda] = deriveHeightIndexPDA(TEST_BTC_BLOCK.height, programId);
  const [blockHeaderPda] = deriveBlockHeaderPDA(TEST_BTC_BLOCK.hash, programId);

  const ix = buildBTCLCInitializeIx(
    lightClientPda,
    authority.publicKey,
    heightIndexPda,
    blockHeaderPda,
    programId,
    TEST_BTC_BLOCK.height,
    TEST_BTC_BLOCK.hash,
    TEST_BTC_BLOCK.network
  );

  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
    commitment: "confirmed",
  });

  log(`BTC Light Client initialized: ${sig}`);
  return lightClientPda;
}

async function initializeUTXOPIA(
  connection: Connection,
  authority: Keypair,
  programId: PublicKey
): Promise<InitResult> {
  logSection("UTXOpia Initialization");

  const [poolStatePda, poolBump] = derivePoolStatePDA(programId);
  const [commitmentTreePda, treeBump] = deriveCommitmentTreePDA(programId);

  log(`Pool State PDA: ${poolStatePda.toBase58()} (bump: ${poolBump})`);
  log(`Commitment Tree PDA: ${commitmentTreePda.toBase58()} (bump: ${treeBump})`);

  // Check if already initialized
  const poolAccount = await connection.getAccountInfo(poolStatePda);
  if (poolAccount && poolAccount.data[0] === Discriminators.POOL_STATE) {
    log("UTXOpia already initialized, skipping...");

    // Parse existing pool state to get mint and vault info
    // Pool state layout: discriminator(1) + bump(1) + flags(1) + padding(1) + authority(32) + zkbtc_mint(32) + pool_vault(32) + ...
    const mintPubkey = new PublicKey(poolAccount.data.subarray(36, 68));
    // pool_vault is at offset 68 (after zkbtc_mint)
    const poolVaultPubkey = new PublicKey(poolAccount.data.subarray(68, 100));

    log(`Existing mint: ${mintPubkey.toBase58()}`);
    log(`Existing pool vault: ${poolVaultPubkey.toBase58()}`);

    return {
      poolStatePda,
      commitmentTreePda,
      btcLightClientPda: PublicKey.default,
      zkbtcMint: mintPubkey,
      poolVault: poolVaultPubkey,
      authority: authority.publicKey,
    };
  }

  // Create zkBTC Token-2022 mint with pool PDA as mint authority
  log("Creating zkBTC Token-2022 mint...");
  const mintKeypair = Keypair.generate();
  const mintLen = getMintLen([]);
  const mintLamports = await connection.getMinimumBalanceForRentExemption(mintLen);

  const createMintTx = new Transaction().add(
    SystemProgram.createAccount({
      fromPubkey: authority.publicKey,
      newAccountPubkey: mintKeypair.publicKey,
      space: mintLen,
      lamports: mintLamports,
      programId: TOKEN_2022_PROGRAM_ID,
    }),
    createInitializeMintInstruction(
      mintKeypair.publicKey,
      8, // decimals (satoshis)
      poolStatePda, // mint authority is pool PDA (critical for CPI minting!)
      null, // no freeze authority
      TOKEN_2022_PROGRAM_ID
    )
  );

  await sendAndConfirmTransaction(connection, createMintTx, [authority, mintKeypair], {
    commitment: "confirmed",
  });
  const zkbtcMint = mintKeypair.publicKey;
  log(`zkBTC Mint: ${zkbtcMint.toBase58()}`);

  // Create pool vault (ATA for pool PDA)
  log("Creating pool vault...");
  const poolVault = await getOrCreateAssociatedTokenAccount(
    connection,
    authority,
    zkbtcMint,
    poolStatePda,
    true, // allowOwnerOffCurve (PDA)
    undefined,
    undefined,
    TOKEN_2022_PROGRAM_ID
  );
  log(`Pool Vault: ${poolVault.address.toBase58()}`);

  // Create frost vault (for freeze/thaw operations)
  log("Creating frost vault...");
  const frostVault = await getOrCreateAssociatedTokenAccount(
    connection,
    authority,
    zkbtcMint,
    authority.publicKey,
    false,
    undefined,
    undefined,
    TOKEN_2022_PROGRAM_ID
  );
  log(`Frost Vault: ${frostVault.address.toBase58()}`);

  // Initialize UTXOpia
  log("Initializing UTXOpia pool...");
  const ix = buildUTXOpiaInitializeIx(
    poolStatePda,
    commitmentTreePda,
    zkbtcMint,
    poolVault.address,
    frostVault.address,
    authority.publicKey,
    programId,
    poolBump,
    treeBump
  );

  const tx = new Transaction().add(ix);
  const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
    commitment: "confirmed",
  });

  log(`UTXOpia initialized: ${sig}`);

  return {
    poolStatePda,
    commitmentTreePda,
    btcLightClientPda: PublicKey.default,
    zkbtcMint,
    poolVault: poolVault.address,
    authority: authority.publicKey,
  };
}

async function addDemoNotes(
  connection: Connection,
  authority: Keypair,
  programId: PublicKey,
  poolStatePda: PublicKey,
  commitmentTreePda: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
  count: number = 3
): Promise<void> {
  logSection("Adding Demo Stealth Notes");

  log(`Adding ${count} demo stealth notes to commitment tree...`);
  log(`zkBTC will be minted to pool vault: ${poolVault.toBase58()}`);

  // Demo amount: 0.0001 BTC = 10,000 sats (matches DEMO_MINT_AMOUNT_SATS in contract)
  const demoAmount = 10_000n;

  for (let i = 0; i < count; i++) {
    // Generate stealth keys for the demo deposit
    // Spending key: Baby Jubjub scalar
    const spendingPrivKey = randomFieldElement();
    const spendingPubKey = babyJubMul(spendingPrivKey, BABYJUB_BASE8);
    // Viewing key: Ed25519
    const viewingKey = ed25519GenerateKeyPair();
    // Ephemeral key: Ed25519 (32 bytes)
    const ephemeralKey = ed25519GenerateKeyPair();
    const ephemeralPub = ephemeralKey.pubKey; // Already 32 bytes

    // Compute shared secret using X25519 ECDH
    const sharedSecret = x25519Ecdh(ephemeralKey.privKey, viewingKey.pubKey);

    // Use spending pub key X for commitment
    const stealthPubX = spendingPubKey.x;

    // Compute commitment = Poseidon(stealthPub.x, amount)
    const commitment = computeUnifiedCommitmentSync(stealthPubX, demoAmount);
    const commitmentBytes = bigintToBytes32(commitment);

    // Encrypt the amount (XOR with shared secret hash)
    const encryptedAmountBytes = encryptAmount(demoAmount, sharedSecret);

    // Derive stealth announcement PDA
    const [stealthAnnouncement] = deriveStealthAnnouncementPDA(ephemeralPub, programId);

    log(`Note ${i + 1}: ephemeral=${Buffer.from(ephemeralPub).toString("hex").slice(0, 16)}...`);

    const ix = buildAddDemoStealthIx(
      poolStatePda,
      commitmentTreePda,
      stealthAnnouncement,
      authority.publicKey,
      zkbtcMint,
      poolVault,
      programId,
      ephemeralPub,
      commitmentBytes,
      encryptedAmountBytes
    );

    const tx = new Transaction().add(ix);
    const sig = await sendAndConfirmTransaction(connection, tx, [authority], {
      commitment: "confirmed",
    });

    log(`Demo stealth note ${i + 1}/${count} added: ${sig.slice(0, 16)}...`);
  }

  log(`Successfully added ${count} demo stealth notes`);
}

// Helper to convert bigint to 32-byte Uint8Array
function bigintToBytes32(value: bigint): Uint8Array {
  const bytes = new Uint8Array(32);
  let temp = value;
  for (let i = 31; i >= 0; i--) {
    bytes[i] = Number(temp & 0xffn);
    temp >>= 8n;
  }
  return bytes;
}

// =============================================================================
// Config Saving
// =============================================================================

function saveLocalnetConfig(
  deployResult: DeployResult,
  initResult: InitResult
): void {
  logSection("Saving Configuration");

  // Update config.json with localnet values
  config.programs.localnet = {
    UTXOpia: deployResult.utxopiaProgramId.toBase58(),
    btc_light_client: deployResult.btcLightClientProgramId.toBase58(),
    chadbuffer: deployResult.chadbufferProgramId.toBase58(),
    groth16_verifier: deployResult.groth16VerifierProgramId.toBase58(),
  };

  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + "\n");
  log(`Updated ${CONFIG_PATH}`);

  // Save detailed localnet config
  const localnetConfig = {
    network: "localnet",
    rpcUrl: RPC_URL,
    programs: {
      UTXOpia: deployResult.utxopiaProgramId.toBase58(),
      btcLightClient: deployResult.btcLightClientProgramId.toBase58(),
      chadbuffer: deployResult.chadbufferProgramId.toBase58(),
      groth16Verifier: deployResult.groth16VerifierProgramId.toBase58(),
    },
    accounts: {
      poolState: initResult.poolStatePda.toBase58(),
      commitmentTree: initResult.commitmentTreePda.toBase58(),
      zkbtcMint: initResult.zkbtcMint.toBase58(),
      poolVault: initResult.poolVault.toBase58(),
      authority: initResult.authority.toBase58(),
    },
    btcLightClient: {
      pda: initResult.btcLightClientPda.toBase58(),
      startHeight: TEST_BTC_BLOCK.height.toString(),
      startHash: TEST_BTC_BLOCK.hash.toString("hex"),
      network: ["mainnet", "testnet3", "testnet4", "regtest"][TEST_BTC_BLOCK.network],
    },
    createdAt: new Date().toISOString(),
  };

  const localnetConfigPath = path.join(CONTRACTS_DIR, ".localnet-config.json");
  fs.writeFileSync(localnetConfigPath, JSON.stringify(localnetConfig, null, 2) + "\n");
  log(`Saved ${localnetConfigPath}`);
}

// =============================================================================
// Main
// =============================================================================

async function main() {
  const args = process.argv.slice(2);
  const skipDeploy = args.includes("--skip-deploy");
  const skipDemo = args.includes("--skip-demo");

  logSection("UTXOpia Localnet Deploy & Initialize");

  log(`RPC URL: ${RPC_URL}`);
  log(`Skip Deploy: ${skipDeploy}`);
  log(`Skip Demo Notes: ${skipDemo}`);

  // Connect to localnet
  const connection = new Connection(RPC_URL, "confirmed");

  try {
    const version = await connection.getVersion();
    log(`Solana version: ${version["solana-core"]}`);
  } catch (e) {
    console.error("\nError: Cannot connect to localnet.");
    console.error("Make sure solana-test-validator is running with Poseidon support:");
    console.error("");
    console.error("  # With Poseidon syscall (clone devnet features):");
    console.error("  solana-test-validator --clone-feature-set --url devnet --reset");
    console.error("");
    process.exit(1);
  }

  // Load authority keypair
  const walletPath = config.wallet?.path || "~/.config/solana/id.json";
  let authority: Keypair;

  try {
    authority = await loadKeypair(walletPath);
    log(`Authority: ${authority.publicKey.toBase58()}`);
  } catch (e) {
    log("Creating new authority keypair...");
    authority = Keypair.generate();
    log(`Authority: ${authority.publicKey.toBase58()}`);
  }

  // Check balance and airdrop if needed
  const balance = await connection.getBalance(authority.publicKey);
  log(`Balance: ${balance / LAMPORTS_PER_SOL} SOL`);

  if (balance < LAMPORTS_PER_SOL) {
    log("Requesting airdrop...");
    const sig = await connection.requestAirdrop(
      authority.publicKey,
      10 * LAMPORTS_PER_SOL
    );
    await connection.confirmTransaction(sig, "confirmed");
    log("Airdrop successful");
  }

  // Deploy programs
  const deployResult = await deployPrograms(skipDeploy);

  // Initialize BTC Light Client
  const btcLightClientPda = await initializeBTCRelay(
    connection,
    authority,
    deployResult.btcLightClientProgramId
  );

  // Initialize UTXOpia
  const initResult = await initializeUTXOPIA(
    connection,
    authority,
    deployResult.utxopiaProgramId
  );
  initResult.btcLightClientPda = btcLightClientPda;

  // Add demo notes (now also mints zkBTC to pool vault)
  if (!skipDemo) {
    // Initialize Poseidon before computing commitments
    await initPoseidon();
    await addDemoNotes(
      connection,
      authority,
      deployResult.utxopiaProgramId,
      initResult.poolStatePda,
      initResult.commitmentTreePda,
      initResult.zkbtcMint,
      initResult.poolVault,
      3
    );
  } else {
    log("Skipping demo notes (--skip-demo flag)");
  }

  // Save configuration
  saveLocalnetConfig(deployResult, initResult);

  logSection("Deployment Complete!");

  console.log("Summary:");
  console.log(`  UTXOpia Program:       ${deployResult.utxopiaProgramId.toBase58()}`);
  console.log(`  BTC Light Client:     ${deployResult.btcLightClientProgramId.toBase58()}`);
  console.log(`  ChadBuffer:           ${deployResult.chadbufferProgramId.toBase58()}`);
  console.log(`  Groth16 Verifier:   ${deployResult.groth16VerifierProgramId.toBase58()}`);
  console.log(`  Pool State PDA:       ${initResult.poolStatePda.toBase58()}`);
  console.log(`  Commitment Tree PDA:  ${initResult.commitmentTreePda.toBase58()}`);
  console.log(`  zkBTC Mint:           ${initResult.zkbtcMint.toBase58()}`);
  console.log(`  BTC Light Client PDA:           ${btcLightClientPda.toBase58()}`);
  console.log("");
  console.log("Next steps:");
  console.log("  1. Build SDK: cd ../sdk && bun run build");
  console.log("  2. Run tests: bun run test:all");
  console.log("");
}

main().catch((err) => {
  console.error("\nError:", err.message);
  process.exit(1);
});
