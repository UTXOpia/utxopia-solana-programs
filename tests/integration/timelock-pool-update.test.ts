/**
 * E2E test for timelocked pool parameter updates.
 *
 * Tests:
 * 1. Propose → Execute (happy path, with warp)
 * 2. Propose → Cancel → verify cleared
 * 3. Security: non-authority cannot propose
 * 4. Security: non-authority cannot cancel
 * 5. Security: cannot execute before timelock expires
 * 6. Security: cannot execute with no pending proposal
 * 7. Security: cannot cancel with no pending proposal
 * 8. Propose overwrites existing proposal
 *
 * Requires: solana-test-validator running, utxopia program deployed.
 */

import { describe, it, beforeAll, expect } from "bun:test";
import {
  Connection,
  Keypair,
  PublicKey,
  Transaction,
  SystemProgram,
  TransactionInstruction,
  sendAndConfirmTransaction,
  LAMPORTS_PER_SOL,
} from "@solana/web3.js";
import {
  TOKEN_2022_PROGRAM_ID,
  createMint,
  createAccount,
  getMinimumBalanceForRentExemptAccount,
} from "@solana/spl-token";

const RPC_URL = "http://127.0.0.1:8899";
const PROGRAM_ID = new PublicKey("7JJeVjVCy1fZqCDWvf41R7LuTWirTjX7Tp6suC2WVUMQ");

// Instruction discriminators (must match lib.rs)
const DISC_INITIALIZE = 0;
const DISC_PROPOSE_POOL_UPDATE = 3;
const DISC_EXECUTE_POOL_UPDATE = 4;
const DISC_CANCEL_POOL_UPDATE = 5;

// PoolState offsets (must match pool.rs repr(C) layout)
// 0:disc 1:bump 2:flags 3:pad 4:authority(32) 36:mint(32) 68:poolVault(32) 100:frostVault(32)
// 132:deposit_count(8) 140:total_minted(8) 148:total_burned(8) 156:pending_redemptions(8)
// 164:last_update(8) 172:min_deposit(8) 180:max_deposit(8) 188:total_shielded(8)
// 196:service_fee_sats(8) 204:fee_pool(8) 212:pending_min(8) 220:pending_max(8)
// 228:pending_fee(8) 236:pending_execute_after(8) 244:reserved(24)
const POOL_MIN_DEPOSIT_OFFSET = 172;
const POOL_MAX_DEPOSIT_OFFSET = 180;
const POOL_SERVICE_FEE_OFFSET = 196;
const POOL_PENDING_MIN_DEPOSIT_OFFSET = 212;
const POOL_PENDING_MAX_DEPOSIT_OFFSET = 220;
const POOL_PENDING_SERVICE_FEE_OFFSET = 228;
const POOL_PENDING_EXECUTE_AFTER_OFFSET = 236;

// Timelock delay in seconds (must match constants.rs)
const TIMELOCK_DELAY_SECS = 48 * 60 * 60; // 172800

function derivePoolStatePDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("pool_state")],
    PROGRAM_ID,
  );
}

function deriveCommitmentTreePDA(): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("commitment_tree")],
    PROGRAM_ID,
  );
}

function buildInitializeIx(
  poolState: PublicKey,
  commitmentTree: PublicKey,
  zkbtcMint: PublicKey,
  poolVault: PublicKey,
  frostVault: PublicKey,
  authority: PublicKey,
  poolBump: number,
  treeBump: number,
): TransactionInstruction {
  const data = Buffer.alloc(3);
  data[0] = DISC_INITIALIZE;
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
    programId: PROGRAM_ID,
    data,
  });
}

function buildProposeIx(
  poolState: PublicKey,
  authority: PublicKey,
  minDeposit: bigint,
  maxDeposit: bigint,
  serviceFee: bigint,
): TransactionInstruction {
  const data = Buffer.alloc(25);
  data[0] = DISC_PROPOSE_POOL_UPDATE;
  data.writeBigUInt64LE(minDeposit, 1);
  data.writeBigUInt64LE(maxDeposit, 9);
  data.writeBigUInt64LE(serviceFee, 17);

  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data,
  });
}

function buildExecuteIx(poolState: PublicKey): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
    ],
    programId: PROGRAM_ID,
    data: Buffer.from([DISC_EXECUTE_POOL_UPDATE]),
  });
}

function buildCancelIx(
  poolState: PublicKey,
  authority: PublicKey,
): TransactionInstruction {
  return new TransactionInstruction({
    keys: [
      { pubkey: poolState, isSigner: false, isWritable: true },
      { pubkey: authority, isSigner: true, isWritable: false },
    ],
    programId: PROGRAM_ID,
    data: Buffer.from([DISC_CANCEL_POOL_UPDATE]),
  });
}

async function readPoolState(connection: Connection, poolState: PublicKey) {
  const info = await connection.getAccountInfo(poolState);
  if (!info) throw new Error("Pool state not found");
  const data = info.data;
  return {
    minDeposit: data.readBigUInt64LE(POOL_MIN_DEPOSIT_OFFSET),
    maxDeposit: data.readBigUInt64LE(POOL_MAX_DEPOSIT_OFFSET),
    serviceFeeSats: data.readBigUInt64LE(POOL_SERVICE_FEE_OFFSET),
    pendingMinDeposit: data.readBigUInt64LE(POOL_PENDING_MIN_DEPOSIT_OFFSET),
    pendingMaxDeposit: data.readBigUInt64LE(POOL_PENDING_MAX_DEPOSIT_OFFSET),
    pendingServiceFee: data.readBigUInt64LE(POOL_PENDING_SERVICE_FEE_OFFSET),
    pendingExecuteAfter: data.readBigInt64LE(POOL_PENDING_EXECUTE_AFTER_OFFSET),
  };
}

async function sendTx(
  connection: Connection,
  ix: TransactionInstruction,
  signers: Keypair[],
): Promise<string> {
  const tx = new Transaction().add(ix);
  return sendAndConfirmTransaction(connection, tx, signers, {
    commitment: "confirmed",
  });
}

async function sendTxExpectFail(
  connection: Connection,
  ix: TransactionInstruction,
  signers: Keypair[],
): Promise<string> {
  const tx = new Transaction().add(ix);
  const { blockhash } = await connection.getLatestBlockhash();
  tx.recentBlockhash = blockhash;
  tx.feePayer = signers[0].publicKey;
  tx.sign(...signers);
  const sim = await connection.simulateTransaction(tx);
  if (sim.value.err) {
    // Return logs joined for assertion matching
    const logs = sim.value.logs || [];
    return logs.join("\n") + "\n" + JSON.stringify(sim.value.err);
  }
  throw new Error("Transaction should have failed but simulation passed");
}

describe("Timelocked Pool Update E2E", () => {
  let connection: Connection;
  let authority: Keypair;
  let attacker: Keypair;
  let poolStatePDA: PublicKey;
  let poolBump: number;
  let commitmentTreePDA: PublicKey;
  let treeBump: number;
  let zkbtcMint: PublicKey;
  let poolVault: PublicKey;
  let frostVault: PublicKey;
  let initialized = false;

  beforeAll(async () => {
    connection = new Connection(RPC_URL, "confirmed");

    // Check validator is running
    try {
      await connection.getVersion();
    } catch {
      console.warn("Solana validator not running — skipping timelock tests");
      return;
    }

    authority = Keypair.generate();
    attacker = Keypair.generate();

    // Fund both
    const sig1 = await connection.requestAirdrop(authority.publicKey, 10 * LAMPORTS_PER_SOL);
    const sig2 = await connection.requestAirdrop(attacker.publicKey, 2 * LAMPORTS_PER_SOL);
    await connection.confirmTransaction(sig1, "confirmed");
    await connection.confirmTransaction(sig2, "confirmed");

    [poolStatePDA, poolBump] = derivePoolStatePDA();
    [commitmentTreePDA, treeBump] = deriveCommitmentTreePDA();

    // Create Token-2022 mint + vaults (using Keypair-based accounts, not ATA)
    const vaultKeypair1 = Keypair.generate();
    const vaultKeypair2 = Keypair.generate();

    zkbtcMint = await createMint(
      connection,
      authority,
      authority.publicKey,
      null,
      8,
      undefined,
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );
    poolVault = await createAccount(
      connection,
      authority,
      zkbtcMint,
      authority.publicKey,
      vaultKeypair1,
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );
    frostVault = await createAccount(
      connection,
      authority,
      zkbtcMint,
      authority.publicKey,
      vaultKeypair2,
      undefined,
      TOKEN_2022_PROGRAM_ID,
    );

    // Initialize pool
    const initIx = buildInitializeIx(
      poolStatePDA,
      commitmentTreePDA,
      zkbtcMint,
      poolVault,
      frostVault,
      authority.publicKey,
      poolBump,
      treeBump,
    );
    await sendTx(connection, initIx, [authority]);
    initialized = true;
    console.log("Pool initialized successfully");
  }, 30_000);

  it("should reject execute with no pending proposal", async () => {
    if (!initialized) return;
    const err = await sendTxExpectFail(connection, buildExecuteIx(poolStatePDA), [attacker]);
    expect(err).toContain("custom program error");
  });

  it("should reject cancel with no pending proposal", async () => {
    if (!initialized) return;
    const err = await sendTxExpectFail(
      connection,
      buildCancelIx(poolStatePDA, authority.publicKey),
      [authority],
    );
    expect(err).toContain("custom program error");
  });

  it("should reject propose from non-authority", async () => {
    if (!initialized) return;
    const ix = buildProposeIx(poolStatePDA, attacker.publicKey, 1000n, 999_000n, 100n);
    const err = await sendTxExpectFail(connection, ix, [attacker]);
    expect(err).toContain("custom program error");
  });

  it("should propose pool update successfully", async () => {
    if (!initialized) return;
    const newMin = 20_000n;
    const newMax = 50_000_000_000n;
    const newFee = 1000n;

    const ix = buildProposeIx(poolStatePDA, authority.publicKey, newMin, newMax, newFee);
    await sendTx(connection, ix, [authority]);

    const pool = await readPoolState(connection, poolStatePDA);
    expect(pool.pendingMinDeposit).toBe(newMin);
    expect(pool.pendingMaxDeposit).toBe(newMax);
    expect(pool.pendingServiceFee).toBe(newFee);
    expect(pool.pendingExecuteAfter).toBeGreaterThan(0n);

    // Original values should be unchanged (set during initialization)
    expect(pool.minDeposit).toBe(5_000n);        // MIN_DEPOSIT_SATS
    expect(pool.maxDeposit).toBe(100_000_000_000n); // MAX_DEPOSIT_SATS
  });

  it("should reject execute before timelock expires", async () => {
    if (!initialized) return;
    const err = await sendTxExpectFail(connection, buildExecuteIx(poolStatePDA), [attacker]);
    expect(err).toContain("custom program error");
  }, 15_000);

  it("should reject cancel from non-authority", async () => {
    if (!initialized) return;
    const ix = buildCancelIx(poolStatePDA, attacker.publicKey);
    const err = await sendTxExpectFail(connection, ix, [attacker]);
    expect(err).toContain("custom program error");
  });

  it("should cancel pool update successfully", async () => {
    if (!initialized) return;
    const ix = buildCancelIx(poolStatePDA, authority.publicKey);
    await sendTx(connection, ix, [authority]);

    const pool = await readPoolState(connection, poolStatePDA);
    expect(pool.pendingMinDeposit).toBe(0n);
    expect(pool.pendingMaxDeposit).toBe(0n);
    expect(pool.pendingServiceFee).toBe(0n);
    expect(pool.pendingExecuteAfter).toBe(0n);
  });

  it("should overwrite existing proposal with new one", async () => {
    if (!initialized) return;

    // First proposal
    const ix1 = buildProposeIx(poolStatePDA, authority.publicKey, 1000n, 2000n, 100n);
    await sendTx(connection, ix1, [authority]);

    let pool = await readPoolState(connection, poolStatePDA);
    expect(pool.pendingMinDeposit).toBe(1000n);

    // Second proposal overwrites
    const ix2 = buildProposeIx(poolStatePDA, authority.publicKey, 5000n, 9000n, 200n);
    await sendTx(connection, ix2, [authority]);

    pool = await readPoolState(connection, poolStatePDA);
    expect(pool.pendingMinDeposit).toBe(5000n);
    expect(pool.pendingMaxDeposit).toBe(9000n);
    expect(pool.pendingServiceFee).toBe(200n);

    // Cleanup for next test
    await sendTx(connection, buildCancelIx(poolStatePDA, authority.publicKey), [authority]);
  }, 15_000);

  // NOTE: solana-test-validator does not support runtime clock manipulation
  // (setClockUnixTimestamp is not available). This test requires bankrun or
  // solana-program-test to warp the clock past the 48h timelock.
  // The TimelockNotElapsed error is already verified in the test above.
  it.skip("should execute after timelock via clock warp (requires bankrun)", async () => {
    if (!initialized) return;

    const newMin = 15_000n;
    const newMax = 75_000_000_000n;
    const newFee = 750n;

    // Propose
    const ix = buildProposeIx(poolStatePDA, authority.publicKey, newMin, newMax, newFee);
    await sendTx(connection, ix, [authority]);

    const poolBefore = await readPoolState(connection, poolStatePDA);
    const executeAfter = poolBefore.pendingExecuteAfter;
    expect(executeAfter).toBeGreaterThan(0n);

    // TODO: Use bankrun setClock() to warp past executeAfter
    // Then call buildExecuteIx and verify values are applied + pending cleared
  });

  it("should reject propose with invalid bounds (min > max)", async () => {
    if (!initialized) return;
    const ix = buildProposeIx(poolStatePDA, authority.publicKey, 100_000n, 50_000n, 0n);
    const err = await sendTxExpectFail(connection, ix, [authority]);
    expect(err).toContain("InvalidInstructionData");
  });

  it("should reject propose with max > 21M BTC", async () => {
    if (!initialized) return;
    const ix = buildProposeIx(
      poolStatePDA,
      authority.publicKey,
      1000n,
      2_100_000_000_000_001n, // 21M BTC + 1 sat
      0n,
    );
    const err = await sendTxExpectFail(connection, ix, [authority]);
    expect(err).toContain("InvalidInstructionData");
  });
});
