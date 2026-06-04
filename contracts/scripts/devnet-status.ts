#!/usr/bin/env bun
/**
 * Check UTXOpia devnet status
 */

import { Connection, PublicKey } from "@solana/web3.js";
import * as fs from "fs";

const RPC_URL = "https://api.devnet.solana.com";

async function main() {
  console.log("=".repeat(60));
  console.log("UTXOpia Devnet Status Check");
  console.log("=".repeat(60));

  const connection = new Connection(RPC_URL, "confirmed");
  const devnetConfig = JSON.parse(fs.readFileSync(".devnet-config.json", "utf-8"));

  console.log("\n📋 Configuration:");
  console.log(`  Program: ${devnetConfig.programs.UTXOpia}`);
  console.log(`  Pool State: ${devnetConfig.accounts.poolState}`);
  console.log(`  Commitment Tree: ${devnetConfig.accounts.commitmentTree}`);
  console.log(`  zkBTC Mint: ${devnetConfig.accounts.zkbtcMint}`);
  console.log(`  Pool Vault: ${devnetConfig.accounts.poolVault}`);

  // Check Pool State
  console.log("\n🏦 Pool State:");
  const poolStatePDA = new PublicKey(devnetConfig.accounts.poolState);
  const poolStateInfo = await connection.getAccountInfo(poolStatePDA);
  if (poolStateInfo) {
    console.log(`  ✓ Account exists (${poolStateInfo.data.length} bytes)`);
    const view = new DataView(poolStateInfo.data.buffer, poolStateInfo.data.byteOffset, poolStateInfo.data.byteLength);
    console.log(`  Discriminator: ${poolStateInfo.data[0]}`);
  } else {
    console.log(`  ✗ Account not found`);
  }

  // Check Commitment Tree
  console.log("\n🌳 Commitment Tree:");
  const commitmentTreePDA = new PublicKey(devnetConfig.accounts.commitmentTree);
  const treeInfo = await connection.getAccountInfo(commitmentTreePDA);
  if (treeInfo) {
    console.log(`  ✓ Account exists (${treeInfo.data.length} bytes)`);
    console.log(`  Discriminator: ${treeInfo.data[0]}`);
    // Read next_index from offset 0xcb0 (little-endian u32)
    const nextIndex = treeInfo.data[0xcb0] | (treeInfo.data[0xcb1] << 8) | (treeInfo.data[0xcb2] << 16) | (treeInfo.data[0xcb3] << 24);
    console.log(`  Commitment Count: ${nextIndex}`);
  } else {
    console.log(`  ✗ Account not found`);
  }

  // Check Pool Vault Balance
  console.log("\n💰 Pool Vault (zkBTC):");
  const poolVault = new PublicKey(devnetConfig.accounts.poolVault);
  const vaultInfo = await connection.getAccountInfo(poolVault);
  if (vaultInfo && vaultInfo.data.length >= 72) {
    console.log(`  ✓ Account exists (${vaultInfo.data.length} bytes)`);
    const view = new DataView(vaultInfo.data.buffer, vaultInfo.data.byteOffset, vaultInfo.data.byteLength);
    const balance = view.getBigUint64(64, true);
    console.log(`  Balance: ${balance} sats (${Number(balance) / 100_000_000} BTC)`);
  } else {
    console.log(`  ✗ Account not found or invalid`);
  }

  // Check zkBTC Mint
  console.log("\n🪙 zkBTC Mint:");
  const zkbtcMint = new PublicKey(devnetConfig.accounts.zkbtcMint);
  const mintInfo = await connection.getAccountInfo(zkbtcMint);
  if (mintInfo) {
    console.log(`  ✓ Account exists (${mintInfo.data.length} bytes)`);
    // Token-2022 mint layout: 4 bytes option + 32 bytes authority
    const hasAuthority = mintInfo.data[0] === 1;
    if (hasAuthority) {
      const mintAuthority = new PublicKey(mintInfo.data.slice(4, 36)).toBase58();
      console.log(`  Mint Authority: ${mintAuthority}`);
      if (mintAuthority === devnetConfig.accounts.poolState) {
        console.log(`  ✓ Authority is Pool State PDA (correct)`);
      } else {
        console.log(`  ⚠ Authority is NOT Pool State PDA`);
      }
    }
  } else {
    console.log(`  ✗ Account not found`);
  }

  // Fetch recent stealth announcements
  console.log("\n📣 Recent Stealth Announcements:");
  const programId = new PublicKey(devnetConfig.programs.UTXOpia);
  try {
    const accounts = await connection.getProgramAccounts(programId, {
      filters: [
        { dataSize: 91 }, // StealthAnnouncement size
        { memcmp: { offset: 0, bytes: "9" } }, // Discriminator 8 = 0x08 in base58 is "9"
      ],
    });
    console.log(`  Found: ${accounts.length} announcement(s)`);

    for (let i = 0; i < Math.min(accounts.length, 5); i++) {
      const acc = accounts[i];
      const data = acc.account.data;
      // StealthAnnouncement layout: disc(1) + amount(8) + ephemeral(33) + commitment(32) + enc_amount(8) + timestamp(8) = 90+1 = 91
      const commitment = Buffer.from(data.slice(42, 74)).toString('hex');
      console.log(`  [${i}] ${acc.pubkey.toBase58().slice(0, 12)}... commitment: ${commitment.slice(0, 24)}...`);
    }
  } catch (err: any) {
    console.log(`  Error fetching: ${err.message}`);
  }

  console.log("\n" + "=".repeat(60));
  console.log("✓ Devnet status check complete");
}

main().catch(console.error);
