import { Connection, PublicKey, TransactionSignature } from "@solana/web3.js";

export async function assertSolanaSuccess(connection: Connection, signature: TransactionSignature): Promise<void> {
  const tx = await connection.getTransaction(signature, {
    commitment: "confirmed",
    maxSupportedTransactionVersion: 0,
  });
  if (!tx) throw new Error(`Transaction not found: ${signature}`);
  if (tx.meta?.err) throw new Error(`Transaction failed: ${JSON.stringify(tx.meta.err)}`);
}

export async function assertAccountExists(connection: Connection, pubkey: PublicKey, label = pubkey.toBase58()): Promise<void> {
  const account = await connection.getAccountInfo(pubkey);
  if (!account) throw new Error(`Missing account: ${label}`);
}

export function assertBufferEquals(actual: Uint8Array, expected: Uint8Array, label = "buffer"): void {
  if (!Buffer.from(actual).equals(Buffer.from(expected))) {
    throw new Error(`${label} mismatch`);
  }
}
