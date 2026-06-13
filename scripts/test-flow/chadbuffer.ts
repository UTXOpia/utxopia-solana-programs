import {
  Connection,
  Keypair,
  PublicKey,
  SystemProgram,
  Transaction,
  TransactionInstruction,
  sendAndConfirmTransaction,
} from "@solana/web3.js";
import { BUFFER_HEADER_SIZE } from "./constants";

export async function createTxBufferAccount(
  connection: Connection,
  payer: Keypair,
  rawTx: Uint8Array,
  chadbufferId: PublicKey,
): Promise<Keypair> {
  const bufferKeypair = Keypair.generate();
  const space = BUFFER_HEADER_SIZE + rawTx.length;
  const lamports = await connection.getMinimumBalanceForRentExemption(space);

  const createIx = SystemProgram.createAccount({
    fromPubkey: payer.publicKey,
    newAccountPubkey: bufferKeypair.publicKey,
    lamports,
    space,
    programId: chadbufferId,
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(createIx), [payer, bufferKeypair], { commitment: "confirmed" });

  const maxChunk = 900;
  const firstChunk = rawTx.slice(0, maxChunk);
  const initData = new Uint8Array(1 + firstChunk.length);
  initData[0] = 0;
  initData.set(firstChunk, 1);

  const initIx = new TransactionInstruction({
    programId: chadbufferId,
    keys: [
      { pubkey: payer.publicKey, isSigner: true, isWritable: true },
      { pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true },
    ],
    data: Buffer.from(initData),
  });
  await sendAndConfirmTransaction(connection, new Transaction().add(initIx), [payer], { commitment: "confirmed" });

  let offset = firstChunk.length;
  while (offset < rawTx.length) {
    const chunk = rawTx.slice(offset, offset + maxChunk);
    const writeData = new Uint8Array(1 + 3 + chunk.length);
    writeData[0] = 2;
    writeData[1] = offset & 0xff;
    writeData[2] = (offset >> 8) & 0xff;
    writeData[3] = (offset >> 16) & 0xff;
    writeData.set(chunk, 4);

    const writeIx = new TransactionInstruction({
      programId: chadbufferId,
      keys: [
        { pubkey: payer.publicKey, isSigner: true, isWritable: true },
        { pubkey: bufferKeypair.publicKey, isSigner: false, isWritable: true },
      ],
      data: Buffer.from(writeData),
    });
    await sendAndConfirmTransaction(connection, new Transaction().add(writeIx), [payer], { commitment: "confirmed" });
    offset += chunk.length;
  }

  return bufferKeypair;
}
