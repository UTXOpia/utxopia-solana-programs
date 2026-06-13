import { PublicKey } from "@solana/web3.js";
import { Seeds } from "./constants";

export function derivePoolStatePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.POOL_STATE)],
    programId,
  );
}

export function deriveCommitmentTreePDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.COMMITMENT_TREE), Buffer.from([0, 0, 0, 0])],
    programId,
  );
}

export function deriveVkRegistryPDA(programId: PublicKey, nInputs: number, nOutputs: number): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.VK_REGISTRY), Buffer.from([nInputs]), Buffer.from([nOutputs])],
    programId,
  );
}

export function deriveNullifierPDA(programId: PublicKey, nullifierHash: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.NULLIFIER), Buffer.from(nullifierHash)],
    programId,
  );
}

export function deriveStealthAnnouncementPDA(programId: PublicKey, ephemeralPub: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.STEALTH_ANNOUNCEMENT), Buffer.from(ephemeralPub)],
    programId,
  );
}

export function deriveDepositStealthPDA(programId: PublicKey, txid: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.STEALTH_ANNOUNCEMENT), Buffer.from(txid)],
    programId,
  );
}

export function deriveDepositIntentPDA(programId: PublicKey, npk: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("deposit_intent"), Buffer.from(npk)],
    programId,
  );
}

export function deriveDepositReceiptPDA(programId: PublicKey, depositTxid: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("deposit_receipt"), Buffer.from(depositTxid)],
    programId,
  );
}

export function deriveTokenConfigPDA(programId: PublicKey, mint: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("token_config"), mint.toBuffer()],
    programId,
  );
}

export function derivePoolConfigPDA(programId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("pool_config")],
    programId,
  );
}

export function deriveUtxoRecordPDA(programId: PublicKey, txid: Uint8Array, vout: number): [PublicKey, number] {
  const voutBuf = Buffer.alloc(4);
  voutBuf.writeUInt32LE(vout);
  return PublicKey.findProgramAddressSync(
    [Buffer.from("utxo"), Buffer.from(txid), voutBuf],
    programId,
  );
}

export function deriveLightClientPDA(btcLightClientId: PublicKey): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.BTC_LIGHT_CLIENT)],
    btcLightClientId,
  );
}

export function deriveBlockHeaderPDA(btcLightClientId: PublicKey, blockHash: Uint8Array): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.BLOCK_HEADER), Buffer.from(blockHash)],
    btcLightClientId,
  );
}

export function deriveHeightIndexPDA(btcLightClientId: PublicKey, height: bigint): [PublicKey, number] {
  const heightBuf = Buffer.alloc(8);
  heightBuf.writeBigUInt64LE(height);
  return PublicKey.findProgramAddressSync(
    [Buffer.from(Seeds.HEIGHT_INDEX), heightBuf],
    btcLightClientId,
  );
}

export function deriveVerifiedTransactionPDA(
  btcLightClientId: PublicKey,
  blockHash: Uint8Array,
  txid: Uint8Array,
): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [Buffer.from("verified_tx"), Buffer.from(blockHash), Buffer.from(txid)],
    btcLightClientId,
  );
}
