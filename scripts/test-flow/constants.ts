export const BUFFER_HEADER_SIZE = 32; // ChadBuffer authority pubkey

export const Seeds = {
  POOL_STATE: "pool_state",
  COMMITMENT_TREE: "commitment_tree",
  VK_REGISTRY: "vk_registry",
  NULLIFIER: "nullifier",
  STEALTH_ANNOUNCEMENT: "stealth",
  DEPOSIT: "deposit",
  BTC_LIGHT_CLIENT: "btc_light_client",
  BLOCK_HEADER: "block",
  HEIGHT_INDEX: "height_index",
} as const;

export const BTCRelayDisc = {
  INITIALIZE: 0,
  EXTEND_BLOCKCHAIN: 1,
  VERIFY_TRANSACTION: 2,
  PRUNE_OBSOLETE_BLOCKS: 3,
  REINITIALIZE: 4,
} as const;

export const BTCNetwork = {
  MAINNET: 0,
  TESTNET3: 1,
  TESTNET4: 2,
  REGTEST: 3,
} as const;

export type BTCNetworkId = (typeof BTCNetwork)[keyof typeof BTCNetwork];

export const TREE_DEPTH = 16;
