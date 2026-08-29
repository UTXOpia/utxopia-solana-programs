# UTXOpia Contracts

Solana smart contracts for UTXOpia - a privacy-preserving Bitcoin to Solana bridge using Pinocchio.

## Programs

### UTXOpia (Pinocchio)
Main privacy bridge program - optimized with [Pinocchio](https://github.com/febo/pinocchio).

**Program ID (devnet):** `B2H3B6iDg3zfvZkT4dNgjhKSqrtdcWBJSwbP7Wbbhzsq`

### BTC Light Client
Tracks Bitcoin block headers for SPV verification.

**Program ID (devnet):** `Ho6UTeF8yFnRdCK15tSZtcJozvkDABJZWYxkgGyWAfyq`

## Commands

```bash
# Build programs
bun run build

# Deploy fresh devnet program
bun run scripts/deploy-fresh-devnet.ts

# Run tests
bun run test
```

## Structure

```
.
├── programs/
│   ├── utxopia/        # Main Pinocchio program
│   │   └── src/
│   │       ├── lib.rs       # Entry point + dispatcher
│   │       ├── instructions/ # All instruction handlers
│   │       ├── state/       # Account structures
│   │       └── utils/       # Helpers (BTC, chadbuffer)
│   └── btc-light-client/    # BTC header tracking
├── scripts/                 # Deployment and verification
├── tests/                   # Integration tests
└── package.json
```

## Instructions

| ID | Name | Description |
|----|------|-------------|
| 0 | INITIALIZE | Create pool state |
| 1 | SET_PAUSED | Pause or unpause pool |
| 2 | SET_POOL_CONFIG | Configure BTC/Ika pool settings |
| 3 | PROPOSE_POOL_UPDATE | Propose timelocked pool parameter update |
| 4 | EXECUTE_POOL_UPDATE | Execute elapsed pool update |
| 5 | CANCEL_POOL_UPDATE | Cancel pending pool update |
| 6 | INIT_VK_REGISTRY | Initialize JoinSplit VK registry |
| 7 | UPDATE_VK_REGISTRY | Update JoinSplit VK registry |
| 8 | REGISTER_TOKEN | Register token config |
| 9 | UPDATE_TOKEN_CONFIG | Update token config |
| 10 | CLAIM_FEES | Claim accumulated protocol fees |
| 11 | COMPLETE_DEPOSIT | Complete SPV-verified BTC deposit |
| 12 | SHIELD | Shield public tokens |
| 13 | TRANSACT | Private JoinSplit transfer |
| 14 | UNSHIELD | JoinSplit unshield |
| 15 | REDEEM | Proof-checked BTC withdrawal request |
| 17 | COMPLETE_REDEMPTION | Complete SPV-verified BTC payout |
| 18 | MARK_PROCESSING | Reserve UTXOs for redemption signing |
| 19 | CANCEL_REDEMPTION | Cancel pending/timed-out redemption |
| 20 | ROTATE_TREE | Rotate active commitment tree |
| 24 | REGISTER_DEPOSIT_INTENT | Register OP_RETURN-free deposit intent |
| 25 | VERIFY_DEPOSIT | Verify OP_RETURN-free deposit |
| 27 | APPROVE_REDEMPTION_SIGNING | Approve Ika BTC signing |

See [SDK and Frontend Migration](docs/SDK_FRONTEND_MIGRATION.md) for the
current client-facing account layouts and instruction builder changes.

## Privacy Model

- **Commitment**: `Poseidon(npk, token, amount)`
- **Nullifier**: `Poseidon(nullifyingKey, leafIndex)`
- **Stealth**: Dual-key ECDH (X25519 viewing + Baby Jubjub spending)

## Development

```bash
# Install deps
bun install

# Build. Always go through these scripts, never a bare `cargo build-sbf`:
#   - naming the network is mandatory (an unnamed on-chain build is now a compile
#     error, because it silently took the devnet/localnet program ids and compiled
#     out the SPV network check)
#   - they pin platform-tools to the version the deployed programs were built with,
#     which is what makes the artifact reproducible on another machine
bun run build:devnet-regtest   # devnet Solana + regtest BTC — what app.utxopia.com runs
bun run build:devnet           # plain devnet
bun run build:localnet         # SHA256 instead of Poseidon; local validator only
bun run build:mainnet          # fails until a mainnet BTC light client id is configured

# Prove what is actually deployed: rebuild locally and compare against the chain.
bun run verify:deployed 28z2AtKA6aFGrGCh4ns1rmp7vGpWuh6x3H7gXKBcfxur devnet devnet

# Test locally
solana-test-validator &
bun run test
```
