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

# Deploy to devnet
bun run deploy

# Run tests
bun run test

# Setup devnet
bun run setup:devnet
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
├── scripts/                 # Setup & deployment
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
| 16 | RESERVED | Removed proofless request_redemption |
| 17 | COMPLETE_REDEMPTION | Complete SPV-verified BTC payout |
| 18 | MARK_PROCESSING | Reserve UTXOs for redemption signing |
| 19 | CANCEL_REDEMPTION | Cancel pending/timed-out redemption |
| 20 | ROTATE_TREE | Rotate active commitment tree |
| 24 | REGISTER_DEPOSIT_INTENT | Register OP_RETURN-free deposit intent |
| 25 | VERIFY_DEPOSIT | Verify OP_RETURN-free deposit |
| 27 | APPROVE_REDEMPTION_SIGNING | Approve Ika BTC signing |

## Privacy Model

- **Commitment**: `Poseidon(npk, token, amount)`
- **Nullifier**: `Poseidon(nullifyingKey, leafIndex)`
- **Stealth**: Dual-key ECDH (X25519 viewing + Baby Jubjub spending)

## Development

```bash
# Install deps
bun install

# Build
cargo build-sbf

# Test locally
solana-test-validator &
bun run test
```
