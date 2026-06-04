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

| ID | Name | Description | CU |
|----|------|-------------|----|
| 0 | INITIALIZE | Create pool state | ~5k |
| 8 | VERIFY_DEPOSIT | Record BTC deposit (SPV) | ~50k |
| 9 | CLAIM | Mint zkBTC with ZK proof | ~95k |
| 4 | SPLIT_COMMITMENT | Split 1→2 notes | ~100k |
| 5 | REQUEST_REDEMPTION | Burn for BTC withdrawal | ~20k |
| 12 | ANNOUNCE_STEALTH | Stealth address send | ~15k |
| 17 | REGISTER_NAME | Register .zkey name | ~10k |

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
