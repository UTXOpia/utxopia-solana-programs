# Solana Test Flow

This directory keeps scenario code modular, mirroring the Sui test-flow layout.

## Test Tiers

1. Unit
   - `cargo test`
   - `bun test tests/unit`
   - Pure byte utilities, merkle proof serialization, instruction serialization, and state parsers.

2. Build
   - `bun run check:scripts`
   - `bun run build:localnet`
   - Add script entrypoints to `tsconfig.scripts.json` as they are cleaned up.

3. Hermetic Integration
   - `bun run test:localnet`
   - Uses a local Solana validator and already-deployed local programs.
   - No external Ika and no real proof generation unless a fixture is supplied.

4. Full Regtest Scenario
   - `bun run test:regtest`
   - Bitcoin regtest plus Esplora plus Solana localnet/devnet-regtest.
   - Real proof artifacts and optional redeem/Ika legs should stay behind explicit flags.

## Module Ownership

- `config.ts`: env, `config.json`, keypair, and program ID loading.
- `scenario.ts`: top-level orchestration only.
- `solana-context.ts`: connection, payer, program refs, PDAs, and shared account readers.
- `bitcoin-regtest.ts`: Docker, `bitcoin-cli`, Esplora, tx creation, and regtest lifecycle.
- `light-client.ts`: BTC light-client instruction builders and header submission.
- `deposit.ts`: deposit instruction builders and relay CLI behavior.
- `joinsplit-proof.ts`: fixture loading and explicit full-flow proof generation boundary.
- `merkle.ts`: merkle proof and tx byte helpers.
- `assertions.ts`: transaction, account, event, and state assertions.
- `state-recording.ts`: writes last-flow result files.

Keep entrypoints such as `scripts/regtest-flow.ts`, `scripts/relay-deposit.ts`,
and `scripts/e2e-localnet.ts` thin. They should parse CLI input, call one module
function, print high-level status, and exit.
