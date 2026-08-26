#!/usr/bin/env sh
# The only supported way to build a deployable artifact in this repo.
#
# `cargo build-sbf` picks a platform-tools version from whatever agave CLI happens to be on
# PATH, and platform-tools carries the rustc + LLVM that actually emit the SBF bytes. Two
# machines on different agave releases therefore produce different binaries from identical
# source, which defeats `solana program dump | sha256sum` as a check on what is deployed.
# Pinning it here makes the artifact a function of (commit, features) alone.
#
# Everything else that could vary is already handled: Cargo.lock is committed, the release
# profile lives in the workspace Cargo.toml, and cargo-build-sbf remaps the cwd prefix by
# default so no absolute path reaches the binary (verified: 0 occurrences).
#
# Verified 2026-08-26: this pin reproduces the deployed testnet4 programs byte for byte —
# see `bun run verify:deployed`.
set -eu

TOOLS_VERSION=v1.54
EXPECTED_BUILD_SBF=4.1.0

actual_build_sbf=$(cargo-build-sbf --version 2>/dev/null | awk '/^cargo-build-sbf/ {print $2}')
if [ "$actual_build_sbf" != "$EXPECTED_BUILD_SBF" ]; then
  echo "warning: cargo-build-sbf $actual_build_sbf, pinned to $EXPECTED_BUILD_SBF." >&2
  echo "         --tools-version $TOOLS_VERSION still pins the compiler, so the artifact should" >&2
  echo "         match, but confirm with 'bun run verify:deployed' before trusting a deploy." >&2
fi

exec cargo build-sbf --tools-version "$TOOLS_VERSION" "$@"
