#!/usr/bin/env sh
# Prove which commit is running on chain: rebuild locally and compare against the deployed bytes.
#
#   sh scripts/verify-deployed.sh <program-id> <cluster> <cargo-features>
#   sh scripts/verify-deployed.sh 28z2AtKA6aFGrGCh4ns1rmp7vGpWuh6x3H7gXKBcfxur devnet devnet
#
# `solana program dump` pads the account out to its allocated length, so both sides are compared
# with trailing NULs stripped. A match means the checked-out commit built with those features is
# byte-for-byte what is deployed; a mismatch means it is not, and says nothing about which commit
# is — bisect by rebuilding candidates.
set -eu

[ $# -ge 3 ] || { echo "usage: $0 <program-id> <cluster> <cargo-features>" >&2; exit 2; }
PROGRAM_ID=$1; CLUSTER=$2; FEATURES=$3
DUMP=$(mktemp -t deployed-XXXXXX.so)
trap 'rm -f "$DUMP"' EXIT

sha() { python3 -c "import sys,hashlib;d=open(sys.argv[1],'rb').read().rstrip(b'\x00');print(hashlib.sha256(d).hexdigest(), len(d))" "$1"; }

solana program dump "$PROGRAM_ID" "$DUMP" -u "$CLUSTER" >/dev/null
sh "$(dirname "$0")/build-sbf.sh" --features "$FEATURES" >/dev/null 2>&1

# The dumped program tells us nothing about which .so in target/deploy it came from, so compare
# against every one and report the match.
deployed=$(sha "$DUMP")
echo "deployed $PROGRAM_ID"
echo "  $deployed"
match=""
for so in target/deploy/*.so; do
  local_sha=$(sha "$so")
  [ "$local_sha" = "$deployed" ] && { match=$so; echo "  MATCH  $so"; }
done
if [ -z "$match" ]; then
  echo "  no local artifact matches. Built at $(git rev-parse --short HEAD) with --features $FEATURES:"
  for so in target/deploy/*.so; do echo "    $(sha "$so")  $so"; done
  exit 1
fi
