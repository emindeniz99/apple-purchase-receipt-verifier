#!/usr/bin/env bash
# Runs one fuzz target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#
# libFuzzer takes several corpus directories and writes new units only to
# the first, so the shared fixtures seed every run without being copied into
# this directory. A crasher lands under artifacts/<target>/; turn it into a
# test under ../test/ rather than committing it here.
#
# Requires `npm ci` in this directory first — the fuzzer is a dev dependency
# of this directory alone, not of the published package.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../../fixtures"
jazzer="$here/node_modules/.bin/jazzer"
target="${1:?usage: run.sh <target>|all [seconds]}"
seconds="${2:-60}"

if [ ! -x "$jazzer" ]; then
  echo "jazzer is not installed: run 'npm ci' in $here" >&2
  exit 2
fi
if [ ! -f "$here/../dist/index.js" ]; then
  echo "the library is not built: run 'npm run build' in $here/.." >&2
  exit 2
fi

# The endpoint target's one seed that carries a real receipt is built here
# from the public fixture rather than checked in, so the receipt has exactly
# one copy in the repository.
generated="$here/.seeds-generated/endpoint-json"
mkdir -p "$generated"
node -e '
  const { readFileSync, writeFileSync } = require("node:fs");
  const b64 = readFileSync(process.argv[1], "ascii").replace(/\s+/g, "");
  writeFileSync(process.argv[2], JSON.stringify({ "receipt-data": b64 }));
' "$fixtures/public-receipts/receipt-sandbox-g5.b64" "$generated/sandbox-g5.json"

run_one() {
  local name="$1"
  local seeds
  case "$name" in
    parse-der | parse-cms | verify-receipt)
      seeds=("$fixtures/generated" "$fixtures/apple-official/certs") ;;
    verify-receipt-base64)
      seeds=("$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode") ;;
    verify-transaction)
      seeds=("$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode") ;;
    endpoint-json)
      seeds=("$here/seeds/endpoint-json" "$generated") ;;
    *) echo "unknown target: $name" >&2; exit 2 ;;
  esac
  mkdir -p "$here/corpus/$name" "$here/artifacts/$name"
  echo "=== $name (${seconds}s) ==="
  "$jazzer" "$here/targets/$name.mjs" "$here/corpus/$name" "${seeds[@]}" --sync \
    -- -max_total_time="$seconds" -artifact_prefix="$here/artifacts/$name/" -print_final_stats=1
}

if [ "$target" = all ]; then
  for name in parse-der parse-cms verify-receipt verify-receipt-base64 verify-transaction endpoint-json; do
    run_one "$name"
  done
else
  run_one "$target"
fi
