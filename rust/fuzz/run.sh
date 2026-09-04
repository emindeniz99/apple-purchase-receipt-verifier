#!/usr/bin/env bash
# Runs one fuzz target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#
# libFuzzer takes several corpus directories and writes new units only to
# the first, so the shared fixtures seed every run without being copied
# into this directory. A crasher lands under artifacts/<target>/; turn it
# into a test under ../tests/ rather than committing it here.
set -euo pipefail

# cargo-fuzz needs a nightly toolchain for the sanitizer flags; FUZZ_TOOLCHAIN
# overrides which one.

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../../fixtures"
target="${1:?usage: run.sh <target>|all [seconds]}"
seconds="${2:-60}"

seeds() {
  case "$1" in
    parse-der|parse-certificate|parse-cms|verify-receipt)
      echo "$fixtures/generated" "$fixtures/apple-official/certs" ;;
    verify-receipt-base64)
      echo "$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode" ;;
    verify-transaction)
      echo "$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode" ;;
    endpoint-json)
      echo "$here/seeds/endpoint-json" ;;
    *) echo "unknown target: $1" >&2; exit 2 ;;
  esac
}

run_one() {
  local name="$1"
  mkdir -p "$here/corpus/$name"
  # shellcheck disable=SC2046
  cargo +"${FUZZ_TOOLCHAIN:-nightly}" fuzz run "$name" "$here/corpus/$name" $(seeds "$name") -- -max_total_time="$seconds"
}

if [ "$target" = all ]; then
  for name in parse-der parse-certificate parse-cms verify-receipt verify-receipt-base64 verify-transaction endpoint-json; do
    run_one "$name"
  done
else
  run_one "$target"
fi
