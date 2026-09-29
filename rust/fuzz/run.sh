#!/usr/bin/env bash
# Runs one fuzz target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]           every target but abi-call
#
# abi-call (a package of its own under abi/, with Wasmtime) needs the built
# module: APRV_WASM=<out>/aprv.wasm ./run.sh abi-call [seconds].
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

run_one() {
  local name="$1"
  local seeds
  case "$name" in
    verify-receipt)
      seeds=("$fixtures/generated" "$fixtures/generated-0.7" "$fixtures/apple-official/certs") ;;
    verify-receipt-base64)
      seeds=("$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode") ;;
    verify-transaction)
      seeds=("$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode") ;;
    endpoint-json)
      seeds=("$here/seeds/endpoint-json") ;;
    ffi)
      seeds=("$fixtures/generated/receipt-b64" "$fixtures/generated" "$here/seeds/endpoint-json") ;;
    abi-call)
      [ -n "${APRV_WASM:-}" ] || { echo "abi-call needs APRV_WASM=<out>/aprv.wasm (rust/bindings/abi/build.sh)" >&2; exit 2; }
      seeds=("$fixtures/generated/receipt-b64" "$fixtures/generated" "$here/seeds/endpoint-json")
      mkdir -p "$here/abi/corpus/$name"
      cargo +"${FUZZ_TOOLCHAIN:-nightly}" fuzz run --fuzz-dir "$here/abi" "$name" "$here/abi/corpus/$name" "${seeds[@]}" -- -max_total_time="$seconds"
      return ;;
    *) echo "unknown target: $name" >&2; exit 2 ;;
  esac
  mkdir -p "$here/corpus/$name"
  cargo +"${FUZZ_TOOLCHAIN:-nightly}" fuzz run "$name" "$here/corpus/$name" "${seeds[@]}" -- -max_total_time="$seconds"
}

if [ "$target" = all ]; then
  for name in verify-receipt verify-receipt-base64 verify-transaction endpoint-json ffi; do
    run_one "$name"
  done
else
  run_one "$target"
fi
