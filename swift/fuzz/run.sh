#!/usr/bin/env bash
# Runs one fuzz target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#
# The binaries are libFuzzer executables, so the shared fixtures are passed
# as extra corpus directories: libFuzzer reads all of them and writes new
# units only to the first, which is why nothing under fixtures/ is copied
# into this directory. A crasher lands under artifacts/<target>/; turn it
# into a test under ../Tests/ rather than committing it here.
#
# FUZZ_SANITIZERS overrides the sanitizer set. The default is `fuzzer`
# alone — coverage instrumentation and the mutator, no memory checking.
# `fuzzer,address` adds AddressSanitizer, which is worth a long run
# occasionally but roughly halves the executions per second, and Swift's own
# bounds and overflow checks already trap on the memory errors this library
# could commit in its own code.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../../fixtures"
target="${1:?usage: run.sh <target>|all [seconds]}"
seconds="${2:-60}"
sanitizers="${FUZZ_SANITIZERS:-fuzzer}"
targets=(receipt-der receipt-base64 jws endpoint-json receipt-payload readers)

# -sanitize=fuzzer instruments every target in the graph, dependencies
# included, so the fuzzer can steer into swift-asn1 and swift-certificates
# rather than only into this repository's own code. -enable-testing is what
# lets Sources/FuzzSupport reach the library's internal readers. There is no
# -parse-as-library: SwiftPM aliases a Linux executable's `main` to the
# module's entry point, so each target keeps a main.swift and starts
# libFuzzer through LLVMFuzzerRunDriver (see FuzzSupport.runFuzzer).
swift build --package-path "$here" -c release \
  -Xswiftc "-sanitize=$sanitizers" \
  -Xswiftc -enable-testing

bin="$(swift build --package-path "$here" -c release --show-bin-path)"

# The endpoint seed that carries a real receipt is built here from the
# public fixture rather than checked in, so that receipt keeps exactly one
# copy in the repository.
generated="$here/.seeds-generated/endpoint-json"
mkdir -p "$generated"
printf '{"receipt-data":"%s"}' \
  "$(tr -d '\r\n' < "$fixtures/public-receipts/receipt-sandbox-g5.b64")" \
  > "$generated/sandbox-g5.json"

run_one() {
  local name="$1"
  local seeds
  case "$name" in
    receipt-der | receipt-payload)
      seeds=("$fixtures/generated" "$fixtures/apple-official/certs") ;;
    readers)
      seeds=("$fixtures/generated/receipt-b64" "$fixtures/public-receipts") ;;
    receipt-base64)
      seeds=("$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode") ;;
    jws)
      seeds=("$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode") ;;
    endpoint-json)
      seeds=("$here/seeds/endpoint-json" "$generated") ;;
    *) echo "unknown target: $name" >&2; exit 2 ;;
  esac
  mkdir -p "$here/corpus/$name" "$here/artifacts/$name"
  echo "=== $name (${seconds}s, -sanitize=$sanitizers) ==="
  APRV_FIXTURES="$fixtures" "$bin/$name" "$here/corpus/$name" "${seeds[@]}" \
    -max_total_time="$seconds" \
    -artifact_prefix="$here/artifacts/$name/" \
    -print_final_stats=1
}

if [ "$target" = all ]; then
  for name in "${targets[@]}"; do
    run_one "$name"
  done
else
  run_one "$target"
fi
