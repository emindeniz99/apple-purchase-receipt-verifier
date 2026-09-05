#!/usr/bin/env bash
# Runs one fuzz target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#
# libFuzzer takes several corpus directories and writes new units only to the
# first, so the shared fixtures seed every run without being copied into
# dotnet/. A crasher lands under artifacts/<target>/; reduce it and turn it
# into a test under ../tests/, where it runs on every runtime in the matrix
# rather than only where a fuzzer is installed.
#
# Environment:
#   CC          compiler for the driver              (default clang)
#   JOBS        parallel targets for `all`           (default 1)
#   MAX_LEN     libFuzzer -max_len                   (default 65536)
#   RSS_LIMIT   libFuzzer -rss_limit_mb              (default 4096)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../../fixtures"
target="${1:?usage: run.sh <target>|all [seconds]}"
seconds="${2:-60}"

all_targets=(json receipt receipt-base64 jws endpoint-json)

# The published binary is an apphost, and an apphost resolves the runtime
# through DOTNET_ROOT or /usr/share/dotnet — never through PATH. On any host
# where the SDK lives somewhere else (here: /opt/dotnet) it would otherwise
# die with "You must install .NET to run this application" the moment the
# driver execs it, which reads like a fuzzing failure and is not one.
if [ -z "${DOTNET_ROOT:-}" ]; then
  DOTNET_ROOT="$(dirname "$(readlink -f "$(command -v dotnet)")")"
  export DOTNET_ROOT
fi

driver="$here/libfuzzer-dotnet"
publish="$here/bin/fuzz"
binary="$publish/ApplePurchaseReceiptVerifier.Fuzz"

build() {
  # The driver: libFuzzer's own main, forking the .NET process and reading the
  # coverage bitmap back out of shared memory.
  if [ ! -x "$driver" ] || [ "$here/driver/libfuzzer-dotnet.cc" -nt "$driver" ]; then
    "${CC:-clang}" -fsanitize=fuzzer -O2 "$here/driver/libfuzzer-dotnet.cc" -o "$driver"
  fi

  # From scratch: `dotnet publish` skips copying a file it considers current,
  # so an incremental publish leaves the previously instrumented library in
  # place and sharpfuzz then refuses it as "already instrumented".
  rm -rf "$publish"
  dotnet publish "$here/ApplePurchaseReceiptVerifier.Fuzz.csproj" -c Release -o "$publish"

  # SharpFuzz rewrites the library's IL in place, adding the edge counters
  # libFuzzer scores coverage on. Only the library under test is instrumented:
  # instrumenting the fuzz harness would score the harness's own branches, and
  # instrumenting the BCL would drown the signal in string and Asn1 internals.
  # `dotnet tool run` resolves the manifest from the working directory, so the
  # tool calls are the one place this script needs to be in $here.
  (cd "$here" && dotnet tool restore \
    && dotnet tool run sharpfuzz "$publish/ApplePurchaseReceiptVerifier.dll" > /dev/null)
}

seeds_for() {
  case "$1" in
    json)
      echo "$here/seeds/json" "$here/seeds/generated/json" ;;
    receipt)
      echo "$fixtures/generated" "$fixtures/apple-official/certs" ;;
    receipt-base64)
      echo "$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode" ;;
    jws)
      echo "$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode" ;;
    endpoint-json)
      echo "$here/seeds/endpoint-json" "$here/seeds/generated/endpoint-json" ;;
    *)
      echo "unknown target: $1" >&2; exit 2 ;;
  esac
}

# The two JSON targets want request bodies, not receipts. Rather than commit a
# second copy of a 7 KB receipt, wrap the shared base64 fixtures into bodies at
# run time, into a gitignored directory.
generate_seeds() {
  local out="$here/seeds/generated"
  rm -rf "$out"
  mkdir -p "$out/endpoint-json" "$out/json"
  local n=0
  local file
  for file in "$fixtures"/public-receipts/*.b64 "$fixtures"/generated/receipt-b64/*.txt; do
    [ -f "$file" ] || continue
    n=$((n + 1))
    printf '{"receipt-data":"%s","password":"secret"}' \
      "$(tr -d '\n\r' < "$file")" > "$out/endpoint-json/receipt-$n.json"
  done
  cp "$out"/endpoint-json/*.json "$out/json/" 2>/dev/null || true
  cp "$fixtures/cases.json" "$out/json/cases.json"
  cp "$fixtures/generated/manifest.json" "$out/json/manifest.json"
}

run_one() {
  local name="$1"
  local seeds
  read -r -a seeds <<< "$(seeds_for "$name")"
  mkdir -p "$here/corpus/$name" "$here/artifacts/$name"
  echo "=== $name for ${seconds}s ==="
  APRV_FUZZ_TARGET="$name" "$driver" \
    --target_path="$binary" \
    "$here/corpus/$name" "${seeds[@]}" \
    -max_total_time="$seconds" \
    -max_len="${MAX_LEN:-65536}" \
    -rss_limit_mb="${RSS_LIMIT:-4096}" \
    -print_final_stats=1 \
    -artifact_prefix="$here/artifacts/$name/"
}

build
generate_seeds

if [ "$target" = all ]; then
  jobs="${JOBS:-1}"
  if [ "$jobs" -le 1 ]; then
    for name in "${all_targets[@]}"; do run_one "$name"; done
  else
    # One log per target, because interleaved libFuzzer output is unreadable.
    pids=()
    for name in "${all_targets[@]}"; do
      run_one "$name" > "$here/artifacts/$name.log" 2>&1 &
      pids+=("$!")
      while [ "$(jobs -rp | wc -l)" -ge "$jobs" ]; do wait -n; done
    done
    status=0
    for pid in "${pids[@]}"; do wait "$pid" || status=1; done
    for name in "${all_targets[@]}"; do
      echo "=== $name ==="; tail -n 20 "$here/artifacts/$name.log"
    done
    exit "$status"
  fi
else
  run_one "$target"
fi
