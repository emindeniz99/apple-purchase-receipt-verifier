#!/usr/bin/env bash
# Runs one fuzz target for a fixed budget, seeded from the shared fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#   ./run.sh list
#
# libFuzzer takes several corpus directories and writes new units only to the
# first, so fixtures/ seeds every run without being copied into this port. A
# crasher lands under artifacts/<target>/; reduce it and pin it as a test
# under ../test/, where it runs on every Ruby in the matrix rather than only
# where a libFuzzer-capable clang is around.
#
# Set BUNDLE_GEMFILE (to ../gemfiles/fuzz.gemfile) to run under Bundler;
# otherwise ruzzy is taken from the ambient gem path.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../../fixtures"

TARGETS=(parse_der parse_cms verify_receipt verify_receipt_base64 verify_transaction endpoint_json)

target="${1:?usage: run.sh <target>|all|list [seconds]}"
seconds="${2:-60}"

if [ "$target" = list ]; then
  printf '%s\n' "${TARGETS[@]}"
  exit 0
fi

if [ -n "${BUNDLE_GEMFILE:-}" ]; then
  runner=(bundle exec ruby)
else
  runner=(ruby)
fi

# The libFuzzer runtime lives in a shared object ruzzy built at install time;
# it has to be in the process before Ruby starts, which is what LD_PRELOAD is
# for. Resolved through the same runner so a Bundler run finds the same gem.
asan_path="$("${runner[@]}" -e 'require "ruzzy"; print Ruzzy::ASAN_PATH')"

# detect_leaks: Ruby's own allocations are not this fuzzer's business.
# use_sigaltstack=0 keeps ASAN's alternate signal stack away from the one Ruby
# installs to turn stack overflow into SystemStackError — without it a deep
# input crashes the process instead of raising, and the depth bound the
# scanner exists to enforce cannot be observed.
export ASAN_OPTIONS="detect_leaks=0:allocator_may_return_null=1:use_sigaltstack=0:${ASAN_OPTIONS:-}"

# No -timeout: libFuzzer's per-unit watchdog is a SIGALRM it declines to
# install over an existing handler, and under Ruby it is never installed, so
# the alarm reaches the default disposition and kills the run (measured: exit
# 142 at timeout/2+1 seconds, with no libFuzzer timeout report). A hanging
# unit is caught by the caller's budget instead — `timeout` locally, the job
# timeout in CI. Go and Rust run their targets on library defaults too.

run_one() {
  local name="$1"
  local seeds

  case "$name" in
    parse_der|parse_cms|verify_receipt)
      seeds=("$fixtures/generated" "$fixtures/apple-official/certs") ;;
    verify_receipt_base64)
      seeds=("$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode") ;;
    verify_transaction)
      seeds=("$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode") ;;
    endpoint_json)
      "${runner[@]}" "$here/seeds.rb" "$here/.seeds/endpoint_json" >&2
      seeds=("$here/.seeds/endpoint_json") ;;
    *) echo "unknown target: $name (try: ./run.sh list)" >&2; exit 2 ;;
  esac

  mkdir -p "$here/corpus/$name" "$here/artifacts/$name"
  echo "=== $name for ${seconds}s ===" >&2
  APRV_FUZZ_TARGET="$name" \
  LD_PRELOAD="$asan_path" \
    "${runner[@]}" "$here/tracer.rb" \
      "$here/corpus/$name" "${seeds[@]}" \
      -max_total_time="$seconds" \
      -artifact_prefix="$here/artifacts/$name/" \
      -print_final_stats=1 \
      -rss_limit_mb=4096
}

if [ "$target" = all ]; then
  for name in "${TARGETS[@]}"; do
    run_one "$name"
  done
else
  run_one "$target"
fi
