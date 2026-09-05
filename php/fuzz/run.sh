#!/usr/bin/env bash
# Runs one fuzz target for a fixed time budget, seeded from the shared
# fixtures.
#
#   ./run.sh <target> [seconds]      default 60
#   ./run.sh all [seconds]
#
# The fuzzer is nikic/php-fuzzer, downloaded as a pinned phar on first use
# (see README.md for why it is not a Composer dependency of the library).
#
# php-fuzzer takes exactly ONE corpus directory and WRITES new and reduced
# entries into it, so the libFuzzer trick of passing fixtures/ as an extra
# read-only corpus is not available. Seeds are therefore copied into a
# gitignored working corpus under corpus/<target>/ on every run; nothing under
# fixtures/ is modified, and nothing from it is committed under php/.
#
# A crasher lands in crashes/<target>/crash-<hash>.txt and the run exits 1 —
# and keeps exiting 1 on every later run until that file is deleted, which is
# deliberate: a known crasher stays failing until someone deals with it.
# Reduce it and pin it as a regression test under ../tests/, where it runs on
# every matrix leg rather than only when a fuzzer is around:
#
#   php fuzz/tools/php-fuzzer.phar minimize-crash \
#     fuzz/targets/<target>.php fuzz/crashes/<target>/crash-<hash>.txt
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fixtures="$here/../../fixtures"

# Pinned: the phar is verified against this digest before it is ever run.
PHAR_VERSION="v0.0.11"
PHAR_URL="https://github.com/nikic/PHP-Fuzzer/releases/download/${PHAR_VERSION}/php-fuzzer.phar"
PHAR_SHA256="8e8af960a993042b392b98927e9cb40237d466c22f0fc10feab2a40b1d679177"
phar="$here/tools/php-fuzzer-${PHAR_VERSION}.phar"

# php-fuzzer has no time budget of its own, only --max-runs, so the budget is
# imposed from outside; SIGTERM at the deadline is the normal end of a run.
TIMEOUT_EXIT=124

PHP_INI_ARGS=(
  # The library's bounds are sized against a 128M memory_limit. A generous but
  # FINITE ceiling keeps a runaway allocation a recorded finding — php-fuzzer's
  # shutdown handler saves the input that caused a fatal error — rather than an
  # OOM-killed container with nothing to reduce.
  -d memory_limit=512M
  # The instrumentation is a stream wrapper that rewrites source on include;
  # a compiled-code cache in front of it would serve uninstrumented bytecode.
  -d opcache.enable_cli=0
)

TARGETS=(parse-der parse-cms verify-receipt verify-receipt-base64 verify-transaction endpoint-json)

fetch_phar() {
  if [ -f "$phar" ] && echo "${PHAR_SHA256}  ${phar}" | sha256sum --check --status; then
    return
  fi
  mkdir -p "$here/tools"
  echo "downloading php-fuzzer ${PHAR_VERSION}"
  curl -fsSL -o "$phar.tmp" "$PHAR_URL"
  if ! echo "${PHAR_SHA256}  ${phar}.tmp" | sha256sum --check --status; then
    rm -f "$phar.tmp"
    echo "php-fuzzer.phar does not match the pinned sha256 — refusing to run it" >&2
    exit 2
  fi
  mv "$phar.tmp" "$phar"
}

# Fills SEED_DIRS for the named target.
seed_dirs() {
  case "$1" in
    parse-der|parse-cms|verify-receipt)
      SEED_DIRS=("$fixtures/generated" "$fixtures/apple-official/certs") ;;
    verify-receipt-base64)
      SEED_DIRS=("$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode") ;;
    verify-transaction)
      SEED_DIRS=("$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode") ;;
    endpoint-json)
      SEED_DIRS=("$here/seeds/endpoint-json") ;;
    *) echo "unknown target: $1" >&2; exit 2 ;;
  esac
}

run_one() {
  local name="$1" seconds="$2"
  local corpus="$here/corpus/$name" crashes="$here/crashes/$name"
  mkdir -p "$corpus" "$crashes"

  # Seeds are content-addressed so re-seeding is idempotent and a seed the
  # fuzzer replaced with a shorter equivalent is simply restored next run.
  local dir file
  seed_dirs "$name"
  for dir in "${SEED_DIRS[@]}"; do
    while IFS= read -r file; do
      cp -n "$file" "$corpus/seed-$(sha1sum "$file" | cut -c1-40)" 2>/dev/null || true
    done < <(find "$dir" -maxdepth 1 -type f)
  done

  local log="$crashes/run.log"
  echo "=== $name: ${seconds}s, corpus $(find "$corpus" -type f | wc -l) entries"
  local status=0
  # cwd is the crash directory: php-fuzzer writes crash-<hash>.txt to it.
  (cd "$crashes" && timeout --signal=TERM "$seconds" \
    php "${PHP_INI_ARGS[@]}" "$phar" fuzz "$here/targets/$name.php" "$corpus") \
    2>&1 | tee "$log" || status=$?
  if [ "$status" -ne 0 ] && [ "$status" -ne "$TIMEOUT_EXIT" ]; then
    echo "$name: the fuzzer itself exited $status" >&2
    return 1
  fi

  # Two ways a finding shows up: a crash file, and a seed that crashes on
  # load — php-fuzzer reports "CORPUS CRASH" and stops without writing one.
  if find "$crashes" -maxdepth 1 -name 'crash-*.txt' -print -quit | grep -q .; then
    echo "$name: CRASHER FOUND in $crashes" >&2
    return 1
  fi
  if grep -q 'CORPUS CRASH' "$log"; then
    echo "$name: a seed crashes the target — see $log" >&2
    return 1
  fi
}

target="${1:?usage: run.sh <target>|all [seconds]}"
seconds="${2:-60}"
fetch_phar

if [ "$target" = all ]; then
  failed=0
  for name in "${TARGETS[@]}"; do
    run_one "$name" "$seconds" || failed=1
  done
  exit "$failed"
fi
run_one "$target" "$seconds"
