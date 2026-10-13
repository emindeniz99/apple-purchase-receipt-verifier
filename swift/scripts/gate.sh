#!/bin/sh
# The Swift host's corpus parity run against one aprv.wasm build
# (DECISIONS.md R35), in one command:
#
#   swift/scripts/gate.sh DIR [--pin]
#
# DIR has the corpus archive's layout: aprv.wasm, aprv.component.wasm and
# aprv.wit with the SHA256SUMS over them, calls/<corpus>.pinned.jsonl
# (round 13's calls format, every clock pinned), rows/module-<corpus>.jsonl
# (the module's own answers through the trap host, the reference rows) and
# same.py (the byte-for-byte row comparison).
#
#  1. checks DIR/aprv.wasm against the committed aprv.wasm.sha256 (--pin
#     accepts a module the pin does not name), then
#     .github/scripts/place-module.sh checks DIR against its SHA256SUMS and
#     copies the module over the package's committed resource, rewriting the
#     pin in this checkout. Both are for this run only and never committed:
#     the release tooling refreshes the module and its pin;
#  2. builds the package and its tests, optimised (WasmKit interprets, and
#     a debug build is far too slow): the corpus runs as one test,
#     MeasurementTests/testCorpus;
#  3. runs the five corpora through the package's host layer and compares
#     each corpus's rows with DIR/rows/module-<corpus>.jsonl.
#
# Rows only: the whole suite, every case in fixtures/cases.json included,
# runs in ci.yml against the freshly built module, and the archive's module
# predates whatever the core and the shared cases changed since its
# release; swift/bench times the public API on its own.
#
# Environment: SCRATCH_PATH is swift build's --scratch-path (default
# .build), OUT where the rows and logs go (default $SCRATCH_PATH/gate),
# JOBS the build parallelism (default 2). Exits non-zero if the build
# fails or any row differs or traps.
set -u
DIR=${1:?usage: gate.sh DIR [--pin]}
shift
PIN=false
for a in "$@"; do
  case "$a" in
  --pin) PIN=true ;;
  *) echo "unknown option $a" >&2; exit 2 ;;
  esac
done
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RES="$ROOT/swift/Sources/ApplePurchaseReceiptVerifier/Resources"
SCRATCH_PATH=${SCRATCH_PATH:-$ROOT/.build}
OUT=${OUT:-$SCRATCH_PATH/gate}
JOBS=${JOBS:-2}
mkdir -p "$OUT"
status=0

# A timed-out `swift test` leaves the test binary running: kill it.
reap() { pkill -f "$SCRATCH_PATH/.*PackageTests[.]xctest" 2>/dev/null || true; }

echo "== 1. module"
got=$(sha256sum "$DIR/aprv.wasm" | cut -c1-64)
want=$(cut -c1-64 "$RES/aprv.wasm.sha256")
if [ "$PIN" != true ] && [ "$got" != "$want" ]; then
  echo "FAIL: $DIR/aprv.wasm is $got, the pin is $want (rerun with --pin)"
  exit 1
fi
bash "$ROOT/.github/scripts/place-module.sh" "$DIR" swift || exit 1
echo "aprv.wasm $got, $(wc -c < "$RES/aprv.wasm") bytes, in place"

echo "== 2. build the package and its tests"
BUILD="swift build -c release -Xswiftc -enable-testing -j $JOBS --package-path $ROOT --scratch-path $SCRATCH_PATH --build-tests"
TEST="swift test -c release -Xswiftc -enable-testing --package-path $ROOT --scratch-path $SCRATCH_PATH --skip-build"
if ! $BUILD > "$OUT/build.log" 2>&1; then
  tail -20 "$OUT/build.log"
  echo "FAIL: build"
  exit 1
fi

echo "== 3. corpus against the reference rows"
APRV_CORPUS_CALLS="$DIR/calls" APRV_CORPUS_SUFFIX=.pinned.jsonl APRV_CORPUS_OUT="$OUT" APRV_CORPUS_LABEL=swift \
  timeout 3600 $TEST --filter MeasurementTests/testCorpus > "$OUT/corpus.log" 2>&1 || status=1
reap
grep '^corpus: ' "$OUT/corpus.log"
for c in cases hostile algorithms substrate fuzz; do
  printf '%s: ' "$c"
  python3 "$DIR/same.py" "$OUT/swift-$c.jsonl" "$DIR/rows/module-$c.jsonl" --list || status=1
done
echo "restore the committed module and pin: git -C \"$ROOT\" checkout -- swift/Sources/ApplePurchaseReceiptVerifier/Resources"
exit "$status"
