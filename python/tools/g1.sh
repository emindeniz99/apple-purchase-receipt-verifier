#!/bin/sh
# Re-runs the lane against a new aprv.wasm, in one command, from python/:
#
#     PYTHON=/path/to/venv/bin/python tools/g1.sh G1_DIR
#
# G1_DIR holds aprv.wasm, calls/<corpus>.pinned.jsonl, rows/module-<corpus>.jsonl
# and same.py (the layout the core lane hands over). The steps:
#   1. copy aprv.wasm into the package (git-ignored) and rewrite the tracked
#      aprv.wasm.sha256 from it; `git diff` then shows the pin to commit;
#   2. the whole test suite, every conformance case included;
#   3. every corpus through the host layer, compared byte for byte with the
#      module's own rows. A differing row is reported, never adjusted.
# Exit status is 0 only when all of it passed. Nothing here is committed but
# the pin; the module and the outputs stay outside the repository.
set -eu
G1=${1:?usage: tools/g1.sh G1_DIR}
PYTHON=${PYTHON:-python3}
HERE=$(cd "$(dirname "$0")/.." && pwd)
PKG=$HERE/apple_purchase_receipt_verifier
OUT=${G1_OUT:-$(mktemp -d)}
status=0

cp "$G1/aprv.wasm" "$PKG/aprv.wasm"
digest=$("$PYTHON" -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$PKG/aprv.wasm")
printf '%s  aprv.wasm\n' "$digest" > "$PKG/aprv.wasm.sha256"
echo "== module $digest"

echo "== tests"
(cd "$HERE" && "$PYTHON" -m unittest discover -s tests) || status=1

echo "== corpora (rows written to $OUT)"
for calls in "$G1"/calls/*.pinned.jsonl; do
  name=$(basename "$calls" .pinned.jsonl)
  start=$("$PYTHON" -c 'import time;print(time.time())')
  "$PYTHON" "$HERE/tests/corpus_rows.py" "$calls" > "$OUT/py-$name.jsonl" 2> "$OUT/py-$name.err" || status=1
  end=$("$PYTHON" -c 'import time;print(time.time())')
  printf '%s: ' "$name"
  "$PYTHON" "$G1/same.py" "$OUT/py-$name.jsonl" "$G1/rows/module-$name.jsonl" || status=1
  "$PYTHON" -c 'import sys;print("   %.1f s" % (float(sys.argv[2]) - float(sys.argv[1])))' "$start" "$end"
done
exit $status
