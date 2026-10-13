#!/bin/sh
# The corpus parity run against an aprv.wasm (DECISIONS.md R35), from
# python/:
#
#     PYTHON=/path/to/venv/bin/python tools/g1.sh G1_DIR
#
# G1_DIR has the corpus archive's layout: aprv.wasm, aprv.component.wasm and
# aprv.wit with the SHA256SUMS over them, calls/<corpus>.pinned.jsonl,
# rows/module-<corpus>.jsonl and same.py. The steps:
#   1. .github/scripts/place-module.sh checks G1_DIR against its SHA256SUMS
#      and puts aprv.wasm in the package, rewriting aprv.wasm.sha256 in this
#      checkout. Both are for this run only and never committed: the release
#      tooling refreshes the pin;
#   2. every corpus through the host layer, compared byte for byte with the
#      module's own rows. A differing row is reported, never adjusted.
# Rows only: the test suite runs in ci.yml against the freshly built
# module, and the archive's module predates whatever the core and the
# shared cases changed since its release. Exit status is 0 only when every
# row is identical. The module and the outputs stay outside the repository.
set -eu
G1=${1:?usage: tools/g1.sh G1_DIR}
PYTHON=${PYTHON:-python3}
HERE=$(cd "$(dirname "$0")/.." && pwd)
PKG=$HERE/apple_purchase_receipt_verifier
OUT=${G1_OUT:-$(mktemp -d)}
status=0

bash "$HERE/../.github/scripts/place-module.sh" "$G1" python
echo "== module $(cut -c1-64 "$PKG/aprv.wasm.sha256")"

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
