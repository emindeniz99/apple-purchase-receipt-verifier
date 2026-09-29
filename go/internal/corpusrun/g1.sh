#!/bin/sh
# One command for the G1 re-run: check the module, run the whole suite, and
# compare the five corpora through the host layer with the reference rows.
#
#   g1.sh G1_DIR [WORK_DIR]
#
# G1_DIR holds aprv.wasm, calls/<corpus>.pinned.jsonl, rows/module-<corpus>.jsonl
# and same.py (the release job's evidence directory). The module is copied to
# internal/wasm/aprv.wasm (git-ignored) and its hash written to
# aprv.wasm.sha256; commit that file, never the module. WORK_DIR (default a
# temporary directory) receives the rows. Exit status is 0 only when the tests
# pass and every corpus row is identical with no trap.
set -u
g1=${1:?usage: g1.sh G1_DIR [WORK_DIR]}
work=${2:-$(mktemp -d)}
here=$(cd "$(dirname "$0")/../.." && pwd)   # the go/ directory
cd "$here" || exit 2
cp "$g1/aprv.wasm" internal/wasm/aprv.wasm || exit 2
(cd internal/wasm && sha256sum aprv.wasm > aprv.wasm.sha256 && cat aprv.wasm.sha256)
status=0
go vet ./... && go test ./... || status=1
CGO_ENABLED=0 go build -o "$work/corpusrun" ./internal/corpusrun || exit 2
for c in cases hostile algorithms substrate fuzz; do
  "$work/corpusrun" "$g1/calls/$c.pinned.jsonl" > "$work/host-$c.jsonl" 2> "$work/host-$c.err" || status=1
  printf '%s: ' "$c"
  python3 "$g1/same.py" "$g1/rows/module-$c.jsonl" "$work/host-$c.jsonl" || status=1
done
exit $status
