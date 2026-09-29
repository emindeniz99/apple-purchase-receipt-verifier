#!/bin/sh
# One command for a module drop: install the module, pin its hash, run the
# gem's whole suite (the 311 cases and the packaging round trip included), run
# the five corpora through the gem's host code and compare every row byte for
# byte with the reference rows.
#
#   sh g1.sh <g1-dir> [<work-dir>]
#
# <g1-dir> holds aprv.wasm, calls/<corpus>.pinned.jsonl, rows/module-<corpus>.jsonl
# and same.py. <work-dir> (default: a fresh temporary directory) receives the
# gem's rows. The gem's bundle (ruby/Gemfile) must be installed. Nothing is
# committed by this script: the module goes to the gem's ignored path and only
# aprv.wasm.sha256 changes.
set -eu
G1=${1:?usage: g1.sh <g1-dir> [<work-dir>]}
ROOT=$(cd "$(dirname "$0")/../../../.." && pwd)
WORK=${2:-$(mktemp -d)}
LIB="$ROOT/ruby/lib/apple_purchase_receipt_verifier"
mkdir -p "$WORK"

cp "$G1/aprv.wasm" "$LIB/aprv.wasm"
printf '%s  aprv.wasm\n' "$(sha256sum "$LIB/aprv.wasm" | cut -d' ' -f1)" > "$LIB/aprv.wasm.sha256"
echo "module: $(wc -c < "$LIB/aprv.wasm") bytes, $(cut -d' ' -f1 "$LIB/aprv.wasm.sha256")"

status=0
echo "== suite"
(cd "$ROOT/ruby" && APRV_PACKAGING=1 bundle exec rake test) > "$WORK/suite.out" 2>&1 || status=1
grep 'runs, ' "$WORK/suite.out" || status=1

echo "== corpora"
for c in cases hostile algorithms substrate fuzz; do
  (cd "$ROOT/ruby" && bundle exec ruby -Ilib bench/corpus.rb "$G1/calls/$c.pinned.jsonl") \
    > "$WORK/ruby-$c.jsonl" 2> "$WORK/ruby-$c.err"
  printf '%s: ' "$c"
  python3 "$G1/same.py" "$WORK/ruby-$c.jsonl" "$G1/rows/module-$c.jsonl" --list || status=1
done
exit $status
