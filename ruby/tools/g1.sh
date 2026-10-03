#!/bin/sh
# One command for a module drop: put the module in place, run the
# gem's whole suite (every conformance case and the packaging round trip
# included), run the five corpora through the gem's host code and compare
# every row byte for byte with the reference rows. The nightly `corpus` job
# runs it; docs/evidence/2026-09-29-ruby-host/scripts/g1.sh is the copy that
# round recorded its results with.
#
#   sh ruby/tools/g1.sh <g1-dir> [<work-dir>]
#
# <g1-dir> has the corpus archive's layout: aprv.wasm, aprv.component.wasm and
# aprv.wit with the SHA256SUMS over them, calls/<corpus>.pinned.jsonl,
# rows/module-<corpus>.jsonl and same.py. <work-dir> (default: a fresh
# temporary directory) receives the gem's rows. The gem's bundle (ruby/Gemfile)
# must be installed. .github/scripts/place-module.sh checks <g1-dir> against
# its SHA256SUMS and puts the module in the gem's ignored path, rewriting
# aprv.wasm.sha256 in this checkout. Both are for this run only and never
# committed: the release tooling refreshes the pin.
set -eu
G1=${1:?usage: g1.sh <g1-dir> [<work-dir>]}
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${2:-$(mktemp -d)}
LIB="$ROOT/ruby/lib/apple_purchase_receipt_verifier"
mkdir -p "$WORK"

bash "$ROOT/.github/scripts/place-module.sh" "$G1" ruby
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
