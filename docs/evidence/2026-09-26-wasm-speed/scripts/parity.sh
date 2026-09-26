#!/bin/sh
# Spike only (2026-09-26). The gate for every candidate module: Node runs it
# over the 1,179 corpus rows and the 5,000 mutants (the wasm bake-off's
# js/run.mjs, trap host: any import other than the two aprv ones throws),
# and every row must be byte-identical (round 5's py/exact.py) to round 4's
# native C ABI rows of the same source, and, for the four corpora that have
# them, to round 4's Node rows of new-c.wasm. The imports must be exactly
# aprv.clock_now_ms and aprv.random_get.
#   parity.sh <name>   ($ART/<name>.wasm)   >> results/parity.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
N="$1"; W="$ART/$N.wasm"
imp=$(wasm-tools print "$W" | grep -oE '\(import "[^"]*" "[^"]*"' | sed 's/(import "//; s/" "/./; s/"//' | tr '\n' ' ')
[ "$imp" = "aprv.clock_now_ms aprv.random_get " ] && ok=yes || ok=NO
line="$N: imports [$imp] ok=$ok"
fail=0; [ $ok = yes ] || fail=1
for c in cases hostile algorithms substrate fuzz; do
  OUT="$S/run/$N-$c.jsonl"
  node "$PREV/js/run.mjs" --host trap "$W" "$CORPORA/$c.jsonl" > "$OUT" 2> "$OUT.err" || true
  n=$(python3 "$R5/py/exact.py" "$NATIVENEW-$c.jsonl" "$OUT")
  case "$n" in *" 0 differ") ;; *) fail=1 ;; esac
  x=""
  if [ -f "$NODEROWS-$c.jsonl" ]; then
    x=$(python3 "$R5/py/exact.py" "$NODEROWS-$c.jsonl" "$OUT"); case "$x" in *" 0 differ") ;; *) fail=1 ;; esac
    x=" / Node r4 $x"
  fi
  line="$line | $c: native $n$x"
done
[ $fail = 0 ] && line="PASS $line" || line="REJECT $line"
echo "$line"
