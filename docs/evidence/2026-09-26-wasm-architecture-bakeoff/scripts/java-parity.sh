#!/bin/sh
# Three-way Java tallies for every wasm run: Java oracle (JDK 25 + BC 1.86,
# the previous bake-off's rows) vs current Rust native vs the wasm artifact,
# through the previous bake-off's py/tri.py, next to the tallies of the
# native build of the same backend.
#
#   scripts/java-parity.sh > results/java-parity.txt
#
# Columns of each tally: agree cand=java cand=rust cand-own abi.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
TRI="$SPIKE/py/tri.py"
tally() { python3 "$TRI" "$CORPORA/$1.jsonl" "$CORPORA/jvm25-$1.jsonl" "$SCRATCH/run/rust-$1.jsonl" "$2" 2>/dev/null | awk '$1 == "total" { print $2, $3, $4, $5, $6 }'; }
echo "# py/tri.py (previous bake-off) on wasm rows, 2026-09-26. Java oracle rows reused, not rerun."
echo "# Tally columns: agree cand=java cand=rust cand-own abi. 'same' = identical to the native build of the same backend."
echo "# rust-uu-noseam and ossl-w1h-rng* are diagnostic runs (clock trap; broken RNG), not candidates."
echo "# ossl-em-workerd is the failed node+web-glue run (results/builds.txt); its rows are empty, ossl-em-web-workerd is the rerun."
printf '%-34s %-5s %-24s %-24s %-24s %-24s %s\n' run nat cases substrate hostile algorithms vs-native
for f in "$SCRATCH"/wrun/*-cases.jsonl; do
  p=$(basename "$f" -cases.jsonl)
  case "$p" in awslc*) n=awslc ;; ossl*) n=ossl402 ;; libressl*) n=libressl432 ;; *) n=rust ;; esac
  line=""; all=same
  for c in cases substrate hostile algorithms; do
    w=$(tally $c "$SCRATCH/wrun/$p-$c.jsonl")
    nat=$(tally $c "$SCRATCH/run/$n-$c.jsonl")
    [ -n "$w" ] || { w="no rows"; all="NO ROWS"; }
    [ "$w" = "$nat" ] || [ "$all" = "NO ROWS" ] || all=DIFFERS
    line="$line$(printf '%-24s ' "$w")"
  done
  printf '%-34s %-5s %s%s\n' "$p" "$(echo $n | cut -c1-5)" "$line" "$all"
done
echo
echo "# native reference tallies (same script, rows from scripts/native-baseline.sh)"
for n in rust awslc ossl402 libressl432; do
  line=""
  for c in cases substrate hostile algorithms; do line="$line$(printf '%-24s ' "$(tally $c "$SCRATCH/run/$n-$c.jsonl")")"; done
  printf '%-34s %-5s %s\n' "native $n" "$(echo $n | cut -c1-5)" "$line"
done
