#!/bin/sh
# Spike only (2026-09-26). Runs everything against the facade as installed
# in the clean wheel consumer (build.sh), from an empty directory, so the
# code under test is the installed package, not this folder's source.
#   run.sh tests       the ABI tests + facade contract     > results/abi-tests.txt
#   run.sh calls       five corpora; parity and byte identity with Node > results/calls.txt
#   run.sh startup     five fresh processes                > results/startup.txt
#   run.sh bench|threads|processes|isolation              > results/<same>.txt
#   run.sh slab        the wasmtime-py 49.0.0 handle-table race, both patterns > results/slab-race.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
PY="$S/venv-wheel/bin/python"
cd "$S/consumer"
case "$1" in
tests) "$PY" "$PW/py/abi_tests.py" "$CALLS/cases.jsonl" ;;
calls)
  for c in cases hostile algorithms substrate fuzz; do
    start=$(date +%s%N)
    "$PY" "$PW/py/run_calls.py" "$CALLS/$c.jsonl" > "$S/run/python-$c.jsonl" 2> "$S/run/python-$c.err"
    ms=$(( ($(date +%s%N) - start) / 1000000 ))
    python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/python-$c.jsonl" \
      | sed "1s#^#$c (node): #; 2s#^other host 1#    python#"
    echo "    $(cat "$S/run/python-$c.err") ${ms} ms wall"
  done ;;
startup) for i in 1 2 3 4 5; do "$PY" "$PW/py/startup.py" "$CALLS/cases.jsonl"; done ;;
bench|threads|processes|isolation) "$PY" "$PW/py/concurrency.py" "$CALLS/cases.jsonl" "$1" ;;
slab) for m in per-store facade; do "$PY" "$PW/py/slab_race.py" "$m"; done ;;
*) echo "usage: run.sh tests|calls|startup|bench|threads|processes|isolation|slab"; exit 2 ;;
esac
