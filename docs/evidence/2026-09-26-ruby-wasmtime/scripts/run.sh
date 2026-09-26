#!/bin/sh
# Spike only (2026-09-26). Runs the harness against the gem as installed by
# build.sh (the clean GEM_HOME), from an empty directory.
#   run.sh tests|calls|startup|bench|threads|processes|isolation
#   APRV_GVL=1 run.sh threads   the same with the GVL held during aprv_call
#                               (wasmtime-rb's default) > results/threads-gvl-held.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
cd "$S/consumer"
case "$1" in
tests) ruby "$RW/rb/abi_tests.rb" "$CALLS/cases.jsonl" ;;
calls)
  for c in cases hostile algorithms substrate fuzz; do
    start=$(date +%s%N)
    ruby "$RW/rb/run_calls.rb" "$CALLS/$c.jsonl" > "$S/run/ruby-$c.jsonl" 2> "$S/run/ruby-$c.err"
    ms=$(( ($(date +%s%N) - start) / 1000000 ))
    python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/ruby-$c.jsonl" \
      | sed "1s#^#$c (node): #; 2s#^other host 1#    ruby#"
    echo "    $(cat "$S/run/ruby-$c.err") ${ms} ms wall"
  done ;;
startup) for i in 1 2 3 4 5; do ruby "$RW/rb/startup.rb" "$CALLS/cases.jsonl"; done ;;
bench|threads|processes|isolation) ruby "$RW/rb/concurrency.rb" "$CALLS/cases.jsonl" "$1" ;;
*) echo "usage: run.sh tests|calls|startup|bench|threads|processes|isolation"; exit 2 ;;
esac
