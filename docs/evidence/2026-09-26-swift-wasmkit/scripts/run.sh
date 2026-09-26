#!/bin/sh
# Spike only (2026-09-26). Runs the harness built by build.sh package:
#   run.sh tests       ABI tests + facade contract          > results/abi-tests.txt
#   run.sh calls       five corpora; parity and byte identity with Node > results/calls.txt
#   run.sh startup     five fresh processes                 > results/startup.txt
#   run.sh bench       one thread: g5 (op 1) and JWS (op 258), three runs each > results/bench.txt
#   run.sh threads     1/2/4 threads, one instance each     > results/threads.txt
#   run.sh isolation   independent instances; traps under concurrency > results/isolation.txt
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
G5=receipt/verify-genuine-sandbox-g5-against-apple-roots
JWS=transaction/verify-shared-sandbox
case "$1" in
tests) "$TOOL" tests "$CALLS/cases.jsonl" ;;
calls)
  for c in cases hostile algorithms substrate fuzz; do
    start=$(date +%s)
    "$TOOL" calls "$CALLS/$c.jsonl" > "$S/run/swift-$c.jsonl" 2> "$S/run/swift-$c.err"
    s=$(( $(date +%s) - start ))
    python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/swift-$c.jsonl" \
      | sed "1s#^#$c (node): #; 2s#^other host 1#    swift#"
    echo "    $(cat "$S/run/swift-$c.err") ${s} s wall"
  done ;;
startup) for i in 1 2 3 4 5; do "$TOOL" startup "$CALLS/cases.jsonl"; done ;;
bench)
  echo "# $(nproc) cores; load average $(cut -d' ' -f1-3 /proc/loadavg)"
  for r in 1 2 3; do "$TOOL" bench "$CALLS/cases.jsonl" "$G5" 20 200; done
  for r in 1 2 3; do "$TOOL" bench "$CALLS/cases.jsonl" "$JWS" 10 60; done ;;
threads)
  echo "# $(nproc) cores; load average $(cut -d' ' -f1-3 /proc/loadavg)"
  for t in 1 2 4; do "$TOOL" threads "$CALLS/cases.jsonl" "$G5" "$t" 20 150; done
  for t in 1 2 4; do "$TOOL" threads "$CALLS/cases.jsonl" "$JWS" "$t" 10 50; done ;;
isolation) "$TOOL" isolation "$CALLS/cases.jsonl" ;;
*) echo "usage: run.sh tests|calls|startup|bench|threads|isolation"; exit 2 ;;
esac
