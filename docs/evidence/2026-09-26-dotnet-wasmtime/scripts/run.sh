#!/bin/sh
# Spike only (2026-09-26). Runs the harness (build.sh tool) on .NET 10:
#   run.sh tests|calls|startup|bench|threads|isolation
# RUNTIME=8 runs the net8.0 build instead (needs the .NET 8 runtime in DOTNET_ROOT).
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
T="$TOOL"; [ "${RUNTIME:-10}" = 8 ] && T="$TOOL8"
G5=receipt/verify-genuine-sandbox-g5-against-apple-roots
JWS=transaction/verify-shared-sandbox
cd "$S"
case "$1" in
tests) dotnet "$T" tests "$CALLS/cases.jsonl" ;;
calls)
  for c in cases hostile algorithms substrate fuzz; do
    start=$(date +%s%N)
    dotnet "$T" calls "$CALLS/$c.jsonl" > "$S/run/dotnet-$c.jsonl" 2> "$S/run/dotnet-$c.err"
    ms=$(( ($(date +%s%N) - start) / 1000000 ))
    python3 "$AB/py/abi_compare.py" "$CORPORA/$c.jsonl" "$NATIVENEW-$c.jsonl" "$CALLS/$c.jsonl" "$NODEROWS/node-$c.jsonl" "$S/run/dotnet-$c.jsonl" \
      | sed "1s#^#$c (node): #; 2s#^other host 1#    dotnet#"
    echo "    $(cat "$S/run/dotnet-$c.err") ${ms} ms wall"
  done ;;
startup) for i in 1 2 3 4 5; do dotnet "$T" startup "$CALLS/cases.jsonl"; done ;;
bench)
  echo "# $(nproc) cores; load average $(cut -d' ' -f1-3 /proc/loadavg)"
  for r in 1 2 3; do dotnet "$T" bench "$CALLS/cases.jsonl" "$G5" 200 1000; done
  for r in 1 2 3; do dotnet "$T" bench "$CALLS/cases.jsonl" "$JWS" 200 1000; done ;;
threads)
  echo "# $(nproc) cores; load average $(cut -d' ' -f1-3 /proc/loadavg)"
  for t in 1 2 4; do dotnet "$T" threads "$CALLS/cases.jsonl" "$G5" "$t" 300 600; done
  for t in 1 2 4; do dotnet "$T" threads "$CALLS/cases.jsonl" "$JWS" "$t" 150 300; done ;;
isolation) dotnet "$T" isolation "$CALLS/cases.jsonl" ;;
*) echo "usage: run.sh tests|calls|startup|bench|threads|isolation"; exit 2 ;;
esac
