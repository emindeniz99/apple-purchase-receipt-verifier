#!/bin/sh
# The five corpora (6,179 calls) through the host layer, each corpus's rows
# compared byte for byte with the module's own reference rows by same.py.
# The nightly `corpus` job runs it after putting the module in place;
# docs/evidence/2026-09-29-dotnet-host/scripts/corpus.sh is the copy that
# round recorded its results with.
#
#   sh dotnet/tools/corpus.sh <g1-dir> [<work-dir>]
#
# <g1-dir> holds calls/<corpus>.pinned.jsonl, rows/module-<corpus>.jsonl and
# same.py; every unpinned clock in its calls is pinned, so the rows must be
# identical: 6,179 of 6,179, 0 traps. <work-dir> (default: a fresh temporary
# directory) receives the build and the rows. The module the library embeds
# is whatever dotnet/src/ApplePurchaseReceiptVerifier/wasm/aprv.wasm holds.
set -eu
G1=${1:?usage: corpus.sh <g1-dir> [<work-dir>]}
REPO=$(cd "$(dirname "$0")/../.." && pwd)
WORK=${2:-$(mktemp -d)}
export DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
mkdir -p "$WORK/run"
dotnet build -c Release "$REPO/dotnet/tools/CorpusRun/CorpusRun.csproj" -o "$WORK/corpusrun" > "$WORK/build-corpusrun.log" 2>&1 \
  || { grep -E 'error' "$WORK/build-corpusrun.log" | head; exit 1; }
status=0
for c in cases hostile algorithms substrate fuzz; do
  start=$(date +%s)
  dotnet "$WORK/corpusrun/ApplePurchaseReceiptVerifier.CorpusRun.dll" calls "$G1/calls/$c.pinned.jsonl" > "$WORK/run/dotnet-$c.jsonl" 2> "$WORK/run/dotnet-$c.err"
  same=$(python3 "$G1/same.py" "$WORK/run/dotnet-$c.jsonl" "$G1/rows/module-$c.jsonl") || status=1
  echo "$c: $same; $(tail -1 "$WORK/run/dotnet-$c.err"); $(( $(date +%s) - start )) s wall"
done
exit $status
