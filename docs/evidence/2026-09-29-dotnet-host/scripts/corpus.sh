#!/bin/sh
# The five corpora (6,179 calls) through the host layer, each corpus's rows
# compared byte for byte with the module's own reference rows by same.py.
#   REPO=... SCRATCH=... G1=<folder with calls/, rows/, same.py> sh corpus.sh
# G1's calls/<corpus>.pinned.jsonl have every unpinned clock pinned, so the
# rows must be identical: 6,179 of 6,179, 0 traps.
set -eu
. "$(dirname "$0")/env.sh"
: "${G1:?the folder with calls/, rows/ and same.py}"
mkdir -p "$S/run"
dotnet build -c Release "$REPO/dotnet/tools/CorpusRun/CorpusRun.csproj" -o "$S/corpusrun" > "$S/build-corpusrun.log" 2>&1 \
  || { grep -E 'error' "$S/build-corpusrun.log" | head; exit 1; }
status=0
for c in cases hostile algorithms substrate fuzz; do
  start=$(date +%s)
  dotnet "$S/corpusrun/ApplePurchaseReceiptVerifier.CorpusRun.dll" calls "$G1/calls/$c.pinned.jsonl" > "$S/run/dotnet-$c.jsonl" 2> "$S/run/dotnet-$c.err"
  same=$(python3 "$G1/same.py" "$S/run/dotnet-$c.jsonl" "$G1/rows/module-$c.jsonl") || status=1
  echo "$c: $same; $(tail -1 "$S/run/dotnet-$c.err"); $(( $(date +%s) - start )) s wall"
done
exit $status
