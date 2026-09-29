#!/bin/sh
# The five corpora (6,179 rows) through the host layer, each row compared with
# ABI v1's Node rows by round 13's classify.py (expectation: 6,176 identical,
# 2 clock-moves-chain, 1 init-refusal).
#   REPO=... SCRATCH=... CORPORA=... sh corpus.sh
# Needs round 13's inputs under $SCRATCH: wasm/abi/calls (ABI v1's calls files)
# and wasm/abi/run (the Node rows).
set -eu
. "$(dirname "$0")/env.sh"
FE="$REPO/docs/evidence/2026-09-29-canonical-abi-final"
mkdir -p "$S/calls" "$S/run"
dotnet build -c Release "$REPO/dotnet/tools/CorpusRun/CorpusRun.csproj" -o "$S/corpusrun" > "$S/build-corpusrun.log" 2>&1 \
  || { grep -E 'error' "$S/build-corpusrun.log" | head; exit 1; }
for c in cases hostile algorithms substrate fuzz; do
  [ -s "$S/calls/$c.jsonl" ] || python3 "$FE/py/calls_bytes.py" "$SCRATCH/wasm/abi/calls/$c.jsonl" > "$S/calls/$c.jsonl" 2>/dev/null
  start=$(date +%s)
  dotnet "$S/corpusrun/ApplePurchaseReceiptVerifier.CorpusRun.dll" calls "$S/calls/$c.jsonl" > "$S/run/dotnet-$c.jsonl" 2> "$S/run/dotnet-$c.err"
  echo "$c: $(tail -1 "$S/run/dotnet-$c.err") $(( $(date +%s) - start )) s wall"
done
python3 "$FE/py/classify.py" dotnet "$S/calls" "$SCRATCH/wasm/abi/run" "$S/run/dotnet"
