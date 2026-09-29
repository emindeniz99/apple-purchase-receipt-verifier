#!/bin/sh
# Spike only. The five corpora (1,179 rows + 5,000 mutants) through the HTTP
# server, compared byte for byte with the Node rows of the same module.
#   corpus.sh BIN [lifecycles] > results/corpus-http.txt
set -eu
. "$(dirname "$0")/env.sh"; . "$(dirname "$0")/lib.sh"
BIN=$1; LCS=${2:-"fresh pool"}
echo "# $(date -u +%F); module sha256 $(sha256sum "$WASM" | cut -c1-64); Node rows from $(head -1 "$NODEROWS/node-cases.err" | cut -c1-40)"
trap stop_server EXIT
for lc in $LCS; do
  start_server "$BIN" --lifecycle "$lc" --workers 4
  echo "## lifecycle $lc"
  python3 "$EV/py/corpus_http.py" "$SRV_ADDR" "$CALLS" "$NODEROWS"
  stop_server
done
