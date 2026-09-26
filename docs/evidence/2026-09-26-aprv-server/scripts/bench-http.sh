#!/bin/sh
# Spike only. Lifecycle A (pool) vs B (fresh) over HTTP: g5 receipt through
# the public route, shared-sandbox JWS through the spike route (op 258: the
# corpus's test anchors, which the public op 2 cannot take), 1/2/4 clients,
# 8 s each. Server and load generator share the machine's 4 vCPUs; "per
# server CPU-second" divides requests by the server's own CPU time.
#   bench-http.sh BIN [lifecycles] > results/bench-http.txt
set -eu
. "$(dirname "$0")/env.sh"; . "$(dirname "$0")/lib.sh"
BIN=$1; LCS=${2:-"pool fresh"}
L="$CARGO_TARGET_DIR/release/aprv-load"
echo "# $(date -u +%F) $(uname -m), $(nproc) vCPUs ($(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')); load before: $(cut -d' ' -f1-3 /proc/loadavg)"
trap stop_server EXIT
for lc in $LCS; do
  start_server "$BIN" --lifecycle "$lc" --workers 4
  echo "## lifecycle $lc: $(cat "$SV/run/srv.$$.err")"
  echo "   idle RSS kB: $(grep VmRSS /proc/$SRV_PID/status | awk '{print $2}')"
  for c in 1 2 4; do
    printf 'receipt %s ' "$lc"; "$L" --addr "$SRV_ADDR" --path /v1/receipt/verify --body "$SV/in/g5.b64" --conns $c --secs 8 --pid $SRV_PID
    printf 'jws     %s ' "$lc"; "$L" --addr "$SRV_ADDR" --path /spike/call/258 --body "$SV/in/jws-envelope.bin" --conns $c --secs 8 --pid $SRV_PID
  done
  stop_server
done
