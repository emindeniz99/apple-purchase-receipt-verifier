#!/bin/sh
# Spike only. The PHP façade over both transports (CLI per call, HTTP).
#   php.sh > results/php.txt
set -eu
. "$(dirname "$0")/env.sh"; . "$(dirname "$0")/lib.sh"
trap stop_server EXIT
TOKEN=$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')
APRV_TOKEN=$TOKEN start_server "$SV/bin/aprv-min" --lifecycle fresh
php "$EV/php/run.php" "$SV/bin/aprv-cli" "http://$SRV_ADDR" "$TOKEN" "$SV/in/g5.b64" "$SV/in/jws.txt" "$CALLS" "$NODEROWS" 200
