#!/bin/sh
# workerd through `wrangler dev` (local only: Miniflare + workerd on
# 127.0.0.1, nothing deployed, no account). The worker imports the
# INSTALLED package; wrangler's bundler resolves its "workerd" condition
# and the static .wasm imports. Consumer layout: see README.md.
#   npm/worker-smoke.sh <consumer-dir> <core|emscripten|component> <port>
set -eu
cd "$1"
WRANGLER_SEND_METRICS=false "$WRANGLER" dev "src/$2.js" --ip 127.0.0.1 --port "$3" --local > "wrangler-$2.log" 2>&1 &
P=$!
trap 'kill $P 2>/dev/null || true; pkill -P $P 2>/dev/null || true' EXIT
i=0; until curl -s -o /dev/null "http://127.0.0.1:$3/" || [ $i -gt 150 ]; do i=$((i+1)); sleep 0.4; done
echo "{\"host\":\"wrangler dev (local)\",$(curl -s "http://127.0.0.1:$3/" | cut -c2-)"
