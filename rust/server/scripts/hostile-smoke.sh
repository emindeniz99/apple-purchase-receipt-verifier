#!/bin/sh
# A real `aprv serve` process running the hostile component of
# tests/hostile.wat, to check the limits hold outside the in-process tests:
# the infinite loop ends at the time limit, the 1 GiB grow is refused, the
# non-UTF-8 result is an ABI error, the 1 GiB random-get is refused, and the
# process is still there and answering afterwards.
#
#   hostile-smoke.sh FULL_BUILD_aprv
#
# FULL_BUILD_aprv is a `--features compile` build (it compiles the hostile
# component at start). Needs wasm-tools and curl.
set -eu
aprv=${1:?usage: hostile-smoke.sh FULL_BUILD_aprv}
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'kill "$pid" 2>/dev/null || true; rm -rf "$tmp"' EXIT
wasm-tools parse "$here/tests/hostile.wat" -o "$tmp/hostile.wasm"
port=18090
"$aprv" serve --component "$tmp/hostile.wasm" --listen 127.0.0.1:$port --time-limit-ms 300 >/dev/null 2>"$tmp/err" &
pid=$!
i=0
until curl -fs -m 1 "http://127.0.0.1:$port/healthz" >/dev/null; do
  i=$((i + 1)); [ $i -lt 50 ] || { cat "$tmp/err"; echo "FAIL the server did not start" >&2; exit 1; }; sleep 0.1
done
fail=0
check() { # route expected-code
  out=$(curl -s -m 10 -X POST --data x -w ' %{http_code} %{time_total}' "http://127.0.0.1:$port/v1/$1")
  code=$(echo "$out" | awk '{print $(NF-1)}')
  if echo "$out" | grep -q "\"code\":\"$2\"" && [ "$code" = 500 ]; then echo "PASS $1: 500 $2 ($(echo "$out" | awk '{print $NF}') s)"
  else echo "FAIL $1: $out"; fail=1; fi
}
check receipt/verify WASM_TRAP                 # the loop, ended by the time limit
check signed-data/verify WASM_TRAP             # the 1 GiB grow
check verify-receipt/production ABI_ERROR      # a result that is not UTF-8
check verify-receipt/sandbox WASM_TRAP         # a 1 GiB random-get
check receipt/verify WASM_TRAP                 # and again: nothing carried over
# In the pool (the default lifecycle) a trapped instance must be dropped:
# reused, Wasmtime would refuse to enter it at once (ABI_ERROR), so this
# second loop must again run into the time limit.
t=$(curl -s -o /dev/null -m 10 -X POST --data x -w '%{time_total}' "http://127.0.0.1:$port/v1/receipt/verify")
if awk "BEGIN{exit !($t >= 0.25)}"; then echo "PASS a trapped instance is not reused (the loop ran again: $t s)"
else echo "FAIL receipt/verify answered in $t s: a trapped instance may have been reused"; fail=1; fi
if kill -0 "$pid" && [ "$(curl -s "http://127.0.0.1:$port/healthz")" = ok ]; then
  echo "PASS the process survived; RSS $(ps -o rss= -p "$pid" | tr -d ' ') KiB"
else echo "FAIL the process is gone"; fail=1; fi
exit $fail
