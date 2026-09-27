#!/bin/sh
# Spike only (2026-09-27, round 10). Measurements for the three x86_64
# rows, glibc (gnu), musl with musl's malloc (musl) and musl with mimalloc
# (musl-mimalloc), all variant B with the embedded baseline .cwasm:
#   measure.sh static    ldd/file/readelf of every binary          > results/static.txt
#   measure.sh startup   CLI start-up to first result and to exit, 7 runs, all CPUs and
#                        taskset -c 0, 3 interleaved rounds; also the *-fastexit rows
#                        (the CLI skips the runtime's teardown)     > results/startup.txt
#   measure.sh bench     in-process `aprv bench` on CPU 0, receipt and JWS, lifecycles
#                        fresh and pool, 5 interleaved rounds       > results/bench.txt
#   measure.sh http      server on CPU 0 (1 worker), aprv-load on CPUs 1-3, 1 connection,
#                        8 s, receipt and JWS, 3 interleaved rounds > results/http.txt
#   measure.sh rss       server start-up and RSS (the spike's startup.py, 7 runs) > results/rss.txt
#   measure.sh alloc     Rust heap allocations per call (gnu-count) and syscalls per call
#                        (strace -c, 300 calls minus 100)           > results/alloc.txt
#   measure.sh corpus    the five corpora over HTTP through musl-spike and
#                        musl-mimalloc-spike (the spike's corpus_http.py) > results/corpus.txt
set -eu
. "$(dirname "$0")/env.sh"
ROWS="gnu musl musl-mimalloc"
B="$S/bin"
hdr() { echo "# $(date -u +%F) $(uname -m), $(nproc) vCPUs; load before: $(cut -d' ' -f1-3 /proc/loadavg)"; }
case "$1" in
static)
  hdr
  for f in gnu-min musl-min musl-mimalloc-min a64-musl-min a64-musl-mimalloc-min gnu-spike musl-spike musl-mimalloc-spike a64-musl-spike a64-rt-host-wt; do
    echo "$f: file: $(file -b "$B/$f" | sed 's/, BuildID\[[^]]*\]=[0-9a-f]*//')"
    echo "    ldd: $(ldd "$B/$f" 2>&1 | sed "s#$B/##g; s#(0x[0-9a-f]*)##g" | tr -s ' \t\n' ' ')"
    echo "    readelf: INTERP $(readelf -l "$B/$f" | grep -c INTERP), NEEDED $(readelf -d "$B/$f" 2>/dev/null | grep -c NEEDED), type $(readelf -h "$B/$f" | sed -n 's/^ *Type: *//p')"
  done ;;
startup)
  hdr
  for round in 1 2 3; do
    for r in $ROWS gnu-fastexit musl-fastexit musl-mimalloc-fastexit; do
      python3 "$FE/py/cli_first.py" "$r" 7 "$S/in/g5.b64" -- "$B/$r-min" verify-receipt
      python3 "$FE/py/cli_first.py" "$r" 7 "$S/in/g5.b64" --cpus 0 -- "$B/$r-min" verify-receipt
    done
  done ;;
bench)
  hdr
  for round in 1 2 3 4 5; do
    for r in $ROWS; do
      for lc in fresh pool; do
        echo "{\"row\":\"$r\",\"round\":$round,\"bench\":$(timeout -s KILL 300 taskset -c 0 "$B/$r-spike" bench 1 "$S/in/g5.b64" $lc 1 300)}"
        echo "{\"row\":\"$r\",\"round\":$round,\"bench\":$(timeout -s KILL 300 taskset -c 0 "$B/$r-spike" bench 258 "$S/in/jws-envelope.bin" $lc 1 100)}"
      done
    done
  done ;;
http)
  hdr
  for round in 1 2 3; do
    for r in $ROWS; do
      out="$S/run/http.$$.out"; : > "$out"
      setsid taskset -c 0 "$B/$r-spike" serve --listen 127.0.0.1:0 --lifecycle fresh --workers 1 > "$out" 2> "$out.err" &
      pid=$!
      i=0; while ! grep -q '^APRV_LISTEN=' "$out"; do i=$((i + 1)); [ $i -gt 300 ] && { echo "no server"; kill -9 -$pid; exit 1; }; sleep 0.05; done
      A=$(sed -n 's/^APRV_LISTEN=//p' "$out")
      printf '%s round %s receipt ' "$r" "$round"; timeout -s KILL 60 taskset -c 1-3 "$B/aprv-load" --addr "$A" --path /v1/receipt/verify --body "$S/in/g5.b64" --conns 1 --secs 8 --pid $pid
      printf '%s round %s jws     ' "$r" "$round"; timeout -s KILL 60 taskset -c 1-3 "$B/aprv-load" --addr "$A" --path /spike/call/258 --body "$S/in/jws-envelope.bin" --conns 1 --secs 8 --pid $pid
      kill -TERM -$pid 2>/dev/null || true; sleep 0.3; kill -9 -$pid 2>/dev/null || true; wait $pid 2>/dev/null || true
      rm -f "$out" "$out.err"
    done
  done ;;
rss)
  hdr
  for r in $ROWS; do python3 "$EV/py/startup.py" "$B/$r-min" "$S/in/g5.b64" 7; done ;;
alloc)
  hdr
  echo "## Rust heap allocations per call (gnu-count: the gnu row with a counting global allocator)"
  for lc in fresh pool; do
    printf 'receipt %s: ' $lc; "$B/gnu-count" bench 1 "$S/in/g5.b64" $lc 1 300 2>&1 >/dev/null
    printf 'jws     %s: ' $lc; "$B/gnu-count" bench 258 "$S/in/jws-envelope.bin" $lc 1 100 2>&1 >/dev/null
  done
  echo "## syscalls per call, receipt, lifecycle fresh and pool (strace -f -c; the 300-call run minus the 100-call run, divided by 200)"
  for r in gnu musl musl-mimalloc; do
    for lc in fresh pool; do
      for n in 100 300; do strace -f -c -o "$S/run/strace-$n.txt" "$B/$r-spike" bench 1 "$S/in/g5.b64" $lc 1 $n > /dev/null; done
      python3 - "$S/run/strace-100.txt" "$S/run/strace-300.txt" "$r $lc" <<'PYEOF'
import sys
def calls(p):
    d = {}
    for line in open(p):
        f = line.split()
        if len(f) >= 5 and f[0][0].isdigit() and not line.startswith("100.00"):
            d[f[-1]] = int(f[3])
    return d
a, b = calls(sys.argv[1]), calls(sys.argv[2])
per = {k: (b.get(k, 0) - a.get(k, 0)) / 200 for k in set(a) | set(b)}
per = {k: v for k, v in sorted(per.items(), key=lambda kv: -kv[1]) if v >= 0.05}
print(f"{sys.argv[3]}: {sum(per.values()):.1f} syscalls/call: " + ", ".join(f"{k} {v:.1f}" for k, v in per.items()))
PYEOF
    done
  done
  rm -f "$S/run/strace-100.txt" "$S/run/strace-300.txt" ;;
corpus)
  hdr
  echo "# module sha256 $(sha256sum "$WASM" | cut -c1-64)"
  for r in musl musl-mimalloc; do
    out="$S/run/corpus.$$.out"; : > "$out"
    setsid "$B/$r-spike" serve --listen 127.0.0.1:0 --lifecycle fresh --workers 4 > "$out" 2> "$out.err" &
    pid=$!
    i=0; while ! grep -q '^APRV_LISTEN=' "$out"; do i=$((i + 1)); [ $i -gt 300 ] && { echo "no server"; kill -9 -$pid; exit 1; }; sleep 0.05; done
    echo "## $r-spike, lifecycle fresh, 4 workers"
    timeout -s KILL 1800 python3 "$EV/py/corpus_http.py" "$(sed -n 's/^APRV_LISTEN=//p' "$out")" "$CALLS" "$NODEROWS"
    kill -TERM -$pid 2>/dev/null || true; sleep 0.3; kill -9 -$pid 2>/dev/null || true; wait $pid 2>/dev/null || true
    rm -f "$out" "$out.err"
  done ;;
*) echo "usage: measure.sh static|startup|bench|http|rss|alloc|corpus"; exit 2 ;;
esac
