#!/bin/sh
# Spike only (2026-09-27, round 10). Static-ness and a functional smoke of
# one aprv binary (a `-spike` build: it has the /spike/call route the
# test-anchor JWS needs), in one of three places:
#   smoke.sh host   BIN   run it directly on this glibc host
#   smoke.sh chroot BIN   copy it alone into an empty directory and chroot
#                         there: no libc, no loader, no /proc, /dev or /etc
#   smoke.sh qemu   BIN   an aarch64 binary under qemu-aarch64 user mode
#                         (correctness only, not performance)
# CLI: info, verify-receipt, verify-signed-data, verify-receipt-endpoint.
# Server: serve on 127.0.0.1:0, then GET /healthz, /readyz and POST the
# receipt, the public JWS route, the test-anchor JWS (/spike/call/258) and
# the sandbox endpoint, with curl from the host.
set -u
. "$(dirname "$0")/env.sh"
where=$1; BIN=$2
R="$S/root-empty"
case "$where" in
  host) P="$BIN" ;;
  chroot)
    rm -rf "$R"; mkdir -p "$R"; cp "$BIN" "$R/aprv"
    echo "chroot contents: $(cd "$R" && find . | sort | tr '\n' ' ')"
    P="chroot $R /aprv" ;;
  qemu) P="qemu-aarch64 $BIN" ;;
  *) echo "usage: smoke.sh host|chroot|qemu BIN"; exit 2 ;;
esac
T=60; [ "$where" = qemu ] && T=600
echo "## $where: $(basename "$BIN") ($(file -b "$BIN" | cut -d, -f1-2))"
show() { python3 -c 'import sys; d=sys.stdin.buffer.read(); print(d[:110].decode("utf-8","replace").replace("\n"," "))'; }
echo "info: $(timeout -s KILL $T $P info 2>&1 | grep -E '^(module|arch)' | tr '\n' ' ')"
printf 'cli verify-receipt: ';            timeout -s KILL $T $P verify-receipt < "$S/in/g5.b64" 2>&1 | show
printf 'cli verify-signed-data: ';        timeout -s KILL $T $P verify-signed-data < "$S/in/jws.txt" 2>&1 | show
printf 'cli verify-receipt-endpoint sandbox: '; timeout -s KILL $T $P verify-receipt-endpoint sandbox < "$S/in/endpoint-sandbox.json" 2>&1 | show
out="$S/run/smoke.$$.out"; : > "$out"
setsid $P serve --listen 127.0.0.1:0 --lifecycle fresh --workers 2 > "$out" 2> "$out.err" &
pid=$!
i=0
while ! grep -q '^APRV_LISTEN=' "$out"; do
  i=$((i + 1))
  if [ $i -gt $((T * 10)) ] || ! kill -0 $pid 2>/dev/null; then
    echo "server did not start: $(tr '\n' ' ' < "$out.err" | cut -c1-300)"; kill -9 -$pid 2>/dev/null; exit 1
  fi
  sleep 0.1
done
A=$(sed -n 's/^APRV_LISTEN=//p' "$out")
echo "server: $(head -1 "$out.err" | sed 's/listening on [0-9.:]*/listening on 127.0.0.1:<port>/')"
c() { # method path [body]
  if [ $# -eq 3 ]; then r=$(curl -sS -m $T -o "$out.body" -w '%{http_code}' --data-binary @"$3" "http://$A$2"); else r=$(curl -sS -m $T -o "$out.body" -w '%{http_code}' "http://$A$2"); fi
  printf 'http %s %s -> %s ' "$1" "$2" "$r"; show < "$out.body"
}
c GET /healthz
c GET /readyz
c POST /v1/receipt/verify "$S/in/g5.b64"
c POST /v1/signed-data/verify "$S/in/jws.txt"
c POST /spike/call/258 "$S/in/jws-envelope.bin"
c POST /v1/verify-receipt/sandbox "$S/in/endpoint-sandbox.json"
kill -TERM -$pid 2>/dev/null; sleep 0.5; kill -9 -$pid 2>/dev/null; wait $pid 2>/dev/null
rm -f "$out" "$out.err" "$out.body"
[ "$where" = chroot ] && rm -rf "$R"
exit 0
