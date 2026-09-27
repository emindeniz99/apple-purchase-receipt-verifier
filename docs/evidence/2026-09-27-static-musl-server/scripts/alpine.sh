#!/bin/sh
# Spike only (2026-09-27, round 10). The static musl server in an Alpine
# minirootfs, and round 11's open item: does the Wasmi cdylib built for
# x86_64-unknown-linux-musl (-crt-static off, NEEDED libc.so) load in a musl
# CPython?
#   alpine.sh > results/alpine.txt
# 1. Download the current alpine-minirootfs for x86_64 from the official CDN,
#    check it against the sha256 in latest-releases.yaml (fetched over HTTPS
#    from the same CDN), unpack into $S/alpine.
# 2. smoke: the static musl server's CLI + HTTP routes inside that rootfs
#    (smoke.sh's checks, run through chroot).
# 3. apk add python3 inside the rootfs (network through this machine's
#    HTTPS proxy; its CA bundle copied into the rootfs only), build round
#    11's cdylib for x86_64-unknown-linux-musl, and run round 11's ctypes
#    facade (py/aprv_wasmi_rs) on Alpine's python3: one g5 verification.
set -eu
. "$(dirname "$0")/env.sh"
R11="$REPO/docs/evidence/2026-09-27-python-runtime-final"
CDN=https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/x86_64
A="$S/alpine"
curl -fsS "$CDN/latest-releases.yaml" > "$S/run/alpine.yaml"
file=$(python3 -c "import sys,re; t=open(sys.argv[1]).read(); b=t[t.index('flavor: alpine-minirootfs'):]; print(re.search(r'file: (\S+)', b).group(1))" "$S/run/alpine.yaml")
want=$(python3 -c "import sys,re; t=open(sys.argv[1]).read(); b=t[t.index('flavor: alpine-minirootfs'):]; print(re.search(r'sha256: (\S+)', b).group(1))" "$S/run/alpine.yaml")
[ -f "$S/run/$file" ] || curl -fsS -o "$S/run/$file" "$CDN/$file"
got=$(sha256sum "$S/run/$file" | cut -c1-64)
echo "# alpine.sh, $(date -u +%F): $file, sha256 $got (latest-releases.yaml says $want)"
[ "$got" = "$want" ] || { echo "sha256 MISMATCH, stopping"; exit 1; }
rm -rf "$A"; mkdir -p "$A"; tar -xzf "$S/run/$file" -C "$A"
echo "rootfs: $(cat "$A/etc/alpine-release"), musl loader: $(cd "$A" && ls lib/ld-musl-*)"
echo "## 2. static server in the Alpine rootfs"
cp "$S/bin/musl-spike" "$A/aprv"
printf 'cli verify-receipt: '; chroot "$A" /aprv verify-receipt < "$S/in/g5.b64" | cut -c1-90
out="$S/run/alpine.out"; : > "$out"
setsid chroot "$A" /aprv serve --listen 127.0.0.1:0 --lifecycle fresh --workers 2 > "$out" 2> "$out.err" &
pid=$!
i=0; while ! grep -q '^APRV_LISTEN=' "$out"; do i=$((i + 1)); [ $i -gt 300 ] && { echo "no server"; kill -9 -$pid; exit 1; }; sleep 0.05; done
AD=$(sed -n 's/^APRV_LISTEN=//p' "$out")
for p in /healthz /readyz; do printf 'http GET %s -> ' $p; curl -sS -m 30 "http://$AD$p"; echo; done
printf 'http POST /v1/receipt/verify -> '; curl -sS -m 30 --data-binary @"$S/in/g5.b64" "http://$AD/v1/receipt/verify" | cut -c1-90
printf 'http POST /spike/call/258 -> '; curl -sS -m 30 --data-binary @"$S/in/jws-envelope.bin" "http://$AD/spike/call/258" | cut -c1-90
printf 'http POST /v1/verify-receipt/sandbox -> '; curl -sS -m 30 --data-binary @"$S/in/endpoint-sandbox.json" "http://$AD/v1/verify-receipt/sandbox" | cut -c1-90
kill -TERM -$pid 2>/dev/null || true; sleep 0.3; kill -9 -$pid 2>/dev/null || true; wait $pid 2>/dev/null || true
echo "## 3. round 11's cdylib on Alpine's python3"
cp /etc/resolv.conf "$A/etc/resolv.conf"
mkdir -p "$A/etc/ssl/certs"; cp "${SSL_CERT_FILE:-/etc/ssl/certs/ca-certificates.crt}" "$A/etc/ssl/certs/ca-certificates.crt"
rm -f "$A/etc/ssl/cert.pem"; cp "$A/etc/ssl/certs/ca-certificates.crt" "$A/etc/ssl/cert.pem"
chroot "$A" /usr/bin/env SSL_CERT_FILE=/etc/ssl/cert.pem HTTPS_PROXY="${HTTPS_PROXY:-}" https_proxy="${HTTPS_PROXY:-}" /sbin/apk add -q --no-progress python3 > "$S/run/apk.log" 2>&1 \
  || { echo "apk add python3 failed (the log stays in scratch: it can name the proxy)"; exit 0; }
echo "alpine python: $(chroot "$A" /usr/bin/python3 --version)"
T=x86_64-unknown-linux-musl
# As round 11's cross.sh: cargo zigbuild (zig supplies musl's dynamic libc to
# link against; with the host cc, -crt-static off would link glibc instead).
RUSTFLAGS="-C target-feature=-crt-static" PATH="$ZIGVENV/bin:$PATH" cargo zigbuild -q --release --locked --target $T --manifest-path "$R11/wasmi-cdylib/Cargo.toml" > "$S/run/cdylib.log" 2>&1 \
  || { tail -20 "$S/run/cdylib.log"; exit 1; }
mkdir -p "$A/aprvpy"; cp "$CARGO_TARGET_DIR/$T/release/libaprv_wasmi.so" "$A/aprvpy/"; cp -r "$R11/py/aprv_wasmi_rs" "$A/aprvpy/"
cp "$WASM" "$A/aprvpy/aprv.wasm"; cp "$S/in/g5.b64" "$A/aprvpy/g5.b64"
echo "cdylib: $(file -b "$A/aprvpy/libaprv_wasmi.so" | cut -d, -f1-2), NEEDED: $(readelf -d "$A/aprvpy/libaprv_wasmi.so" | grep NEEDED | grep -o '\[.*\]' | tr '\n' ' ')"
chroot "$A" /usr/bin/env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/aprvpy APRV_LIBAPRVWASMI=/aprvpy/libaprv_wasmi.so APRV_MODULE=/aprvpy/aprv.wasm \
  APRV_WASMI_FUEL=5000000000 APRV_WASMI_MAXMEM=67108864 /usr/bin/python3 -c '
import json, sys, time, aprv_wasmi_rs as m
t = time.perf_counter(); v = m.Verifier(); r = v.verify_receipt(open("/aprvpy/g5.b64").read())
ms = (time.perf_counter() - t) * 1000
print("ctypes load + instantiate + g5 on Alpine python3:", "verified" if r["verified"] else r, "(%.0f ms, bundleId %s)" % (ms, r["payload"]["bundleId"]))
' 2>&1 | head -3
