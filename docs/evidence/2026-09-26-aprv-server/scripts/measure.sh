#!/bin/sh
# Spike only. Variant A (full Wasmtime + .wasm) against variant B (runtime-only
# Wasmtime + precompiled .cwasm): sizes, start-up, first call, memory,
# steady-state throughput per server CPU-second; then the one-shot CLI.
#   measure.sh sizes|server|cli|baseline > results/<part>.txt
set -eu
. "$(dirname "$0")/env.sh"; . "$(dirname "$0")/lib.sh"
trap stop_server EXIT
CW="$SV/art/aprv-abi1.cwasm"
L="$CARGO_TARGET_DIR/release/aprv-load"
hdr() { echo "# $(date -u +%F) $(uname -m), $(nproc) vCPUs; load before: $(cut -d' ' -f1-3 /proc/loadavg)"; }
case "$1" in
sizes)
  hdr; echo "# file | raw | stripped | gzip -9 of stripped | xz -9 of stripped   (bytes)"
  mkdir -p "$SV/sz"
  for f in aprv-full aprv-min aprv-min-side aprv-cli; do
    strip -o "$SV/sz/$f" "$SV/bin/$f"
    echo "$f | $(stat -c %s "$SV/bin/$f") | $(stat -c %s "$SV/sz/$f") | $(gzip -9c "$SV/sz/$f" | wc -c) | $(xz -9c "$SV/sz/$f" | wc -c)"
  done
  echo "aprv-abi1.cwasm (side file, shipped as built) | $(stat -c %s "$CW") | - | $(gzip -9c "$CW" | wc -c) | $(xz -9c "$CW" | wc -c)"
  echo "aprv-abi1.wasm (canonical) | $(stat -c %s "$WASM") | - | $(gzip -9c "$WASM" | wc -c) | $(xz -9c "$WASM" | wc -c)"
  echo "# ldd aprv-min:"; ldd "$SV/bin/aprv-min" | awk '{print $1}'
  echo "# sha256: wasm $(sha256sum "$WASM" | cut -c1-64), cwasm $(sha256sum "$CW" | cut -c1-64)"
  echo "# cwasm: $(file -b "$CW")"
  rm -rf "$SV/sz" ;;
server)
  hdr
  python3 "$EV/py/startup.py" "$SV/bin/aprv-full" "$SV/in/g5.b64" 5
  python3 "$EV/py/startup.py" "$SV/bin/aprv-min" "$SV/in/g5.b64" 5
  python3 "$EV/py/startup.py" "$SV/bin/aprv-min-side" "$SV/in/g5.b64" 5 APRV_MODULE_FILE="$CW"
  for pair in "A:aprv-spike" "B:aprv-min-spike"; do
    v=${pair%%:*}; bin=${pair#*:}
    start_server "$SV/bin/$bin" --lifecycle fresh --workers 4
    echo "## variant $v ($bin, lifecycle fresh): $(cat "$SV/run/srv.$$.err")"
    for c in 1 4; do
      printf 'receipt %s ' "$v"; "$L" --addr "$SRV_ADDR" --path /v1/receipt/verify --body "$SV/in/g5.b64" --conns $c --secs 8 --pid $SRV_PID
      printf 'jws     %s ' "$v"; "$L" --addr "$SRV_ADDR" --path /spike/call/258 --body "$SV/in/jws-envelope.bin" --conns $c --secs 8 --pid $SRV_PID
    done
    stop_server
  done ;;
cli)
  hdr
  python3 "$EV/py/cli_bench.py" "B aprv-cli (embedded .cwasm), receipt" 30 200 "$SV/in/g5.b64" "$SV/bin/aprv-cli" verify-receipt
  python3 "$EV/py/cli_bench.py" "B aprv-min (server binary, embedded .cwasm), receipt" 30 200 "$SV/in/g5.b64" "$SV/bin/aprv-min" verify-receipt
  python3 "$EV/py/cli_bench.py" "B aprv-min-side (.cwasm side file, pinned hash), receipt" 30 200 "$SV/in/g5.b64" "$SV/bin/aprv-min-side" verify-receipt -- APRV_MODULE_FILE="$CW"
  python3 "$EV/py/cli_bench.py" "A aprv-full-pin + .cwasm side file, receipt" 30 200 "$SV/in/g5.b64" "$SV/bin/aprv-full-pin" verify-receipt -- APRV_MODULE_FILE="$CW"
  python3 "$EV/py/cli_bench.py" "A aprv-full (compiles the .wasm at every start), receipt" 5 12 "$SV/in/g5.b64" "$SV/bin/aprv-full" verify-receipt
  python3 "$EV/py/cli_bench.py" "B aprv-cli, endpoint sandbox" 30 200 "$SV/in/endpoint-sandbox.json" "$SV/bin/aprv-cli" verify-receipt-endpoint sandbox ;;
baseline)
  # The default precompile uses this machine's CPU features (Config::new()
  # detects them). An explicit target gives the ISA baseline instead, so the
  # artifact does not depend on the build machine's CPU.
  hdr
  BC="$SV/art/aprv-abi1.x86_64-baseline.cwasm"
  APRV_TARGET=x86_64-unknown-linux-gnu "$SV/bin/aprv-full" precompile "$BC" | sed 's|^wrote .*/|wrote |'
  echo "host-feature precompile: $(stat -c %s "$CW") bytes, sha256 $(sha256sum "$CW" | cut -c1-64)"
  APRV_CWASM="$BC" APRV_CWASM_SHA256="$(sha256sum "$BC" | cut -c1-64)" \
    cargo build -q --release --locked --manifest-path "$EV/server/Cargo.toml" --no-default-features --features server,embed,spike
  cp "$CARGO_TARGET_DIR/release/aprv" "$SV/bin/aprv-min-baseline"
  "$SV/bin/aprv-min-baseline" info | tail -1
  start_server "$SV/bin/aprv-min-baseline" --lifecycle fresh --workers 4
  printf 'receipt B-baseline '; "$L" --addr "$SRV_ADDR" --path /v1/receipt/verify --body "$SV/in/g5.b64" --conns 1 --secs 8 --pid $SRV_PID
  printf 'jws     B-baseline '; "$L" --addr "$SRV_ADDR" --path /spike/call/258 --body "$SV/in/jws-envelope.bin" --conns 1 --secs 8 --pid $SRV_PID
  stop_server ;;
esac
