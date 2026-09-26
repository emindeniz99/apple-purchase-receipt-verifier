# Spike only. Shared helpers: start a server in the background, read its
# address, stop it. Source after env.sh.
# start_server BIN ARGS... -> sets SRV_PID and SRV_ADDR
start_server() {
  _bin=$1; shift
  out="$SV/run/srv.$$.out"; : > "$out"
  "$_bin" serve --listen 127.0.0.1:0 "$@" > "$out" 2> "$SV/run/srv.$$.err" &
  SRV_PID=$!
  i=0
  while ! grep -q '^APRV_LISTEN=' "$out"; do
    i=$((i+1)); [ $i -gt 600 ] && { echo "server did not start" >&2; cat "$SV/run/srv.$$.err" >&2; kill $SRV_PID; return 1; }
    sleep 0.05
  done
  SRV_ADDR=$(sed -n 's/^APRV_LISTEN=//p' "$out")
}
SRV_PID=""
stop_server() { [ -n "$SRV_PID" ] || return 0; kill "$SRV_PID" 2>/dev/null; wait "$SRV_PID" 2>/dev/null; rm -f "$SV/run/srv.$$.out"; SRV_PID=""; }
