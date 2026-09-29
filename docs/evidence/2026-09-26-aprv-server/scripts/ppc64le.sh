#!/bin/sh
# Spike only. Pulley on a host Cranelift does not support: variant B for
# powerpc64le-unknown-linux-gnu (runtime-only Wasmtime, which falls back to
# Pulley there), embedding a pulley64 .cwasm precompiled on x86_64, run under
# qemu-ppc64le user-mode emulation. Needs the rust-std target, the Ubuntu
# powerpc64le cross gcc, and qemu-user.
#   ppc64le.sh > results/pulley.txt   (after build.sh)
set -eu
. "$(dirname "$0")/env.sh"; . "$(dirname "$0")/lib.sh"
trap stop_server EXIT
T=powerpc64le-unknown-linux-gnu
PC="$SV/art/aprv-abi1.pulley64.cwasm"
APRV_TARGET=pulley64 "$SV/bin/aprv-spike" precompile "$PC"
echo "# Pulley on x86_64 (aprv-spike built with the pulley feature, APRV_TARGET=pulley64), in-process, 1 thread"
for lc in pool fresh; do
  APRV_TARGET=pulley64 "$SV/bin/aprv-spike" bench 1 "$SV/in/g5.b64" $lc 1 40
  APRV_TARGET=pulley64 "$SV/bin/aprv-spike" bench 258 "$SV/in/jws-envelope.bin" $lc 1 20
done
export APRV_CWASM="$PC" APRV_CWASM_SHA256="$(sha256sum "$PC" | cut -c1-64)"
export CARGO_TARGET_POWERPC64LE_UNKNOWN_LINUX_GNU_LINKER=powerpc64le-linux-gnu-gcc CC_powerpc64le_unknown_linux_gnu=powerpc64le-linux-gnu-gcc
cargo build -q --release --locked --target $T --manifest-path "$EV/server/Cargo.toml" --no-default-features --features server,embed,spike
cp "$CARGO_TARGET_DIR/$T/release/aprv" "$SV/bin/aprv-min-ppc64le"
echo "# $(file -b "$SV/bin/aprv-min-ppc64le" | cut -d, -f1-2); $(stat -c %s "$SV/bin/aprv-min-ppc64le") bytes; $(qemu-ppc64le --version | head -1)"
Q="$SV/bin/aprv-ppc64le-qemu"
printf '#!/bin/sh\nexec qemu-ppc64le -L /usr/powerpc64le-linux-gnu "%s" "$@"\n' "$SV/bin/aprv-min-ppc64le" > "$Q"; chmod +x "$Q"
"$Q" info
start_server "$Q" --lifecycle fresh --workers 1
echo "## $(cat "$SV/run/srv.$$.err")"
curl -s "http://$SRV_ADDR/healthz"; echo
"$CARGO_TARGET_DIR/release/aprv-load" --addr "$SRV_ADDR" --path /v1/receipt/verify --body "$SV/in/g5.b64" --conns 1 --secs 10 --warm 2
"$CARGO_TARGET_DIR/release/aprv-load" --addr "$SRV_ADDR" --path /spike/call/258 --body "$SV/in/jws-envelope.bin" --conns 1 --secs 10 --warm 1
stop_server
