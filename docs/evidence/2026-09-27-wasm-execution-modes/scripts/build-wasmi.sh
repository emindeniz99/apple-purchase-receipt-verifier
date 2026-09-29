#!/bin/sh
# Spike only (2026-09-27, round 9). Builds ../wasmi-host once per engine
# configuration into $S/bin/aprv-<row>, and prints the exact Cargo features,
# the toolchain, the build time and the binary size (as built, and stripped).
#   build-wasmi.sh [ROW...]     default: every row below
# Rows (Cargo features of ../wasmi-host/Cargo.toml):
#   wasmi1            v1                 Wasmi 1.1.0 (std)
#   wasmi2-auto       v2-auto            Wasmi 2.0.0 std,validate,memory64,stable,auto-dispatch (the default dispatch)
#   wasmi2-tail       v2-tail            ... stable, no auto-dispatch: tail-call dispatch forced
#   wasmi2-tail-ind   v2-tail-indirect   ... stable, indirect-dispatch
#   wasmi2-loop       v2-loop            ... stable, portable-dispatch
#   wasmi2-loop-ind   v2-loop-indirect   ... stable, portable-dispatch, indirect-dispatch
#   wasmi2-unstable   v2-unstable        ... unstable (nightly Rust: `become`)
#   wasmtime          wt                 Wasmtime 49.0.1 runtime,std,cranelift,winch,pulley,parallel-compilation
set -eu
. "$(dirname "$0")/env.sh"
feat() {
  case "$1" in
    wasmi1) echo v1 ;; wasmi2-auto) echo v2-auto ;; wasmi2-tail) echo v2-tail ;;
    wasmi2-tail-ind) echo v2-tail-indirect ;; wasmi2-loop) echo v2-loop ;;
    wasmi2-loop-ind) echo v2-loop-indirect ;; wasmi2-unstable) echo v2-unstable ;;
    wasmtime) echo wt ;; *) echo "unknown row $1" >&2; exit 2 ;;
  esac
}
ROWS=${*:-"wasmi1 wasmi2-auto wasmi2-tail wasmi2-tail-ind wasmi2-loop wasmi2-loop-ind wasmi2-unstable"}
for row in $ROWS; do
  f=$(feat "$row")
  tc=1.98.1; [ "$row" = wasmi2-unstable ] && tc=nightly
  TB="$RUSTUP_HOME/toolchains/$tc-x86_64-unknown-linux-gnu/bin"
  start=$(date +%s)
  PATH="$TB:$PATH" "$TB/cargo" build -q --locked --release --manifest-path "$EM/wasmi-host/Cargo.toml" --features "$f" > "$S/build-$row.log" 2>&1 \
    || { tail -30 "$S/build-$row.log"; echo "$row: BUILD FAILED"; continue; }
  secs=$(( $(date +%s) - start ))
  cp "$CARGO_TARGET_DIR/release/aprv-rt-host" "$S/bin/.aprv-$row.new"; mv "$S/bin/.aprv-$row.new" "$S/bin/aprv-$row"  # rename: safe while an old copy runs
  cp "$S/bin/aprv-$row" "$S/bin/.aprv-$row.stripped"; strip "$S/bin/.aprv-$row.stripped"; mv "$S/bin/.aprv-$row.stripped" "$S/bin/aprv-$row.stripped"
  echo "$row: features=$f toolchain=$("$TB/rustc" --version | tr " " _) build ${secs} s; binary $(wc -c < "$S/bin/aprv-$row") bytes, stripped $(wc -c < "$S/bin/aprv-$row.stripped") bytes"
done
