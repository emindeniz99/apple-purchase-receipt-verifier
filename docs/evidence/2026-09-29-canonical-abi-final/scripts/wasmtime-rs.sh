#!/bin/sh
# Spike only (2026-09-29, round 13). The Rust Wasmtime 49 host
# (hosts/wasmtime-rs), built three ways into $S/wt, as aprv-server's A/B:
#   wasmtime-rs.sh full        --features compile,component -> $S/wt/aprv-wt-full
#   wasmtime-rs.sh precompile  the full build writes $S/wt/aprv-cabi.ccwasm, $S/wt/aprv-abi1.cwasm (component_model
#                              wasm feature on, for the component-model runtime) and $S/wt/aprv-abi1.no-cm.cwasm (off:
#                              aprv-server's artifact today, for the runtime without component-model)
#   wasmtime-rs.sh runtime     runtime-only builds, the precompiled files embedded (include_bytes!):
#                              --features component,embed -> $S/wt/aprv-wt-rt-component
#                              --features embed           -> $S/wt/aprv-wt-rt-core (aprv-server B's wasmtime features)
#   wasmtime-rs.sh engines     the same two without embedded files (the engine's own size):
#                              --features component -> aprv-wt-rt-component-noembed; (none) -> aprv-wt-rt-core-noembed
#   wasmtime-rs.sh bindgen     dump the code bindgen! generates (WASMTIME_DEBUG_BINDGEN, a cargo check)
#                              to $S/wt/aprv-bindgen.rs and count it
#   wasmtime-rs.sh sizes       binary and precompiled-file sizes (stripped by the profile; gzip -9)
#   wasmtime-rs.sh startup [RUNS]   RUNS (7) fresh processes per case, interleaved, taskset -c 0
# Crates: $CARGO_HOME (default: round 10's $SCRATCH/r10/cargo-home, which holds wasmtime 49.0.1).
set -eu
. "$(dirname "$0")/env.sh"
export CARGO_HOME="${WT_CARGO_HOME:-$SCRATCH/r10/cargo-home}"
W="$S/wt"; T="$W/target"; mkdir -p "$W"
build() { # features out
  rm -rf "$W/pkg"; cp -r "$FE/hosts/wasmtime-rs" "$W/pkg"
  [ -f "$FE/hosts/wasmtime-rs/Cargo.lock" ] && lock=--locked || lock=
  start=$(date +%s)
  cargo build --release $lock --manifest-path "$W/pkg/Cargo.toml" --target-dir "$T" --features "$1" > "$S/run/wt-build-$2.log" 2>&1 \
    || { tail -30 "$S/run/wt-build-$2.log"; exit 1; }
  [ -n "$lock" ] || cp "$W/pkg/Cargo.lock" "$FE/hosts/wasmtime-rs/Cargo.lock"
  cp "$T/release/aprv-wt" "$W/$2"
  echo "$2 (--features $1): built in $(( $(date +%s) - start )) s; $(wc -c < "$W/$2") bytes"
}
case "$1" in
full) build compile,component aprv-wt-full ;;
precompile) "$W/aprv-wt-full" precompile "$COMP" "$V1" "$W" ;;
runtime)
  export APRV_CCWASM="$W/aprv-cabi.ccwasm" APRV_CWASM="$W/aprv-abi1.cwasm"
  build component,embed aprv-wt-rt-component
  export APRV_CWASM="$W/aprv-abi1.no-cm.cwasm"
  build embed aprv-wt-rt-core
  for b in aprv-wt-rt-component aprv-wt-rt-core; do echo "$b: $("$W/$b" info)"; done ;;
bindgen)
  rm -rf "$W/pkg"; cp -r "$FE/hosts/wasmtime-rs" "$W/pkg"
  WASMTIME_DEBUG_BINDGEN=1 cargo check --locked --manifest-path "$W/pkg/Cargo.toml" --target-dir "$T" --features component > "$S/run/wt-bindgen.log" 2>&1 \
    || { tail -30 "$S/run/wt-bindgen.log"; exit 1; }
  cp "$(ls -t "$T"/debug/build/wasmtime-internal-component-macro-*/out/aprv0.rs | head -1)" "$W/aprv-bindgen.rs"
  echo "bindgen! output for wit/aprv.wit (rustfmt-ed by the macro): $(wc -l < "$W/aprv-bindgen.rs") lines, $(grep -cv '^[[:space:]]*\(//.*\)\?$' "$W/aprv-bindgen.rs") non-blank non-comment, $(wc -c < "$W/aprv-bindgen.rs") bytes" ;;
engines)
  build component aprv-wt-rt-component-noembed
  build "" aprv-wt-rt-core-noembed ;;
sizes)
  printf '%-26s %10s %10s\n' file bytes gzip-9
  for f in aprv-wt-full aprv-wt-rt-component aprv-wt-rt-core aprv-wt-rt-component-noembed aprv-wt-rt-core-noembed aprv-cabi.ccwasm aprv-abi1.cwasm aprv-abi1.no-cm.cwasm; do
    printf '%-26s %10s %10s\n' $f "$(wc -c < "$W/$f")" "$(gzip -9 -c "$W/$f" | wc -c)"
  done ;;
startup)
  echo "# Rust Wasmtime 49.0.1 start-up, $(date -u +%F), taskset -c 0, fresh process per run, embedded precompiled files, load before: $(cut -d' ' -f1-3 /proc/loadavg)"
  for i in $(seq "${2:-7}"); do
    for c in "aprv-wt-rt-core v1" "aprv-wt-rt-component v1" "aprv-wt-rt-component cabi"; do
      set -- $c
      t=$(date +%s%N)
      o=$(taskset -c 0 "$W/$1" startup $2 - "$S/calls/cases.jsonl")
      echo "${o%\}},\"binary\":\"$1\",\"process_wall_ms\":$(( ($(date +%s%N) - t) / 1000000 ))}"
    done
  done ;;
esac
