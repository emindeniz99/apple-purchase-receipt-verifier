#!/bin/sh
# Spike only (2026-09-29, round 13). The WasmKit host (hosts/wasmkit), a
# SwiftPM package on WasmKit 0.4.0, built with the Swift 6.3.x toolchain
# in $SWIFT_TC (round 7's download.swift.org toolchain, extracted).
#   wasmkit.sh build                 swift build -c release in $S/wasmkit
#   wasmkit.sh cmd                   print the command line for corpus.sh
#   wasmkit.sh tests                 the ABI tests
#   wasmkit.sh startup [RUNS]        RUNS (7) fresh processes per module, interleaved, taskset -c 0
set -eu
. "$(dirname "$0")/env.sh"
: "${SWIFT_TC:?}"
export PATH="$SWIFT_TC/usr/bin:$PATH"
PKG="$S/wasmkit/AprvCabi"
TOOL="$PKG/.build/release/aprv-cabi"
case "$1" in
build)
  mkdir -p "$PKG"; rm -rf "$PKG/Sources" "$PKG/Package.swift"   # keeps .build between runs
  cp -r "$FE/hosts/wasmkit/Package.swift" "$FE/hosts/wasmkit/Sources" "$PKG/"
  start=$(date +%s)
  swift build -c release --package-path "$PKG" > "$S/run/wasmkit-build.log" 2>&1 || { tail -40 "$S/run/wasmkit-build.log"; exit 1; }
  echo "wasmkit host: release build $(( $(date +%s) - start )) s wall; $(swift --version 2>&1 | head -1); WasmKit $(python3 -c "import json;d=json.load(open('$PKG/Package.resolved'));print([p['state'].get('version') for p in d['pins'] if p['identity']=='wasmkit'][0])")"
  ;;
cmd) echo "$TOOL calls $MOD" ;;
tests) "$TOOL" tests "$MOD" "$S/calls/cases.jsonl" ;;
startup)
  echo "# WasmKit start-up, $(date -u +%F), taskset -c 0, fresh process per run, load before: $(cut -d' ' -f1-3 /proc/loadavg)"
  for i in $(seq "${2:-7}"); do
    for m in v1 cabi; do
      [ $m = v1 ] && p="$V1" || p="$MOD"
      t=$(date +%s%N)
      o=$(taskset -c 0 "$TOOL" startup $m "$p" "$S/calls/cases.jsonl")
      echo "${o%\}},\"process_wall_ms\":$(( ($(date +%s%N) - t) / 1000000 ))}"
    done
  done ;;
esac
