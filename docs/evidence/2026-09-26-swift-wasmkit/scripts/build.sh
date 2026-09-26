#!/bin/sh
# Spike only (2026-09-26). Builds the AprvWasm package (release) with the
# ABI v1 module as its resource, then a clean consumer package that
# depends on it by path and resolves WasmKit from GitHub by itself.
#   build.sh package    -> $S/pkg/.build/release/aprv-tool
#   build.sh consumer   -> $S/consumer (fresh .build and Package.resolved)
set -eu
. "$(dirname "$0")/env.sh"
case "$1" in
package)
  mkdir -p "$PKG"; rm -rf "$PKG/Sources" "$PKG/Package.swift"   # keeps .build between runs
  cp -r "$SW/AprvWasm/Package.swift" "$SW/AprvWasm/Sources" "$PKG/"
  mkdir -p "$PKG/Sources/AprvWasm/Resources"; cp "$MOD" "$PKG/Sources/AprvWasm/Resources/aprv.wasm"
  start=$(date +%s)
  swift build -c release --package-path "$PKG" > "$S/build-package.log" 2>&1 || { tail -40 "$S/build-package.log"; exit 1; }
  echo "package: release build $(( $(date +%s) - start )) s wall (includes resolving WasmKit)"
  echo "resolved: $(python3 -c "import json;d=json.load(open('$PKG/Package.resolved'));print(', '.join(p['identity']+' '+(p['state'].get('version') or p['state'].get('revision','')[:12]) for p in d['pins']))")"
  echo "aprv-tool: $(wc -c < "$TOOL") bytes"
  ;;
consumer)
  rm -rf "$S/consumer"; cp -r "$SW/consumer" "$S/consumer"
  sed -i "s#@PKG@#$PKG#" "$S/consumer/Package.swift"
  start=$(date +%s)
  swift build -c release --package-path "$S/consumer" > "$S/build-consumer.log" 2>&1 || { tail -40 "$S/build-consumer.log"; exit 1; }
  echo "consumer: release build $(( $(date +%s) - start )) s wall, fresh .build"
  G5=$(python3 -c "import json,base64; [print(base64.b64decode(c['input']).decode()) for c in map(json.loads, open('$CALLS/cases.jsonl')) if c['id']=='receipt/verify-genuine-sandbox-g5-against-apple-roots']")
  echo "consumer run: $(cd "$S" && "$S/consumer/.build/release/Consumer" "$G5")"
  ;;
*) echo "usage: build.sh package|consumer"; exit 2 ;;
esac
