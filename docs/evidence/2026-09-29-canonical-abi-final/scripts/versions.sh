#!/bin/sh
# Spike only (2026-09-29, round 13). The tool versions behind results/.
#   versions.sh > results/versions.txt     (DENO, BUN, SWIFT_TC as for jco.sh and wasmkit.sh)
set -u
. "$(dirname "$0")/env.sh"
unset JAVA_TOOL_OPTIONS
echo "# $(date -u +%F), $(uname -m)"
echo "guest:          rustc $(rustc --version | cut -d' ' -f2-); wit-bindgen crate $(awk '/^name = "wit-bindgen"$/{getline; print $3}' "$FE/guest/Cargo.lock" | tr -d '"'), CLI $(wit-bindgen --version | cut -d' ' -f2); wasm-tools $(wasm-tools --version | cut -d' ' -f2); wasi-sdk 34.0 ($("$WS/bin/clang" --version | head -1 | cut -d'(' -f1))"
echo "wazero:         $(awk '/tetratelabs\/wazero/{print $NF}' "$FE/hosts/wazero/go.mod"), built with $(go version "$S/aprv-wazero" | cut -d' ' -f2) (go.mod: go 1.25.0; installed $(go version | cut -d' ' -f3))"
echo "endive:         $(sed -n 's:.*<endive.version>\(.*\)</endive.version>.*:\1:p' "$FE/hosts/endive/pom.xml") on $("${JDK21:-/usr/lib/jvm/java-21-openjdk-amd64}/bin/java" -version 2>&1 | head -1)"
echo "wasmkit:        $(python3 -c "import json;d=json.load(open('$S/wasmkit/AprvCabi/Package.resolved'));print([p['state'].get('version') for p in d['pins'] if p['identity']=='wasmkit'][0])") with $("${SWIFT_TC:?}/usr/bin/swift" --version 2>&1 | head -1)"
echo "jco:            1.35.0 (npm @bytecodealliance/jco; $S/jco/out was transpiled with it)"
echo "node:           $(node --version)"
echo "deno:           $(${DENO:-deno} --version | head -1)"
echo "bun:            $(${BUN:-bun} --version)"
echo "wasmtime-py:    $("$SCRATCH/pyvenv/bin/python" -c 'import importlib.metadata as m; print(m.version("wasmtime"))') on $("$SCRATCH/pyvenv/bin/python" --version)"
echo "wasmtime (Rust): $(awk '/^name = "wasmtime"$/{getline; print $3}' "$FE/hosts/wasmtime-rs/Cargo.lock" | tr -d '"'); wasmtime-internal-component-macro $(awk '/^name = "wasmtime-internal-component-macro"$/{getline; print $3}' "$FE/hosts/wasmtime-rs/Cargo.lock" | tr -d '"'); getrandom $(awk '/^name = "getrandom"$/{getline; print $3}' "$FE/hosts/wasmtime-rs/Cargo.lock" | tr -d '"' | tr '\n' ' ')"
