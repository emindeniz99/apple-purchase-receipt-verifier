#!/bin/sh
# Spike only (2026-09-29, round 12). The tool versions behind results/.
#   versions.sh > results/versions.txt
set -u
. "$(dirname "$0")/env.sh"
echo "# $(date -u +%F), $(uname -m)"
echo "rustc:          $(rustc --version)"
echo "wit-bindgen:    crate $(awk '/^name = "wit-bindgen"$/{getline; print $3}' "$FE/guest/Cargo.lock" | tr -d '"'); CLI $(wit-bindgen --version)"
echo "wasm-tools:     $(wasm-tools --version)"
echo "wasi-sdk:       $("$WS/bin/clang" --version | head -1)"
echo "go:             host-built binary $(go version "$S/aprv-wazero" | cut -d' ' -f2) (installed $(go version | cut -d' ' -f3); go.mod says go 1.25.0, which wazero 1.12 needs, so GOTOOLCHAIN=auto fetched that toolchain)"
echo "wazero:         $(awk '/tetratelabs\/wazero/{print $NF}' "$FE/hosts/wazero/go.mod")"
echo "endive:         $(sed -n 's:.*<endive.version>\(.*\)</endive.version>.*:\1:p' "$FE/hosts/endive/pom.xml")"
echo "java:           $(env -u JAVA_TOOL_OPTIONS "${JDK21:-/usr/lib/jvm/java-21-openjdk-amd64}/bin/java" -version 2>&1 | head -1)"
echo "node:           $(node --version)"
echo "jco:            $(node -p "require('$S/jco/node_modules/@bytecodealliance/jco/package.json').version" 2>/dev/null)"
echo "wasmtime-py:    $("$SCRATCH/pyvenv/bin/python" -c 'import importlib.metadata as m; print(m.version("wasmtime"))') ($("$SCRATCH/pyvenv/bin/python" --version))"
