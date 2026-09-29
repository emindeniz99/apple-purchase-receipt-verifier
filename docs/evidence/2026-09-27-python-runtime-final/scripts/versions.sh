#!/bin/sh
# Spike only (2026-09-27, round 11). Versions, machine and module hash.
#   versions.sh > results/versions.txt
set -eu
. "$(dirname "$0")/env.sh"
echo "date: $(date -u +%F)"
echo "os: $(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r), $(uname -m)"
echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'), $(nproc) vCPUs, $(awk '/MemTotal/ {printf "%.0f GB", $2/1048576}' /proc/meminfo) RAM"
echo "python: $("$PY312" --version) (facades, harness children); $(python3 --version) (harness parents)"
echo "pywasm: $("$PYWASM_VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("pywasm"))') in a python3.12 venv"
echo "rust: $(rustc --version), $(cargo --version)"
echo "zig: $("$S/venv-zig/bin/python" -m ziglang version) (PyPI ziglang), cargo-zigbuild $("$S/venv-zig/bin/cargo-zigbuild" --version | cut -d' ' -f2) (PyPI)"
echo "qemu: $(qemu-aarch64 --version | head -1)"
echo "wasm-tools: $("$SCRATCH/tools/wasm-tools-1.259.0-x86_64-linux/wasm-tools" --version) (compiles ../wat/*.wat)"
echo "module: aprv-abi1.wasm $(wc -c < "$MOD") bytes, sha256 $(sha256sum "$MOD" | cut -d' ' -f1) (expected $MOD_SHA256)"
echo "round 9 native host reused for the A/B: aprv-wasmi2-auto (round 9's build-wasmi.sh wasmi2-auto), sha256 $(sha256sum "$SCRATCH/r9/bin/aprv-wasmi2-auto" | cut -d' ' -f1)"
