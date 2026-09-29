#!/bin/sh
# Spike only (2026-09-27, round 10). Machine, tools, module and artifact hashes.
#   versions.sh > results/versions.txt
set -eu
. "$(dirname "$0")/env.sh"
RL="$RUSTUP_HOME/toolchains/1.98.1-x86_64-unknown-linux-gnu/lib/rustlib"
echo "date: $(date -u +%F)"
echo "os: $(. /etc/os-release && echo "$PRETTY_NAME"), kernel $(uname -r), $(uname -m)"
echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'), $(nproc) vCPUs, $(awk '/MemTotal/ {printf "%.0f GB", $2/1048576}' /proc/meminfo) RAM"
echo "rust: $(rustc --version), $(cargo --version); rust-std targets: x86_64-unknown-linux-gnu, x86_64-unknown-linux-musl, aarch64-unknown-linux-musl"
echo "rustlib self-contained musl libc.a: x86_64 sha256 $(sha256sum "$RL/x86_64-unknown-linux-musl/lib/self-contained/libc.a" | cut -c1-16)..., aarch64 sha256 $(sha256sum "$RL/aarch64-unknown-linux-musl/lib/self-contained/libc.a" | cut -c1-16)...; statx present (musl >= 1.2.5): $(nm "$RL/x86_64-unknown-linux-musl/lib/self-contained/libc.a" 2>/dev/null | grep -c ' T statx$')"
echo "host glibc: $(ldd --version | head -1)"
echo "host C: $(cc --version | head -1); musl-tools $(dpkg-query -W -f '${Version}' musl-tools) (musl-gcc wrapper, used by cc-rs for mimalloc on x86_64 musl)"
echo "zig: $("$ZIGVENV/bin/python" -m ziglang version) (PyPI ziglang), cargo-zigbuild $("$ZIGVENV/bin/cargo-zigbuild" --version | cut -d' ' -f2) (PyPI)"
echo "crates (from the patched Cargo.lock): $(for c in wasmtime axum tokio mimalloc libmimalloc-sys cc getrandom; do printf '%s %s, ' $c "$(grep -A1 "^name = \"$c\"$" "$S/src/server/Cargo.lock" | sed -n 's/version = "\(.*\)"/\1/p' | head -1)"; done)"
echo "qemu: $(qemu-aarch64 --version | head -1); valgrind: $(valgrind --version); strace: $(strace -V | head -1)"
echo "module: aprv-abi1.wasm $(wc -c < "$WASM") bytes, sha256 $(sha256sum "$WASM" | cut -d' ' -f1)"
for t in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  echo "cwasm $t (baseline ISA): $(wc -c < "$S/art/aprv-abi1.$t.cwasm") bytes, sha256 $(sha256sum "$S/art/aprv-abi1.$t.cwasm" | cut -d' ' -f1), FDEs in .eh_frame: $(readelf --debug-dump=frames "$S/art/aprv-abi1.$t.cwasm" 2>/dev/null | grep -c ' FDE ')"
done
