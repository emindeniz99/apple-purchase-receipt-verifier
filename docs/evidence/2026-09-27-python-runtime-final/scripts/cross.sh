#!/bin/sh
# Spike only (2026-09-27, round 11). Cross-build feasibility of the Rust
# cdylib (../wasmi-cdylib) for the eight wheel targets, from this x86-64
# Linux container. Feasibility, artifact size and blockers only: nothing
# built here is run, except the aarch64 QEMU smoke in qemu-smoke.sh.
#
# Tools (scratch only, nothing system-wide):
#   rustup target add --toolchain 1.98.1 <the nine triples below>
#   python3 -m venv $S/venv-zig && $S/venv-zig/bin/pip install ziglang cargo-zigbuild
#     (the pair maturin uses for manylinux/musllinux/macOS cross builds)
#   cross.sh > results/cross.txt
#
# Each build is stripped by rustc (CARGO_PROFILE_RELEASE_STRIP=symbols) so
# sizes compare across object formats; its target directory is deleted after
# measuring. The glibc builds ask zig for glibc 2.17 (manylinux2014).
set -u
. "$(dirname "$0")/env.sh"
export PATH="$S/venv-zig/bin:$PATH" CARGO_PROFILE_RELEASE_STRIP=symbols
OUT="$S/cross"; mkdir -p "$OUT"
echo "# cross.sh, $(date -u +%F); $(rustc --version); cargo-zigbuild $(cargo-zigbuild --version | cut -d' ' -f2); zig $(python -m ziglang version)"
row() { # label triple artifact how(zigbuild|"" = plain cargo build) [extra RUSTFLAGS]
  label=$1; triple=$2; art=$3; how=$4; flags=${5:-}
  base=${triple%%.2.17}
  start=$(date +%s)
  if RUSTFLAGS="$flags" timeout -s KILL 1200 cargo "${how:-build}" --release --locked --target "$triple" \
       --manifest-path "$FE/wasmi-cdylib/Cargo.toml" > "$OUT/$base.log" 2>&1; then
    f="$CARGO_TARGET_DIR/$base/release/$art"
    cp "$f" "$OUT/$base-$art"
    cfg=$(cat "$CARGO_TARGET_DIR/$base"/release/build/wasmi-*/output 2>/dev/null | grep 'rustc-cfg=' | grep -o 'wasmi_[a-z_]*' | sort -u | tr '\n' ' ')
    echo "$label | $triple | cargo ${how:-build} | OK in $(( $(date +%s) - start )) s | $art $(wc -c < "$f") bytes, gzip -9 $(gzip -9c "$f" | wc -c) | $(file -b "$f" | cut -d, -f1-2) | wasmi cfg: $cfg"
    case "$triple" in
      *linux-gnu*) echo "    glibc symbol versions needed: $(readelf -V --wide "$f" | grep -o 'GLIBC_[0-9.]*' | sort -uV | tail -1); NEEDED: $(readelf -d "$f" | grep NEEDED | grep -o '\[.*\]' | tr '\n' ' ')" ;;
      *linux-musl*) echo "    NEEDED: $(readelf -d "$f" | grep NEEDED | grep -o '\[.*\]' | tr '\n' ' ')" ;;
      *windows*) echo "    DLL names in the image (strings): $(strings -n 6 "$f" | grep -i '\.dll$' | sort -u | tr '\n' ' ')" ;;
    esac
  else
    echo "$label | $triple | cargo ${how:-build} | FAILED after $(( $(date +%s) - start )) s | $(grep -m3 -E '^error|note: .*(link|not found)|cannot find' "$OUT/$base.log" | sed 's#[^ `]*/cargo-zigbuild/[^ `]*#<cargo-zigbuild linker wrapper>#g' | cut -c1-220 | tr '\n' ' ')"
  fi
  rm -rf "${CARGO_TARGET_DIR:?}/$base"
}
row "Linux glibc x86_64 (manylinux2014)" x86_64-unknown-linux-gnu.2.17 libaprv_wasmi.so zigbuild
row "Linux glibc aarch64 (manylinux2014)" aarch64-unknown-linux-gnu.2.17 libaprv_wasmi.so zigbuild
# musl targets default to crt-static, which cannot produce a cdylib; a
# musllinux wheel's shared library links musl dynamically.
row "Linux musl x86_64 (musllinux)" x86_64-unknown-linux-musl libaprv_wasmi.so zigbuild "-C target-feature=-crt-static"
row "Linux musl aarch64 (musllinux)" aarch64-unknown-linux-musl libaprv_wasmi.so zigbuild "-C target-feature=-crt-static"
row "macOS x86_64" x86_64-apple-darwin libaprv_wasmi.dylib zigbuild
row "macOS arm64" aarch64-apple-darwin libaprv_wasmi.dylib zigbuild
row "Windows x86_64 (MinGW ABI)" x86_64-pc-windows-gnu aprv_wasmi.dll zigbuild
row "Windows arm64 (MinGW/LLVM ABI)" aarch64-pc-windows-gnullvm aprv_wasmi.dll zigbuild
# The MSVC ABI needs link.exe (or lld-link) plus the MSVC CRT and Windows SDK
# import libraries, none of which ship with rustup or zig.
row "Windows x86_64 (MSVC ABI)" x86_64-pc-windows-msvc aprv_wasmi.dll ""
row "Windows arm64 (MSVC ABI)" aarch64-pc-windows-msvc aprv_wasmi.dll ""
