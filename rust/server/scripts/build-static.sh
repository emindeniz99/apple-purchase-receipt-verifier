#!/bin/sh
# Two-stage build of the shipped `aprv` binary (README.md, "The precompile
# rule"):
#
#   1. the full build (Cranelift, the build host's own triple) precompiles
#      the component for TARGET's baseline ISA: `aprv precompile` writes
#      aprv.TARGET.ccwasm and its manifest;
#   2. the runtime-only build for TARGET embeds that file (APRV_CCWASM).
#      build.rs refuses a .wasm, a file changed since step 1, or one
#      precompiled for another target or Wasmtime version.
#
#   build-static.sh COMPONENT.wasm [TARGET] [OUTDIR]
#
# TARGET defaults to x86_64-unknown-linux-musl: a fully static binary
# (static-pie, musl's own malloc; no INTERP, no NEEDED), which the script
# checks with readelf; it needs musl-gcc (musl-tools) for the C that
# Wasmtime compiles. OUTDIR defaults to rust/server/dist. Set
# COMPONENT_SHA256 to refuse any other component (the release does). A
# Windows TARGET writes aprv-TARGET.exe.
#
# aarch64-unknown-linux-musl works the same way but needs a cross linker,
# which this script does not provide (untested here):
#   CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc \
#     build-static.sh aprv.component.wasm aarch64-unknown-linux-musl
# (or `cargo zigbuild`, as docs/evidence/2026-09-27-static-musl-server
# did). For a TARGET of another architecture than the host, step 1 adds
# `wasmtime/all-arch` so Cranelift has that backend.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
component=${1:?usage: build-static.sh COMPONENT.wasm [TARGET] [OUTDIR]}
target=${2:-x86_64-unknown-linux-musl}
out=${3:-$here/dist}
host=$(rustc -vV | sed -n 's/^host: //p')
targetdir=${CARGO_TARGET_DIR:-$here/target}
mkdir -p "$out"
exe=
case "$target" in *-windows-*) exe=.exe ;; esac
# stdin, not a name: sha256sum escapes a name holding a backslash (Windows).
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum < "$1"; else shasum -a 256 < "$1"; fi | cut -c1-64; }

got=$(sha256 "$component")
if [ -n "${COMPONENT_SHA256:-}" ] && [ "$got" != "$COMPONENT_SHA256" ]; then
  echo "component sha256 $got is not the expected $COMPONENT_SHA256" >&2
  exit 1
fi
echo "component: $component, sha256 $got"

# cc-rs compiles Wasmtime's C helpers with TARGET's C compiler and, for a
# musl TARGET, looks for <arch>-linux-musl-gcc (and musl-gcc for x86_64
# only). Debian's and Ubuntu's musl-tools package installs musl-gcc for
# the machine's own architecture, so name it for a native musl TARGET
# unless CC_<target> already says otherwise.
case "$target" in
*-linux-musl*)
  ccvar="CC_$(echo "$target" | tr - _)"
  if [ "${target%%-*}" = "${host%%-*}" ] && [ -z "$(eval "echo \${$ccvar:-}")" ] \
    && command -v musl-gcc >/dev/null 2>&1; then
    export "$ccvar=musl-gcc"
  fi
  ;;
esac

features=compile
[ "${target%%-*}" = "${host%%-*}" ] || features="compile,wasmtime/all-arch"

# 1. The full build precompiles for TARGET, with the serving build's
#    Wasmtime settings (runtime::config() in both).
cargo build --release --locked --manifest-path "$here/Cargo.toml" --target "$host" --features "$features"
full="$targetdir/$host/release/aprv"
ccwasm="$out/aprv.$target.ccwasm"
"$full" precompile "$component" --target "$target" -o "$ccwasm"

# 2. The shipped build: runtime-only, the .ccwasm embedded.
APRV_CCWASM="$ccwasm" cargo build --release --locked --manifest-path "$here/Cargo.toml" --target "$target"
bin="$out/aprv-$target$exe"
cp "$targetdir/$target/release/aprv$exe" "$bin"

echo "binary: $bin, $(wc -c < "$bin") bytes, gzip -9 $(gzip -9c "$bin" | wc -c) bytes, sha256 $(sha256 "$bin")"
case "$target" in
*-linux-musl*)
  interp=$(readelf -l "$bin" | grep -c INTERP || true)
  needed=$(readelf -d "$bin" 2>/dev/null | grep -c NEEDED || true)
  echo "readelf: $interp INTERP, $needed NEEDED; $(readelf -h "$bin" | sed -n 's/^ *Type: *//p')"
  if [ "$interp" != 0 ] || [ "$needed" != 0 ]; then
    echo "not a static binary" >&2
    exit 1
  fi
  ;;
esac
if [ "${target%%-*}" = "${host%%-*}" ]; then
  "$bin" info
fi
