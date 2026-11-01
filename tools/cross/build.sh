#!/usr/bin/env bash
# Spike (docs/evidence/2026-10-31-cross-build-spike.md): the final builds
# for one target around a .ccwasm tools/cross/precompile.sh wrote: the
# runtime-only aprv-server, the C ABI library, and the test executables of
# both crates, for a runner of that target to run (tools/cross/verify.sh).
#
#   tools/cross/build.sh <aprv.TARGET.ccwasm> <target> <outdir>
#
# How each target is linked:
#   the host's own triple                      cargo build (candidate B)
#   *-linux-musl, the host's architecture      cargo build, musl-gcc for C
#   *-linux-musl, another architecture         cargo zigbuild
#   *-apple-darwin                             cargo zigbuild
#   *-windows-gnu                              cargo zigbuild (zig's MinGW)
#   *-windows-msvc from a non-Windows host     cargo xwin (clang-cl, lld-link,
#                                              the MSVC CRT and Windows SDK
#                                              that xwin downloads)
#
# The server's runtime-only build embeds the .ccwasm (APRV_CCWASM; its
# .ccwasm.json manifest must sit beside it, and build.rs refuses a file
# precompiled for another target or Wasmtime version). The server test
# executables are a `test --no-run` build with --features compile, since
# those tests compile the component themselves. The C ABI is a release
# build of rust/ffi plus its debug test executables, as the rust-ffi job
# runs them; there is none for a musl target, where Rust builds no cdylib.
#
# Writes into <outdir>:
#   aprv-<target>[.exe]          the shipped server binary
#   ffi/                         the C ABI library (and import library)
#   tests/server/, tests/ffi/    the test executables
#   SHA256SUMS                   every file above
#   build.txt                    tool versions and the commands run
#   timings.tsv                  seconds per step (label, target, step, s);
#                                the label is BUILD_LABEL, else b for a
#                                native build and c for a cross build
#
# The server tests read fixtures through env!("CARGO_MANIFEST_DIR"), a path
# fixed at compile time. A cross build runs from a checkout whose path a
# verify runner can recreate (the spike workflow uses /tmp/aprv-src); this
# script keeps that path as given rather than resolving it.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <aprv.TARGET.ccwasm> <target> <outdir>" >&2
  exit 2
fi
ccwasm="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
target="$2"
mkdir -p "$3"
out="$(cd "$3" && pwd)"
# Logical path (no -P): a symlinked checkout keeps the symlink's path.
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
host="$(rustc -vV | sed -n 's/^host: //p')"
exe=
case "$target" in *-windows-*) exe=.exe ;; esac
python=python3
command -v python3 >/dev/null 2>&1 || python=python

kind=cross
case "$target" in
  "$host")
    build=(cargo build) test=(cargo test) tool="native" kind=native ;;
  *-linux-musl*)
    if [[ "${target%%-*}" == "${host%%-*}" && "$host" == *-linux-* ]]; then
      # cc-rs looks for <arch>-linux-musl-gcc; Ubuntu's musl-tools installs
      # musl-gcc, as build-static.sh notes.
      ccvar="CC_$(echo "$target" | tr - _)"
      if [[ -z "${!ccvar:-}" ]] && command -v musl-gcc >/dev/null 2>&1; then export "$ccvar=musl-gcc"; fi
      build=(cargo build) test=(cargo test) tool="native, musl-gcc" kind=native
    else
      build=(cargo zigbuild) test=(cargo-zigbuild test) tool="cargo-zigbuild"
    fi ;;
  *-apple-darwin | *-windows-gnu*)
    build=(cargo zigbuild) test=(cargo-zigbuild test) tool="cargo-zigbuild" ;;
  *-windows-msvc)
    build=(cargo xwin build) test=(cargo xwin test) tool="cargo-xwin" ;;
  *)
    echo "no way to build $target from $host in this spike" >&2
    exit 2 ;;
esac
label="${BUILD_LABEL:-}"
[[ -n "$label" ]] || { [[ $kind == native ]] && label=b || label=c; }
case "$tool" in
  cargo-zigbuild) tool="cargo-zigbuild $(cargo zigbuild --version 2>/dev/null | awk '{print $2}'), zig $("$python" -m ziglang version 2>/dev/null || zig version)" ;;
  cargo-xwin) tool="$(cargo xwin --version 2>/dev/null)" ;;
esac

# zig links a Mach-O for its own default macOS (15.0 with zig 0.17.0, seen
# in LC_BUILD_VERSION) unless told otherwise, where rustc's native link
# uses the target's default (11.0 for arm64, 10.12 for x86_64). Name
# rustc's default, so a cross build claims the same oldest macOS as a
# native one.
case "$target" in
  *-apple-darwin)
    MACOSX_DEPLOYMENT_TARGET="${MACOSX_DEPLOYMENT_TARGET:-$(rustc --print deployment-target --target "$target" | sed 's/^.*=//')}"
    export MACOSX_DEPLOYMENT_TARGET ;;
esac

log="$out/build.txt"
{
  echo "target: $target"
  echo "host: $host"
  echo "tool: $tool"
  echo "MACOSX_DEPLOYMENT_TARGET: ${MACOSX_DEPLOYMENT_TARGET:-}"
  echo "ccwasm: $(basename "$ccwasm")"
  rustc -vV
} > "$log"
: > "$out/timings.tsv"
run() { echo "+ $*" >> "$log"; echo "+ $*" >&2; "$@"; }
now() { date +%s; }
timed() { printf '%s\t%s\t%s\t%s\n' "$label" "$target" "$1" "$(( $(now) - $2 ))" | tee -a "$out/timings.tsv"; }
# The JSON messages of a `--no-run` build name each test executable. On
# Windows Python writes CRLF, so callers strip the CR before using a path.
executables() { "$python" -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("profile", {}).get("test") and m.get("executable"):
        print(m["executable"])
'; }

server="$repo/rust/server"
ffi="$repo/rust/ffi"
rm -rf "$out/tests/server"
mkdir -p "$out/tests/server"

echo "::group::the runtime-only server for $target"
start=$(now)
APRV_CCWASM="$ccwasm" run "${build[@]}" --release --locked --manifest-path "$server/Cargo.toml" --target "$target"
cp "$server/target/$target/release/aprv$exe" "$out/aprv-$target$exe"
timed server-final "$start"
echo "::endgroup::"

echo "::group::server test executables for $target"
start=$(now)
run "${test[@]}" --no-run --locked --manifest-path "$server/Cargo.toml" --target "$target" --features compile --message-format=json \
  | executables | tr -d '\r' | while IFS= read -r f; do cp "$f" "$out/tests/server/"; done
timed server-tests "$start"
echo "::endgroup::"

case "$target" in
  *-linux-musl*)
    echo "C ABI: skipped, Rust builds no cdylib for $target" | tee -a "$log" ;;
  *)
    mkdir -p "$out/ffi" "$out/tests/ffi"
    echo "::group::the C ABI library for $target"
    # A Mach-O dylib's install name defaults to the path the linker wrote it
    # to, which for a cross build is a Linux path no Mac has; a consumer
    # linked against it would look for the library there. @rpath/<name>
    # lets the consumer's rpath (CMake's BUILD_RPATH in rust/ffi/examples/cpp)
    # find it.
    ffi_rustflags="${RUSTFLAGS:-}"
    case "$target" in
      *-apple-darwin)
        ffi_rustflags="$ffi_rustflags -C link-arg=-Wl,-install_name,@rpath/libapple_purchase_receipt_verifier_ffi.dylib" ;;
    esac
    start=$(now)
    # A failed C ABI build is recorded, not fatal: the server files above
    # still go to the verify job. cargo-xwin is the known case: openssl-src
    # configures OpenSSL for MSVC with Configure's VC-WIN64A/VC-WIN64-ARM,
    # which refuses a Unix perl and then needs nmake.
    if RUSTFLAGS="$ffi_rustflags" run "${build[@]}" --release --locked --manifest-path "$ffi/Cargo.toml" --target "$target"; then
      lib="$repo/rust/target/$target/release"
      for f in libapple_purchase_receipt_verifier_ffi.dylib libapple_purchase_receipt_verifier_ffi.so \
               apple_purchase_receipt_verifier_ffi.dll apple_purchase_receipt_verifier_ffi.dll.lib \
               libapple_purchase_receipt_verifier_ffi.dll.a; do
        if [[ -f "$lib/$f" ]]; then cp "$lib/$f" "$out/ffi/"; fi
      done
      timed ffi "$start"
      echo "::endgroup::"

      echo "::group::C ABI test executables for $target"
      start=$(now)
      run "${test[@]}" --no-run --locked --manifest-path "$ffi/Cargo.toml" --target "$target" --message-format=json \
        | executables | tr -d '\r' | while IFS= read -r f; do cp "$f" "$out/tests/ffi/"; done
      timed ffi-tests "$start"
      echo "::endgroup::"
    else
      echo "::endgroup::"
      echo "::warning::the C ABI did not build for $target with $tool"
      echo "C ABI: the build failed with $tool" >> "$log"
      timed ffi-failed "$start"
      rm -rf "$out/ffi" "$out/tests/ffi"
    fi
    ;;
esac

sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
(cd "$out" && find . -type f ! -name SHA256SUMS ! -name build.txt ! -name timings.tsv | LC_ALL=C sort | sed 's|^\./||' \
  | while read -r f; do sha "$f"; done > SHA256SUMS)
echo "== $target"
(cd "$out" && find . -type f ! -name SHA256SUMS ! -name build.txt ! -name timings.tsv | LC_ALL=C sort | while read -r f; do
  printf '%12d  %s\n' "$(wc -c < "$f")" "${f#./}"
done)
