#!/usr/bin/env bash
# Spike (docs/evidence/2026-10-31-cross-build-spike.md): run what
# tools/cross/build.sh produced on a runner of that target. The same script
# checks a cross build and the native build of the same commit, so the two
# rows of the comparison ran the same checks.
#
#   tools/cross/verify.sh <build-dir> <target> <aprv.component.wasm> <label>
#
# Run from the repository root of a checkout of the same commit (fixtures/,
# the scripts and the C++ consumers come from it). <label> names the row in
# results.tsv, for example `cross` or `native`.
#
# Every check runs even after one fails; each writes a line
#   <label> TAB <target> TAB <check> TAB pass|fail|skip TAB <seconds>
# to <build-dir>/results.tsv, and the exit status is 1 if any failed.
#
# The cross-built server test executables read fixtures through paths fixed
# at compile time (env!("CARGO_MANIFEST_DIR") on the build host). The
# workflow recreates that path before this runs: a symlink at /tmp/aprv-src
# on macOS, a junction at <drive>:\tmp\aprv-src on Windows.
set -uo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 <build-dir> <target> <aprv.component.wasm> <label>" >&2
  exit 2
fi
# Native paths for native programs: Git Bash on Windows otherwise hands
# python, cmake and the test executables /d/... paths they cannot open.
native() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s\n' "$1"; fi; }
dir="$(native "$(cd "$1" && pwd)")"
target="$2"
component="$(native "$(cd "$(dirname "$3")" && pwd)/$(basename "$3")")"
label="$4"
exe=
case "$target" in *-windows-*) exe=.exe ;; esac
bin="$dir/aprv-$target$exe"
results="$dir/results.tsv"
: > "$results"
failed=0
python=python3
command -v python3 >/dev/null 2>&1 || python=python

check() {
  local name="$1"
  shift
  echo "::group::$label $target: $name"
  local start status
  start=$(date +%s)
  if "$@"; then status=pass; else status=fail; failed=1; fi
  echo "::endgroup::"
  printf '%s\t%s\t%s\t%s\t%s\n' "$label" "$target" "$name" "$status" "$(( $(date +%s) - start ))" | tee -a "$results"
}
skip() { printf '%s\t%s\t%s\tskip\t0\n' "$label" "$target" "$1" | tee -a "$results"; }

chmod +x "$bin" "$dir"/tests/*/* 2>/dev/null || true

# --- the shipped server binary ------------------------------------------
check "aprv info" "$bin" info
case "$target" in
  *-apple-darwin)
    # arm64 macOS kills an unsigned Mach-O at exec; the ad-hoc signature a
    # linker writes is enough. Print what this binary carries.
    check "code signature (codesign -dv)" codesign -dv --verbose=2 "$bin" ;;
esac
check "every case over HTTP and through the CLI" \
  "$python" rust/server/scripts/cases.py --aprv "$bin" --mode both --list
check "the managed mode" "$python" rust/server/scripts/managed-smoke.py --aprv "$bin"

# --- the server crate's own tests, as cargo test would run them ---------
run_tests() {
  local where="$1" any=0 f
  shift
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    any=1
    echo "+ $f"
    (cd "$where" && APRV_TEST_COMPONENT="$component" "$f" --include-ignored) || return 1
  done
  [[ $any == 1 ]]
}
check "server tests (--include-ignored)" run_tests rust/server "$dir"/tests/server/*

case "$target" in
  *-linux-musl*)
    # release.yml's own check: no program interpreter, no shared library.
    # readelf runs on its own first, so a readelf that fails fails the check.
    static() {
      local headers dynamic
      headers="$(readelf -lW "$bin")" && dynamic="$(readelf -dW "$bin")" || return 1
      ! grep -q INTERP <<<"$headers" && ! grep -q NEEDED <<<"$dynamic"
    }
    check "static: no INTERP, no NEEDED" static ;;
esac

# --- the C ABI ------------------------------------------------------------
cpp() {
  cmake -S rust/ffi/examples/cpp -B "$dir/cppbuild" -DAPRV_LIB_DIR="$dir/ffi" \
    && cmake --build "$dir/cppbuild" --config Debug \
    && "$dir/cppbuild/bin/aprv_conformance" "$dir/manifest"
}
if [[ ! -d "$dir/ffi" ]]; then
  skip "C ABI (none built for $target)"
else
  check "C ABI Rust tests" run_tests rust/ffi "$dir"/tests/ffi/*
  check "flatten the shared vectors" node tools/gen-cases-manifest.mjs "$dir/manifest"
  if [[ "$target" == *-windows-gnu* ]]; then
    # MinGW writes libNAME.dll.a, an import library MSVC's find_library
    # does not look for; the ctypes run below loads the DLL itself.
    skip "C++ conformance over the C ABI (MSVC consumer, MinGW library)"
  else
    check "C++ conformance over the C ABI" cpp
  fi
  check "ctypes conformance over the C ABI" "$python" rust/ffi/tests/conformance.py "$dir/ffi"
fi

# --- sizes, for the comparison --------------------------------------------
(cd "$dir" && for f in "aprv-$target$exe" ffi/*; do
  if [[ -f "$f" ]]; then printf 'size\t%s\t%s\t%s\t%s\n' "$label" "$target" "$f" "$(wc -c < "$f" | tr -d ' ')"; fi
done) > "$dir/sizes.tsv"
cat "$dir/sizes.tsv"
exit "$failed"
