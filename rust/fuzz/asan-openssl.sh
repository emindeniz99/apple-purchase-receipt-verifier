#!/usr/bin/env bash
# Fuzzes the core over an OpenSSL built with AddressSanitizer and libFuzzer's
# coverage instrumentation, as the evidence campaigns did
# (docs/evidence/2026-09-26-substrate-followup/ §4,
# docs/evidence/2026-09-26-openssl-cms-everywhere/ §4): every path inside
# OpenSSL is instrumented C, so libFuzzer is guided by edges in the CMS,
# X.509 and ASN.1 code and ASan sees its memory errors.
#
#   rust/fuzz/asan-openssl.sh <openssl-dir> <seconds> [target ...]
#
# <openssl-dir> holds the instrumented build, or receives it: when it has no
# lib/libcrypto.a, tools/openssl-asan.sh (the one pin of the OpenSSL
# tarball) builds it there first. Each target (default: every target
# run.sh's `all` names) then runs for <seconds> through run.sh, linked
# against that build. A crash, a leak or a timeout stops that target and
# fails the script; the reproducer is under rust/fuzz/artifacts/<target>/
# (gitignored), to be reduced into a test that uses test keys only.
#
# Needs clang, a nightly Rust with cargo-fuzz (FUZZ_TOOLCHAIN picks the
# nightly, default `nightly`), perl, make and curl.
set -euo pipefail
if [[ $# -lt 2 ]]; then
  echo "usage: $0 <openssl-dir> <seconds> [target ...]" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
mkdir -p "$1"
dir="$(cd "$1" && pwd)"
seconds="$2"
shift 2
targets=("$@")
[[ ${#targets[@]} -gt 0 ]] || targets=(all)

if [[ ! -f "$dir/lib/libcrypto.a" ]]; then
  "${OPENSSL_ASAN_SH:-$repo/tools/openssl-asan.sh}" "$dir" > /dev/null
fi
export OPENSSL_DIR="$dir" OPENSSL_STATIC=1 OPENSSL_NO_VENDOR=1
export ASAN_OPTIONS="${ASAN_OPTIONS:-detect_leaks=1:allocator_may_return_null=0}"

status=0
for target in "${targets[@]}"; do
  echo "asan-openssl: $target, $seconds s, OpenSSL from $dir" >&2
  if ! "$here/run.sh" "$target" "$seconds"; then
    echo "asan-openssl: $target FAILED; see $here/artifacts/" >&2
    status=1
  fi
done
exit "$status"
