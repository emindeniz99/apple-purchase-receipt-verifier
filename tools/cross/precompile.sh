#!/usr/bin/env bash
# Spike (docs/evidence/2026-10-31-cross-build-spike.md), candidates B and C:
# build the Cranelift precompiler ONCE on this host, then write one .ccwasm
# per target with it.
#
#   tools/cross/precompile.sh <aprv.component.wasm> <outdir> <target>...
#
# The precompiler is rust/server's full build (`--features
# compile,wasmtime/all-arch`, so Cranelift has every backend) for the host's
# own triple, in the release profile build-static.sh uses (opt-level 3,
# fat LTO, one codegen unit) unless PRECOMPILER_PROFILE names another
# Cargo profile, for example a cheaper one passed through
# CARGO_PROFILE_<NAME>_* variables. `aprv precompile --target T` then writes
# aprv.T.ccwasm and its manifest for each target, exactly as build-static.sh
# step 1 does on a native leg.
#
# Writes into <outdir>: aprv.<target>.ccwasm and .ccwasm.json per target,
# SHA256SUMS over the .ccwasm files, and timings.tsv
# (`precompiler-build` and `precompile <target>`, in seconds).
set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "usage: $0 <aprv.component.wasm> <outdir> <target>..." >&2
  exit 2
fi
component="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
mkdir -p "$2"
out="$(cd "$2" && pwd)"
shift 2
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
server="$repo/rust/server"
host="$(rustc -vV | sed -n 's/^host: //p')"
profile="${PRECOMPILER_PROFILE:-release}"
dir="$profile"
[[ "$profile" == dev ]] && dir=debug
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }
now() { date +%s.%N 2>/dev/null || date +%s; }
elapsed() { awk -v a="$1" -v b="$(now)" 'BEGIN { printf "%.1f", b - a }'; }

: > "$out/timings.tsv"
echo "::group::the precompiler ($host, profile $profile, compile + wasmtime/all-arch)"
start=$(now)
cargo build --profile "$profile" --locked --manifest-path "$server/Cargo.toml" --target "$host" \
  --features compile,wasmtime/all-arch
printf 'precompiler-build\t%s\n' "$(elapsed "$start")" | tee -a "$out/timings.tsv"
echo "::endgroup::"
precompiler="$server/target/$host/$dir/aprv"
"$precompiler" info | head -n 20 || true

for target in "$@"; do
  start=$(now)
  "$precompiler" precompile "$component" --target "$target" -o "$out/aprv.$target.ccwasm"
  printf 'precompile %s\t%s\n' "$target" "$(elapsed "$start")" | tee -a "$out/timings.tsv"
done
(cd "$out" && sha aprv.*.ccwasm > SHA256SUMS && cat SHA256SUMS)
