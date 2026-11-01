#!/usr/bin/env bash
# Does the .ccwasm depend on how the precompiler was built? Builds
# rust/server's precompiler three ways on this host and hashes the .ccwasm
# each writes per target:
#
#   release           the release profile, --features compile (what
#                     build-static.sh step 1 builds when TARGET's
#                     architecture is the host's); host-architecture
#                     targets only, since it has only that backend
#   release-all-arch  the release profile, --features
#                     compile,wasmtime/all-arch (candidate B's precompiler)
#   cheap-all-arch    the same with LTO off and 16 codegen units
#                     (CARGO_PROFILE_RELEASE_LTO=false,
#                     CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16): the
#                     "cheaper profile for the build-only precompiler"
#
#   ccwasm-compare.sh <aprv.component.wasm> <outdir>
#
# Each variant builds into its own CARGO_TARGET_DIR under <outdir>, which
# is removed after its precompiles, keeping only the logs. Writes
# <outdir>/hashes.tsv (variant, target, sha256, precompile seconds) and
# <outdir>/builds.tsv (variant, build seconds).
set -euo pipefail
component="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
mkdir -p "$2"
out="$(cd "$2" && pwd)"
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
host="$(rustc -vV | sed -n 's/^host: //p')"
arch="${host%%-*}"
all=(x86_64-unknown-linux-musl aarch64-unknown-linux-musl x86_64-apple-darwin aarch64-apple-darwin
     x86_64-pc-windows-msvc aarch64-pc-windows-msvc)
: > "$out/hashes.tsv"
: > "$out/builds.tsv"

variant() {
  local name="$1" features="$2"
  shift 2
  local td="$out/target-$name" start
  start=$(date +%s)
  env "$@" CARGO_TARGET_DIR="$td" cargo build --release --locked \
    --manifest-path "$repo/rust/server/Cargo.toml" --target "$host" --features "$features" \
    > "$out/$name.build.log" 2>&1
  printf '%s\t%s\n' "$name" "$(( $(date +%s) - start ))" | tee -a "$out/builds.tsv"
  for t in "${all[@]}"; do
    if [[ "$features" != *all-arch* && "${t%%-*}" != "$arch" ]]; then continue; fi
    start=$(date +%s.%N)
    "$td/$host/release/aprv" precompile "$component" --target "$t" -o "$out/$name.$t.ccwasm" > /dev/null
    printf '%s\t%s\t%s\t%s\n' "$name" "$t" "$(sha256sum < "$out/$name.$t.ccwasm" | cut -c1-64)" \
      "$(awk -v a="$start" -v b="$(date +%s.%N)" 'BEGIN { printf "%.2f", b - a }')" | tee -a "$out/hashes.tsv"
    rm -f "$out/$name.$t.ccwasm"
  done
  rm -rf "$td"
}

variant release compile
variant release-all-arch compile,wasmtime/all-arch
variant cheap-all-arch compile,wasmtime/all-arch CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
