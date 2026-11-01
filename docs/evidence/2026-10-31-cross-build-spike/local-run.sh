#!/usr/bin/env bash
# The local half of the cross-build spike on a Linux x86_64 host: one
# tools/cross/precompile.sh run for every target, then tools/cross/build.sh
# per target, one log each.
#
#   SCRATCH=<dir> COMPONENT=<aprv.component.wasm> local-run.sh <repo-path> [target...]
#
# <repo-path> is the checkout as the builds should see it (a symlink is
# kept as given: the server tests bake that path in). Needs, on PATH:
# cargo-zigbuild and zig (pip install ziglang cargo-zigbuild), cargo-xwin
# (pip install cargo-xwin), clang-cl (a symlink to clang works), lld-link
# and llvm-lib; and the targets added to the pinned toolchain
# (rustup target add --toolchain <channel> <target>...).
#
# The .ccwasm files go to $SCRATCH/ccwasm, each target's build output to
# $SCRATCH/out/<target>, the logs to $SCRATCH/logs, one wall-clock line per
# step to $SCRATCH/logs/summary.txt. The cargo target directories are
# removed after each target unless KEEP_TARGET_DIRS is set, because several
# wasmtime builds do not fit a small disk.
#
# The first runs of the spike (the first four rows of the note's section 1)
# used an earlier build.sh that also built stage 1; the note says which
# rows ran which.
set -uo pipefail
repo="${1:?usage: local-run.sh <repo-path> [target...]}"
shift
: "${SCRATCH:?SCRATCH is not set}" "${COMPONENT:?COMPONENT is not set}"
targets=("$@")
[[ ${#targets[@]} -gt 0 ]] || targets=(aarch64-apple-darwin x86_64-apple-darwin x86_64-pc-windows-gnu
  x86_64-pc-windows-msvc aarch64-pc-windows-msvc aarch64-unknown-linux-musl)
RUSTUP_TOOLCHAIN="$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$repo/rust/rust-toolchain.toml")"
export RUSTUP_TOOLCHAIN
mkdir -p "$SCRATCH/out" "$SCRATCH/logs"
cd "$repo" || exit 1

start=$(date +%s)
rm -rf "$SCRATCH/ccwasm"
"$repo/tools/cross/precompile.sh" "$COMPONENT" "$SCRATCH/ccwasm" "${targets[@]}" > "$SCRATCH/logs/precompile.log" 2>&1
status=$?
echo "precompile: exit $status after $(( $(date +%s) - start )) s" | tee -a "$SCRATCH/logs/summary.txt"
# No target build may run on stale or missing .ccwasm files.
[[ $status == 0 ]] || exit "$status"
failed=0

for t in "${targets[@]}"; do
  start=$(date +%s)
  "$repo/tools/cross/build.sh" "$SCRATCH/ccwasm/aprv.$t.ccwasm" "$t" "$SCRATCH/out/$t" > "$SCRATCH/logs/$t.log" 2>&1
  status=$?
  echo "$t: exit $status after $(( $(date +%s) - start )) s" | tee -a "$SCRATCH/logs/summary.txt"
  [[ $status == 0 ]] || failed=1
  [[ -n "${KEEP_TARGET_DIRS:-}" ]] || rm -rf "$repo/rust/target"
done
[[ -n "${KEEP_TARGET_DIRS:-}" ]] || rm -rf "$repo/rust/server/target"
exit "$failed"
