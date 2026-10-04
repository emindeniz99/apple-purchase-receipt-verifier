#!/usr/bin/env bash
# Rebuilds aprv.wasm from a tag or commit in the pinned toolchain and
# compares its SHA-256 with the one given (the one a release published).
#
#   tools/reproduce-wasm.sh <tag-or-ref> <expected-sha256>
#   tools/reproduce-wasm.sh --container <tag-or-ref> <expected-sha256>
#
# Without --container it works in a fresh directory: a clean clone of the
# repository checked out at <tag-or-ref>, that ref's own
# tools/wasm-toolchain.sh (so the ref's pins, not today's), the Rust
# toolchain its rust/rust-toolchain.toml names (through rustup), and its
# rust/bindings/abi/build.sh. The build runs in a directory it has never
# run in before, so a build that leaks a path into the module fails here.
# Needs git, curl, perl, make, rustup and sha256sum; Linux x86_64, as the
# pinned toolchain archives are.
#
# With --container it runs the same steps inside tools/reproduce/Dockerfile
# (a digest-pinned Debian base with exactly those tools), so the host's
# own compilers and libraries cannot take part.
#
# Environment (all optional):
#   APRV_REPO_URL       the repository to clone (default: this checkout's
#                       origin, else the GitHub repository)
#   APRV_TOOLCHAIN_DIR  reuse a tools/wasm-toolchain.sh install; the script
#                       still checks it was made by the ref's own script
#   APRV_REPRODUCE_OUT  where to leave the rebuilt files (default: a
#                       temporary directory, printed at the end)
#   APRV_EXPECTED_COMPONENT_SHA256
#                       also require the rebuilt aprv.component.wasm to
#                       have this hash (the release checks both files)
#
# Exit status: 0 when the hashes match, 1 when they differ or a step fails,
# 2 on a usage error.
set -euo pipefail

container=false
if [[ "${1:-}" == "--container" ]]; then container=true; shift; fi
if [[ $# -ne 2 ]]; then
  echo "usage: $0 [--container] <tag-or-ref> <expected-sha256>" >&2
  exit 2
fi
REF=$1
EXPECTED=$2
if [[ ! "$EXPECTED" =~ ^[0-9a-f]{64}$ ]]; then
  echo "reproduce-wasm: '$EXPECTED' is not a lowercase hex SHA-256" >&2
  exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="${APRV_REPO_URL:-$(git -C "$here" remote get-url origin 2>/dev/null || echo https://github.com/emindeniz99/apple-purchase-receipt-verifier.git)}"

if $container; then
  command -v docker >/dev/null || { echo "reproduce-wasm: --container needs docker" >&2; exit 1; }
  out="${APRV_REPRODUCE_OUT:-$(mktemp -d)}"
  mkdir -p "$out"
  docker build --quiet -t aprv-reproduce "$here/reproduce" >&2
  exec docker run --rm -e APRV_REPO_URL="$REPO_URL" -e APRV_REPRODUCE_OUT=/out \
    -v "$out:/out" aprv-reproduce "$REF" "$EXPECTED"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/aprv-reproduce.XXXXXX")"
echo "reproduce-wasm: working in $work" >&2
src="$work/src"
git clone --quiet --no-checkout "$REPO_URL" "$src"
git -C "$src" -c advice.detachedHead=false checkout --quiet "$REF"
commit="$(git -C "$src" rev-parse HEAD)"
echo "reproduce-wasm: $REF is $commit" >&2

build="$src/rust/bindings/abi/build.sh"
if [[ ! -f "$build" ]]; then
  echo "reproduce-wasm: $REF has no rust/bindings/abi/build.sh; it predates aprv.wasm" >&2
  exit 1
fi

toolchain="${APRV_TOOLCHAIN_DIR:-$work/toolchain}"
env_lines="$("$src/tools/wasm-toolchain.sh" "$toolchain")"
eval "$env_lines"
export WASI_SDK_DIR OPENSSL_WASM_DIR PATH

# rustup reads rust/rust-toolchain.toml from the build's directory; name
# the channel explicitly too, so an override in the environment cannot
# pick another compiler.
channel="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$src/rust/rust-toolchain.toml")"
[[ -n "$channel" ]] || { echo "reproduce-wasm: rust/rust-toolchain.toml names no channel" >&2; exit 1; }
unset RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_TARGET_DIR
(cd "$src/rust" && rustup toolchain install "$channel" --profile minimal --target wasm32-wasip1 >&2)
export RUSTUP_TOOLCHAIN="$channel"
rustc --version >&2

out="${APRV_REPRODUCE_OUT:-$work/out}"
mkdir -p "$out"
(cd "$src" && "$build" "$out" >&2)

actual="$(sha256sum "$out/aprv.wasm" | cut -c1-64)"
echo "reproduce-wasm: aprv.wasm   $actual (rebuilt from $commit)"
echo "reproduce-wasm: expected    $EXPECTED"
component=""
if [[ -f "$out/aprv.component.wasm" ]]; then
  component="$(sha256sum "$out/aprv.component.wasm" | cut -c1-64)"
  echo "reproduce-wasm: component   $component"
fi
echo "reproduce-wasm: files in $out"
if [[ "$actual" != "$EXPECTED" ]]; then
  echo "reproduce-wasm: MISMATCH: the rebuild does not reproduce the expected hash" >&2
  exit 1
fi
if [[ -n "${APRV_EXPECTED_COMPONENT_SHA256:-}" && "$component" != "$APRV_EXPECTED_COMPONENT_SHA256" ]]; then
  echo "reproduce-wasm: MISMATCH: the rebuilt component is not the expected $APRV_EXPECTED_COMPONENT_SHA256" >&2
  exit 1
fi
echo "reproduce-wasm: reproduced"
