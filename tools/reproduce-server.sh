#!/usr/bin/env bash
# Rebuilds a static Linux aprv-server binary from a tag or commit and
# compares its SHA-256 with the one given (the one a release published).
#
#   tools/reproduce-server.sh <tag-or-ref> <target-triple> <expected-sha256>
#
# <target-triple> is x86_64-unknown-linux-musl or aarch64-unknown-linux-musl,
# built on a host of the same architecture. The macOS and Windows builds are
# not covered: their linkers stamp the output, so the release attests them
# but does not claim they reproduce.
#
# Steps, all in a fresh directory: a clean clone at <tag-or-ref>; that ref's
# tools/wasm-toolchain.sh; its rust/bindings/abi/build.sh, whose component
# the server embeds (set APRV_EXPECTED_COMPONENT_SHA256 to also check the
# component against the release's); the Rust toolchain its
# rust/rust-toolchain.toml names, with the musl target; then
#
#   rust/server/scripts/build-static.sh <component.wasm> <target-triple> <out-dir>
#
# which precompiles the component and builds the binary that embeds it,
# leaving <out-dir>/aprv-<target-triple> (rust/server's own interface,
# OD-08).
#
# Environment: APRV_REPO_URL, APRV_TOOLCHAIN_DIR and APRV_REPRODUCE_OUT as
# for tools/reproduce-wasm.sh. Exit status: 0 on a match, 1 on a mismatch or
# a failed step, 2 on a usage error.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 <tag-or-ref> <target-triple> <expected-sha256>" >&2
  exit 2
fi
REF=$1
TARGET=$2
EXPECTED=$3
case "$TARGET" in
  x86_64-unknown-linux-musl | aarch64-unknown-linux-musl) ;;
  *) echo "reproduce-server: only the static Linux builds reproduce; not $TARGET" >&2; exit 2 ;;
esac
if [[ ! "$EXPECTED" =~ ^[0-9a-f]{64}$ ]]; then
  echo "reproduce-server: '$EXPECTED' is not a lowercase hex SHA-256" >&2
  exit 2
fi
if [[ "$(uname -m)" != "${TARGET%%-*}" ]]; then
  echo "reproduce-server: $TARGET builds on a $(uname -m) host only on its own architecture; run it on ${TARGET%%-*}" >&2
  exit 1
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_URL="${APRV_REPO_URL:-$(git -C "$here" remote get-url origin 2>/dev/null || echo https://github.com/emindeniz99/apple-purchase-receipt-verifier.git)}"
work="$(mktemp -d "${TMPDIR:-/tmp}/aprv-reproduce-server.XXXXXX")"
echo "reproduce-server: working in $work" >&2
src="$work/src"
git clone --quiet --no-checkout "$REPO_URL" "$src"
git -C "$src" -c advice.detachedHead=false checkout --quiet "$REF"
commit="$(git -C "$src" rev-parse HEAD)"

for f in rust/bindings/abi/build.sh rust/server/scripts/build-static.sh; do
  [[ -f "$src/$f" ]] || { echo "reproduce-server: $REF has no $f" >&2; exit 1; }
done

toolchain="${APRV_TOOLCHAIN_DIR:-$work/toolchain}"
env_lines="$("$src/tools/wasm-toolchain.sh" "$toolchain")"
eval "$env_lines"
export WASI_SDK_DIR OPENSSL_WASM_DIR PATH

channel="$(sed -n 's/^channel *= *"\([^"]*\)".*/\1/p' "$src/rust/rust-toolchain.toml")"
[[ -n "$channel" ]] || { echo "reproduce-server: rust/rust-toolchain.toml names no channel" >&2; exit 1; }
unset RUSTUP_TOOLCHAIN RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS CARGO_TARGET_DIR
(cd "$src/rust" && rustup toolchain install "$channel" --profile minimal --target wasm32-wasip1 --target "$TARGET" >&2)
export RUSTUP_TOOLCHAIN="$channel"

out="${APRV_REPRODUCE_OUT:-$work/out}"
mkdir -p "$out/wasm"
(cd "$src" && rust/bindings/abi/build.sh "$out/wasm" >&2)
component_sha="$(sha256sum "$out/wasm/aprv.component.wasm" | cut -c1-64)"
echo "reproduce-server: component   $component_sha"
if [[ -n "${APRV_EXPECTED_COMPONENT_SHA256:-}" && "$component_sha" != "$APRV_EXPECTED_COMPONENT_SHA256" ]]; then
  echo "reproduce-server: MISMATCH: the component is not the release's ($APRV_EXPECTED_COMPONENT_SHA256)" >&2
  exit 1
fi

(cd "$src" && rust/server/scripts/build-static.sh "$out/wasm/aprv.component.wasm" "$TARGET" "$out" >&2)
actual="$(sha256sum "$out/aprv-$TARGET" | cut -c1-64)"
echo "reproduce-server: aprv ($TARGET) $actual (rebuilt from $commit)"
echo "reproduce-server: expected      $EXPECTED"
if [[ "$actual" != "$EXPECTED" ]]; then
  echo "reproduce-server: MISMATCH: the rebuild does not reproduce the expected hash" >&2
  exit 1
fi
echo "reproduce-server: reproduced"
