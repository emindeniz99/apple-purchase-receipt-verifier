#!/usr/bin/env bash
# The lint and tests of the aprv-server job, for one target:
#
#   .github/scripts/aprv-server-suite.sh <target> <component.wasm>
#
# Run from the repository root. Installs the toolchain rust/rust-toolchain.toml
# pins with rustfmt, clippy and <target>, then runs cargo fmt, clippy over
# both feature sets and the tests (with --include-ignored, so the WIT and
# wire-schema comparisons with rust/bindings run too) against the component
# rust-wasm built from this tree. ci.yml calls it from aprv-server (one leg
# per target) and, on a pull request, from macos-wrappers; one script keeps
# the two from drifting. RUSTUP_TOOLCHAIN is exported here only, never into
# $GITHUB_ENV, so a combined job's later steps keep their own toolchain.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <target> <component.wasm>" >&2
  exit 2
fi
target="$1"
component="$2"

group() {
  if [[ -n "${in_group:-}" ]]; then echo "::endgroup::"; fi
  echo "::group::$*"
  in_group=1
}

group "install the pinned Rust toolchain and $target"
channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust/rust-toolchain.toml)"
rustup toolchain install "$channel" --profile minimal --component rustfmt,clippy --target "$target"
export RUSTUP_TOOLCHAIN="$channel"

cd rust/server
group "cargo fmt --check"
cargo fmt --check
group "cargo clippy --features compile"
cargo clippy --locked --all-targets --features compile -- -D warnings
# The runtime-only feature set, which is what ships.
group "cargo clippy (runtime only)"
cargo clippy --locked --all-targets -- -D warnings
group "the tests, with this tree's component"
APRV_TEST_COMPONENT="$component" cargo test --locked --features compile -- --include-ignored
echo "::endgroup::"
