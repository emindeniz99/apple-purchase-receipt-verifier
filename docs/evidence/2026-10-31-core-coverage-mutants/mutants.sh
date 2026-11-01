#!/usr/bin/env bash
# Mutation testing of the Rust core and its OpenSSL adapter with
# cargo-mutants.
#
#   mutants.sh <repo> <scratch> <openssl-prefix> scoped|rest
#
# `scoped` runs the security-critical files (receipt verification, JWS,
# the certificate path policy, base64, JSON, the payload, the endpoint,
# the verifier and the adapter's CMS, X.509, path, signature, header walk,
# payload, envelope and item wrappers); `rest` runs every other file of
# the two crates (dates, errors, config, environment, the crate roots'
# re-exports and the key-use seam).
#
# <openssl-prefix> is an OpenSSL 4.0.3 installation (include/, lib/), such
# as the one the vendored build leaves under
# <target>/debug/build/openssl-sys-*/out/openssl-build/install. Linking it
# instead of building openssl-src in every cargo-mutants worker saves one
# OpenSSL compile per worker; it is the same 4.0.3 the vendored build
# compiles (rust/CI-NOTES.md item 3, the prebuilt-OpenSSL leg).
#
# Every mutant is tested by the core crate's whole suite plus the adapter's
# own (--test-package both): the adapter's tests alone would leave nearly
# every adapter mutant missed, since the core's tests are what drive it.
set -euo pipefail
REPO="$1"
SCRATCH="$2"
OPENSSL_PREFIX="$3"
WHICH="$4"
export PATH="$SCRATCH/bin:$PATH"
export APRV_FIXTURES_DIR="$REPO/fixtures"
export OPENSSL_NO_VENDOR=1 OPENSSL_STATIC=1 OPENSSL_DIR="$OPENSSL_PREFIX"
# Three workers on a four-core machine shared with other builds.
export CARGO_BUILD_JOBS=2
# cargo-mutants copies rust/ into $TMPDIR once per worker.
export TMPDIR="$SCRATCH/mutants-tmp"
mkdir -p "$TMPDIR"
# openssl/tests/isolation.rs reads ../../fixtures from the adapter's own
# directory, not APRV_FIXTURES_DIR; from a copy at
# $TMPDIR/cargo-mutants-rust-*.tmp/openssl that is $TMPDIR/fixtures.
ln -sfn "$REPO/fixtures" "$TMPDIR/fixtures"
cd "$REPO/rust"

SCOPED=(
  src/receipt.rs src/jws.rs src/path.rs src/base64.rs src/json.rs
  src/receipt_payload.rs src/endpoint.rs src/verifier.rs src/roots.rs
  openssl/src/cms.rs openssl/src/certificate.rs openssl/src/path.rs
  openssl/src/signature.rs openssl/src/walk.rs openssl/src/payload.rs
  openssl/src/envelope.rs openssl/src/item.rs openssl/src/lib.rs
)
args=()
case "$WHICH" in
  scoped) for f in "${SCOPED[@]}"; do args+=(-f "$f"); done ;;
  rest) for f in "${SCOPED[@]}"; do args+=(-e "$f"); done ;;
  *) echo "scoped or rest" >&2; exit 2 ;;
esac

PKGS=(-p apple-purchase-receipt-verifier -p aprv-openssl)
cargo mutants --list "${PKGS[@]}" "${args[@]}" > "$SCRATCH/mutants-$WHICH-list.txt"
echo "$(wc -l < "$SCRATCH/mutants-$WHICH-list.txt") mutants"

# The baseline test run takes about 10 s here; 120 s marks a hang.
#
# One test is skipped: envelope_bounds' a_tiny_entry_flood_costs_what_junk_
# of_its_size_costs compares two wall-clock costs with about 2 % headroom in
# a debug build on this machine (178 ms against a bound of 174 ms in the
# failed baseline), so it failed the unmutated baseline while other builds
# shared the cores, and would mark mutants caught at random. The property
# it times is also pinned without a clock by
# a_million_tiny_set_entries_are_refused_by_the_node_budget_first (the
# full-decode counter seam), which stays in.
time cargo mutants "${PKGS[@]}" \
  --test-package apple-purchase-receipt-verifier --test-package aprv-openssl \
  "${args[@]}" \
  --cargo-test-arg=-- --cargo-test-arg=--skip \
  --cargo-test-arg=a_tiny_entry_flood_costs_what_junk_of_its_size_costs \
  --jobs 3 --timeout 120 --build-timeout 900 \
  --output "$SCRATCH/mutants-$WHICH"
