#!/usr/bin/env bash
# Line, region and branch coverage of the Rust core (rust/src) and its
# OpenSSL adapter (rust/openssl/src) under the two crates' own test suites.
#
#   coverage.sh <repo> <scratch>
#
# Needs cargo-llvm-cov on PATH and the llvm-tools component for the pinned
# toolchain (rustup component add llvm-tools-preview --toolchain 1.99.1).
#
# Branch coverage is still unstable in rustc (-Z coverage-options=branch),
# so this sets RUSTC_BOOTSTRAP=1 on the pinned stable compiler rather than
# switching to a nightly whose code generation differs. The build outputs
# go to <scratch>; the vendored OpenSSL 4.0.3 is rebuilt there once.
set -euo pipefail
REPO="$1"
SCRATCH="$2"
# install-tools.sh puts cargo-llvm-cov in <scratch>/bin.
export PATH="$SCRATCH/bin:$PATH"
export CARGO_TARGET_DIR="$SCRATCH/cov-target"
export APRV_FIXTURES_DIR="$REPO/fixtures"
export RUSTC_BOOTSTRAP=1
cd "$REPO/rust"
# Only the two crates measured here; the bindings and the C ABI are wrappers.
# `report` needs the packages too: without them it keeps the root package's
# files only and drops rust/openssl.
PKGS=(-p apple-purchase-receipt-verifier -p aprv-openssl)
IGNORE='(bindings|ffi|vendor|tests|examples|fuzz|server)/|/\.cargo/'
# --no-fail-fast: under instrumentation the Rust side runs several times
# slower while the vendored OpenSSL (C, not instrumented) does not, so a
# test that compares the cost of two inputs can fail here, more so on a
# loaded machine (envelope_bounds' tiny-entry flood failed in two of three
# runs on 2026-10-31, with other builds sharing the cores). Every test
# still runs and the report covers all of them; the log names any failure.
time cargo llvm-cov --no-report --no-fail-fast --branch --locked -j 3 \
  "${PKGS[@]}" || echo "SOME TESTS FAILED under coverage"
cargo llvm-cov report "${PKGS[@]}" --branch --ignore-filename-regex "$IGNORE" \
  --show-missing-lines > "$SCRATCH/coverage-summary.txt"
cargo llvm-cov report "${PKGS[@]}" --branch --ignore-filename-regex "$IGNORE" \
  --json --output-path "$SCRATCH/coverage.json"
cargo llvm-cov report "${PKGS[@]}" --branch --ignore-filename-regex "$IGNORE" \
  --text --output-path "$SCRATCH/coverage-text.txt"
cargo llvm-cov report "${PKGS[@]}" --branch --ignore-filename-regex "$IGNORE" \
  --html --output-dir "$SCRATCH/coverage-html"
cat "$SCRATCH/coverage-summary.txt"
