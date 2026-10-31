#!/usr/bin/env bash
# Installs the two measuring tools into <scratch>/bin, built from crates.io
# with the repository's pinned toolchain, and the llvm-tools component
# cargo-llvm-cov reads profiles with.
#
#   install-tools.sh <scratch>
set -euo pipefail
SCRATCH="$1"
rustup component add llvm-tools-preview --toolchain 1.99.1
cargo +1.99.1 install --locked --root "$SCRATCH" -j 3 \
  --target-dir "$SCRATCH/install-target" cargo-llvm-cov@0.9.1
cargo +1.99.1 install --locked --root "$SCRATCH" -j 3 \
  --target-dir "$SCRATCH/install-target" cargo-mutants@27.1.0
rm -rf "$SCRATCH/install-target"
