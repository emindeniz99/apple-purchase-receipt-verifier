#!/bin/sh
# Task 2 (libraries): the newest library releases under the unchanged
# adapter and policy, built with rustc 1.98.1 from $SCRATCH (as
# scripts/rust198.sh), compared row by row with the builds on the
# libraries the bake-offs used.
#
#   scripts/newest.sh ossl410b1   OpenSSL 4.1.0-beta1 (BETA, informational)
#                                 after scripts/build-libs.sh openssl-4.1.0-beta1
#   scripts/newest.sh awslc045    aws-lc-sys 0.45.0 through a local copy of
#                                 openssl-sys 0.9.117 whose only change is
#                                 its aws-lc-sys requirement (^0.41 -> ^0.45)
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
FU="$REPO/docs/evidence/2026-09-26-substrate-followup"
PREVPY="$REPO/docs/evidence/2026-09-25-java-native-image-spike/py"
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$SCRATCH/cargo198" RUSTUP_TOOLCHAIN=1.98.1
A="$SCRATCH/fu/art"; R="$SCRATCH/fu/run"; mkdir -p "$A" "$R"
compare() { # name, reference variant
  for c in cases hostile algorithms substrate; do
    python3 "$PREVPY/run_rust.py" "$REPO" "$SCRATCH/target-$1/release" "$CORPORA/$c.jsonl" > "$R/$1-$c.jsonl"
    res=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$SCRATCH/run/$2-$c.jsonl" "$R/$1-$c.jsonl" 2>&1 | tail -1)
    echo "$1 native $c vs $2: $res" | tee -a "$FU/results/parity.txt"
  done
  cp "$SCRATCH/target-$1/release/libapple_purchase_receipt_verifier_ffi.so" "$A/$1.so"
  cp "$SCRATCH/target-$1/Cargo.lock.used" "$A/$1.Cargo.lock"
}
case "$1" in
ossl410b1)
  OPENSSL_DIR="$SCRATCH/inst/openssl-4.1.0-beta1" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" ossl410b1 substrate
  compare ossl410b1 ossl402
  ;;
awslc045)
  # A local copy of openssl-sys 0.9.117 with one manifest line changed,
  # wired in with [patch.crates-io]; aws-lc-sys 0.45.0 from crates.io.
  O="$SCRATCH/fu/openssl-sys-awslc045"
  rm -rf "$O"
  cp -r "$(ls -d "$CARGO_HOME"/registry/src/*/openssl-sys-0.9.117 | head -1)" "$O"
  sed -i 's/^\(\[dependencies.aws-lc-sys\]\)$/\1/; /^\[dependencies.aws-lc-sys\]/,/^\[/ s/^version = "0.41"$/version = "0.45"/' "$O/Cargo.toml"
  grep -n -A3 '^\[dependencies.aws-lc-sys\]' "$O/Cargo.toml"
  TREE="$SCRATCH/tree-awslc045"
  rm -rf "$TREE"; mkdir -p "$TREE/rust"
  tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$TREE/rust" -xf -
  cp "$REPO/version.txt" "$TREE/"
  cp "$SPIKE/core-patch/substrate.rs" "$TREE/rust/src/substrate.rs"
  sed "s#@SPIKE@#$SPIKE#" "$SPIKE/core-patch/core.patch" | patch -s -d "$TREE/rust" -p1
  printf '\n[patch.crates-io]\nopenssl-sys = { path = "%s" }\n' "$O" >> "$TREE/rust/ffi/Cargo.toml"
  # The optional substrate dependencies are not in rust/ffi/Cargo.lock;
  # cargo resolves them at build time (aws-lc-sys ^0.45 -> 0.45.0).
  cargo build --release --manifest-path "$TREE/rust/ffi/Cargo.toml" --target-dir "$SCRATCH/target-awslc045" \
    --features apple-purchase-receipt-verifier/substrate-aws-lc
  cp "$TREE/rust/ffi/Cargo.lock" "$SCRATCH/target-awslc045/Cargo.lock.used"
  strings "$SCRATCH/target-awslc045/release/libapple_purchase_receipt_verifier_ffi.so" | grep -m1 "AWS-LC" || true
  compare awslc045 awslc
  ;;
esac
