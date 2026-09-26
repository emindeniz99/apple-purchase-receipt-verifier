#!/bin/sh
# Task 4: the repository's own fuzz targets rust/fuzz verify-receipt and
# verify-transaction (unchanged) over the CMS build (substrate-cms +
# substrate-prescan), OpenSSL 4.0.2 with AddressSanitizer and libFuzzer
# coverage ($SCRATCH/inst/openssl-4.0.2-fuzz, the follow-up's
# build-libs.sh openssl-fuzz), seeded with the follow-up campaign's corpus
# plus its seed set.
#
# The one exception to "rustc 1.98.1 for everything": cargo-fuzz passes
# -Zsanitizer=address and the sancov passes, which stable rustc refuses, so
# this uses the nightly already in $SCRATCH/rustup (1.100.0-nightly
# 2026-09-25), as the follow-up did.
#
#   scripts/fuzz.sh build
#   scripts/fuzz.sh run <verify-receipt|verify-transaction> <seconds>
set -eu
. "$(dirname "$0")/env.sh"
export RUSTUP_TOOLCHAIN=nightly PATH="$CARGO_HOME/bin:$PATH"
FZ="$C/fuzz"; PF="$SCRATCH/fu/fuzz"; mkdir -p "$FZ"
case "$1" in
build)
  AD="$C/adapter-fuzz"
  rm -rf "$AD"; mkdir -p "$AD"; cp -r "$SPIKE/security-openssl" "$AD/"
  patch -s -d "$AD/security-openssl" -p1 < "$FUP/adapter-cms/adapter-cms.patch"
  cp "$FUP/adapter-cms/cms_path.rs" "$AD/security-openssl/src/cms_path.rs"
  T="$SCRATCH/tree-cms-fuzz"; rm -rf "$T"; mkdir -p "$T/rust" "$T/fixtures"
  tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$T/rust" -xf -
  cp -r "$REPO/fixtures/generated" "$T/fixtures/"; cp "$REPO/version.txt" "$T/"
  cp "$SPIKE/core-patch/substrate.rs" "$T/rust/src/substrate.rs"
  sed "s#@SPIKE@#$AD#" "$SPIKE/core-patch/core.patch" | patch -s -d "$T/rust" -p1
  sed -i 's#^substrate-aws-lc = .*#&\nsubstrate-cms = ["substrate", "aprv-security-openssl/cms"]#' "$T/rust/Cargo.toml"
  sed -i 's#^\[dependencies.apple-purchase-receipt-verifier\]#&\nfeatures = ["substrate-cms", "substrate-prescan"]#' "$T/rust/fuzz/Cargo.toml"
  cd "$T/rust"
  for t in verify-receipt verify-transaction; do
    OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2-fuzz" OPENSSL_STATIC=1 \
      cargo fuzz build --sanitizer address --target-dir "$SCRATCH/target-cms-fuzz" "$t"
  done
  cp "$T/rust/fuzz/Cargo.lock" "$FZ/Cargo.lock"
  ;;
run)
  T="$2"; SECS="$3"
  case "$T" in verify-receipt) S="$PF/corpus-ossl-verify-receipt $PF/seeds-receipt" ;;
               verify-transaction) S="$PF/corpus-ossl-verify-transaction $PF/seeds-jws" ;; esac
  BIN="$SCRATCH/target-cms-fuzz/x86_64-unknown-linux-gnu/release/$T"
  CO="$FZ/corpus-$T"; A="$FZ/artifacts-$T"; mkdir -p "$CO" "$A"
  # New units go to $CO only; the earlier corpus and seeds are read.
  ASAN_OPTIONS=detect_leaks=1:allocator_may_return_null=0 \
    "$BIN" "$CO" $S -max_total_time="$SECS" -timeout=10 -rss_limit_mb=2048 \
    -max_len=65536 -print_final_stats=1 -artifact_prefix="$A/" \
    > "$FZ/log-$T.txt" 2>&1 || echo "exit $?" >> "$FZ/log-$T.txt"
  ;;
esac
