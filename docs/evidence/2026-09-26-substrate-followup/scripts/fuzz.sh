#!/bin/sh
# Task 4: coverage-guided fuzzing (cargo-fuzz 0.13.2, libFuzzer, ASan) of the
# substrate policy + adapter + C library, through the repository's OWN fuzz
# targets rust/fuzz/fuzz_targets/verify-receipt.rs and verify-transaction.rs,
# unchanged. The only difference from the repository's fuzzing: the core is
# the substrate bake-off's patched copy (receipts and JWS go through
# substrate.rs and the rust-openssl adapter), and the C library is
# instrumented too.
#
#   scripts/fuzz.sh seeds                         corpora -> seed directories
#   scripts/fuzz.sh build <name> openssl|awslc    one instrumented build
#   scripts/fuzz.sh run <name> <target> <secs>    one campaign (background-safe)
#
#   openssl: OpenSSL 4.0.2 from scripts/build-libs.sh openssl-fuzz
#            (clang 18, -fsanitize=address,fuzzer-no-link, no-asm)
#   awslc:   aws-lc-sys 0.41.0 (AWS-LC 1.73.0) compiled by clang 18 with the
#            same flags through CC/CFLAGS (its assembly stays uninstrumented)
# Toolchain: the nightly in $SCRATCH/rustup (rustc 1.100.0-nightly
# 2026-09-25), cargo-fuzz installed into $SCRATCH/cargo198.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
FZ="$SCRATCH/fu/fuzz"; mkdir -p "$FZ"
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$SCRATCH/cargo198" RUSTUP_TOOLCHAIN=nightly
export PATH="$CARGO_HOME/bin:$PATH"
case "$1" in
seeds)
  # Every receipt (DER) and JWS input of the five corpora, one file each.
  rm -rf "$FZ/seeds-receipt" "$FZ/seeds-jws"; mkdir -p "$FZ/seeds-receipt" "$FZ/seeds-jws"
  python3 - "$CORPORA" "$FZ" <<'EOF'
import base64, binascii, hashlib, json, sys
corpora, out = sys.argv[1], sys.argv[2]
n = {"receipt": 0, "jws": 0}
for c in ["cases", "substrate", "hostile", "algorithms", "fuzz"]:
    for line in open(f"{corpora}/{c}.jsonl", encoding="utf-8"):
        r = json.loads(line)
        data = base64.b64decode(r["input"])
        if r["kind"] == "receipt":
            if r.get("base64"):
                try:
                    data = base64.b64decode(data, validate=False)
                except (binascii.Error, ValueError):
                    continue
            kind = "receipt"
        elif r["kind"] == "jws":
            kind = "jws"
        else:
            continue
        name = hashlib.sha1(data).hexdigest()
        open(f"{out}/seeds-{kind}/{name}", "wb").write(data)
        n[kind] += 1
print(n)
EOF
  echo "unique seeds: receipt $(ls "$FZ/seeds-receipt" | wc -l), jws $(ls "$FZ/seeds-jws" | wc -l)"
  ;;
build)
  NAME="$2"; LIB="$3"
  TREE="$SCRATCH/tree-fuzz-$NAME"
  rm -rf "$TREE"; mkdir -p "$TREE/rust" "$TREE/fixtures"
  tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$TREE/rust" -xf -
  cp -r "$REPO/fixtures/generated" "$TREE/fixtures/"
  cp "$REPO/version.txt" "$TREE/"
  cp "$SPIKE/core-patch/substrate.rs" "$TREE/rust/src/substrate.rs"
  sed "s#@SPIKE@#$SPIKE#" "$SPIKE/core-patch/core.patch" | patch -s -d "$TREE/rust" -p1
  if [ "$LIB" = openssl ]; then F=substrate; else F=substrate-aws-lc; fi
  sed -i "s#^\[dependencies.apple-purchase-receipt-verifier\]#&\nfeatures = [\"$F\"]#" "$TREE/rust/fuzz/Cargo.toml"
  grep -n -A2 'dependencies.apple-purchase-receipt-verifier' "$TREE/rust/fuzz/Cargo.toml"
  cd "$TREE/rust"
  if [ "$LIB" = openssl ]; then
    OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2-fuzz" OPENSSL_STATIC=1 \
      cargo fuzz build --sanitizer address --target-dir "$SCRATCH/target-fuzz-$NAME" verify-receipt
    OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2-fuzz" OPENSSL_STATIC=1 \
      cargo fuzz build --sanitizer address --target-dir "$SCRATCH/target-fuzz-$NAME" verify-transaction
  else
    S="-fsanitize=address,fuzzer-no-link -fno-omit-frame-pointer -g"
    CC=clang CXX=clang++ CFLAGS="$S" CXXFLAGS="$S" \
      cargo fuzz build --sanitizer address --target-dir "$SCRATCH/target-fuzz-$NAME" verify-receipt
    CC=clang CXX=clang++ CFLAGS="$S" CXXFLAGS="$S" \
      cargo fuzz build --sanitizer address --target-dir "$SCRATCH/target-fuzz-$NAME" verify-transaction
  fi
  cp "$TREE/rust/fuzz/Cargo.lock" "$FZ/$NAME.Cargo.lock"
  ls -l "$SCRATCH/target-fuzz-$NAME/x86_64-unknown-linux-gnu/release/" | grep -E ' verify-'
  ;;
run)
  NAME="$2"; T="$3"; SECS="$4"
  case "$T" in verify-receipt) SEEDS="$FZ/seeds-receipt" ;; verify-transaction) SEEDS="$FZ/seeds-jws" ;; esac
  BIN="$SCRATCH/target-fuzz-$NAME/x86_64-unknown-linux-gnu/release/$T"
  C="$FZ/corpus-$NAME-$T"; A="$FZ/artifacts-$NAME-$T"; mkdir -p "$C" "$A"
  # One process, one core. Seeds are read, new units go to $C only.
  # -timeout: any input running over 10 s is reported as a timeout;
  # -rss_limit_mb: over 2 GB is reported as an OOM. Leak detection on.
  ASAN_OPTIONS=detect_leaks=1:allocator_may_return_null=0 \
    "$BIN" "$C" "$SEEDS" -max_total_time="$SECS" -timeout=10 -rss_limit_mb=2048 \
    -max_len=65536 -print_final_stats=1 -artifact_prefix="$A/" \
    > "$FZ/log-$NAME-$T.txt" 2>&1 || echo "exit $?" >> "$FZ/log-$NAME-$T.txt"
  ;;
esac
