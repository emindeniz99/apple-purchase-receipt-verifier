#!/bin/sh
# Task 2 (compiler): rebuilds the native C ABI and the Route C (freestanding)
# modules for OpenSSL 4.0.2 and AWS-LC 1.73.0 with rustc 1.98.1, installed
# under $SCRATCH (RUSTUP_HOME/CARGO_HOME there; the system toolchain is not
# touched), through the two bake-offs' build scripts, unchanged. Same
# Cargo.lock (the scripts copy rust/ffi/Cargo.lock), same C libraries, so
# only the Rust compiler differs. Then runs all 1,179 rows and compares
# them with the rustc 1.94.1 builds.
#   RUSTUP_HOME=$SCRATCH/rustup rustup toolchain install 1.98.1 --profile minimal --target wasm32-wasip1
#   scripts/rust198.sh build | run
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
FU="$REPO/docs/evidence/2026-09-26-substrate-followup"
PREVPY="$REPO/docs/evidence/2026-09-25-java-native-image-spike/py"
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$SCRATCH/cargo198" RUSTUP_TOOLCHAIN=1.98.1
A="$SCRATCH/fu/art"; R="$SCRATCH/fu/run"; mkdir -p "$A" "$R"
case "$1" in
build)
  rustc -vV
  OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" ossl402-r198 substrate
  cp "$SCRATCH/target-ossl402-r198/release/libapple_purchase_receipt_verifier_ffi.so" "$A/ossl402-r198.so"
  "$SPIKE/scripts/build-variant.sh" awslc-r198 substrate-aws-lc
  cp "$SCRATCH/target-awslc-r198/release/libapple_purchase_receipt_verifier_ffi.so" "$A/awslc-r198.so"
  STUB_WASI=1 HOST_CLOCK=1 "$PREV/scripts/build-wasip1.sh" awslc-c-r198 awslc
  cp "$SCRATCH/target-awslc-c-r198/wasm32-wasip1/release/aprv_wasm_shim.wasm" "$A/awslc-c-r198.wasm"
  STUB_WASI=1 STUB_CFLAGS=-DAPRV_HOST_RANDOM HOST_CLOCK=1 "$PREV/scripts/build-wasip1.sh" ossl-c-r198 openssl
  cp "$SCRATCH/target-ossl-c-r198/wasm32-wasip1/release/aprv_wasm_shim.wasm" "$A/ossl-c-r198.wasm"
  ;;
run)
  for v in ossl402 awslc; do
    for c in cases hostile algorithms substrate; do
      python3 "$PREVPY/run_rust.py" "$REPO" "$SCRATCH/target-$v-r198/release" "$CORPORA/$c.jsonl" > "$R/$v-r198-$c.jsonl"
      res=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$SCRATCH/run/$v-$c.jsonl" "$R/$v-r198-$c.jsonl" 2>&1 | tail -1)
      echo "$v-r198 native $c vs $v (rustc 1.94.1): $res" | tee -a "$FU/results/parity.txt"
    done
  done
  "$FU/scripts/parity.sh" awslc-c-r198 awslc node strict "$A/awslc-c-r198.wasm"
  "$FU/scripts/parity.sh" ossl-c-r198 ossl402 node trap "$A/ossl-c-r198.wasm"
  REFDIR="$R" "$FU/scripts/parity.sh" awslc-c-r198-vs-r198 awslc-r198 node strict "$A/awslc-c-r198.wasm"
  REFDIR="$R" "$FU/scripts/parity.sh" ossl-c-r198-vs-r198 ossl402-r198 node trap "$A/ossl-c-r198.wasm"
  ;;
esac
