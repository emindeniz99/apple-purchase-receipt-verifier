#!/bin/sh
# Rebuilds the previous bake-off's native C ABI variants in $SCRATCH and runs
# the four request corpora through each, so every wasm build below can be
# compared with the native build of the SAME backend. Reuses the previous
# bake-off's scripts unchanged ($SPIKE); nothing new about the natives.
#
#   REPO=... SCRATCH=... CORPORA=... scripts/native-baseline.sh
#
# Output: $SCRATCH/run/<variant>-<corpus>.jsonl for rust, ossl402,
# libressl432 and awslc; $SCRATCH/inst/{openssl-4.0.2,libressl-4.3.2}.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
PREVPY="$REPO/docs/evidence/2026-09-25-java-native-image-spike/py"
"$SPIKE/scripts/build-variant.sh" rust ""
"$SPIKE/scripts/build-libs.sh" openssl
OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" ossl402 substrate
"$SPIKE/scripts/build-libs.sh" libressl
OPENSSL_DIR="$SCRATCH/inst/libressl-4.3.2" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" libressl432 substrate
"$SPIKE/scripts/build-variant.sh" awslc substrate-aws-lc
mkdir -p "$SCRATCH/run"
for v in rust ossl402 libressl432 awslc; do
  for c in cases hostile algorithms substrate; do
    python3 "$PREVPY/run_rust.py" "$REPO" "$SCRATCH/target-$v/release" "$CORPORA/$c.jsonl" > "$SCRATCH/run/$v-$c.jsonl"
  done
done
