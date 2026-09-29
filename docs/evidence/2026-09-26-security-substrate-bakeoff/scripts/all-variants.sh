#!/bin/sh
# Builds every native variant one after the other (one heavy build at a
# time) and runs every corpus through each. Needs the static libraries from
# build-libs.sh and the corpora described in README.md.
#
#   REPO=... SCRATCH=... CORPORA=... scripts/all-variants.sh [variant ...]
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
[ $# -gt 0 ] || set -- rust ossl402 ossl402pre ossl402a1 libressl432 libressl432a1 awslc awslca1 ossl36v
for v in "$@"; do
  case "$v" in
    rust)          env -u OPENSSL_DIR "$SPIKE/scripts/build-variant.sh" rust "" ;;
    ossl402)       OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" "$v" substrate ;;
    ossl402pre)    OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" "$v" substrate,substrate-prescan ;;
    ossl402a1)     OPENSSL_DIR="$SCRATCH/inst/openssl-4.0.2" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" "$v" substrate,substrate-a1 ;;
    libressl432)   OPENSSL_DIR="$SCRATCH/inst/libressl-4.3.2" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" "$v" substrate ;;
    libressl432a1) OPENSSL_DIR="$SCRATCH/inst/libressl-4.3.2" OPENSSL_STATIC=1 "$SPIKE/scripts/build-variant.sh" "$v" substrate,substrate-a1 ;;
    awslc)         "$SPIKE/scripts/build-variant.sh" "$v" substrate-aws-lc ;;
    awslca1)       "$SPIKE/scripts/build-variant.sh" "$v" substrate-aws-lc,substrate-a1 ;;
    ossl36v)       "$SPIKE/scripts/build-variant.sh" "$v" substrate-vendored ;;
    *) echo "unknown variant $v" >&2; exit 2 ;;
  esac
  "$SPIKE/scripts/run-corpora.sh" "$v" cases hostile algorithms substrate
done
