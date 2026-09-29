#!/bin/sh
# Fails when the committed header is not what cbindgen generates from
# src/lib.rs (DECISIONS.md R34): regenerates it into a temporary file with
# the pinned cbindgen and diffs.
#
#   rust/ffi/check-header.sh            from any directory
#
# Needs cbindgen 0.29.0 on PATH (`cargo install cbindgen --locked --version
# 0.29.0`); another version is refused rather than compared, since its
# formatting alone would differ.
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
want="cbindgen 0.29.0"
got="$(cbindgen --version 2>/dev/null || true)"
[ "$got" = "$want" ] || { echo "check-header: need $want on PATH, found '${got:-none}'" >&2; exit 2; }
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
(cd "$here" && cbindgen --quiet --config cbindgen.toml --crate apple-purchase-receipt-verifier-ffi --output "$tmp")
if ! diff -u "$here/include/apple_purchase_receipt_verifier.h" "$tmp"; then
  echo "check-header: include/apple_purchase_receipt_verifier.h is stale; regenerate it (rust/ffi/README.md)" >&2
  exit 1
fi
echo "check-header: the committed header is cbindgen's"
