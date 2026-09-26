#!/bin/sh
# Regenerates results/loc.txt with py/loc.py (relative paths only).
#
#   REPO=... scripts/loc.sh
set -eu
: "${REPO:?}"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
{
  echo "## current custom security code (rust/src)"
  (cd "$REPO" && python3 "$SPIKE/py/loc.py" rust/src/asn1.rs rust/src/cms.rs rust/src/x509.rs rust/src/chain.rs rust/src/crypto.rs)
  echo
  echo "## current policy files that call it"
  (cd "$REPO" && python3 "$SPIKE/py/loc.py" rust/src/receipt.rs rust/src/jws.rs rust/src/roots.rs rust/src/receipt_payload.rs)
  echo
  echo "## spike: adapter (the only crate with unsafe code) and policy over it"
  (cd "$SPIKE" && python3 py/loc.py security-openssl/src/lib.rs security-openssl/build.rs core-patch/substrate.rs)
  echo
  echo "## spike: wasm shim (host-facing alloc/dealloc only)"
  (cd "$SPIKE" && python3 py/loc.py wasm/shim/src/lib.rs)
} > "$SPIKE/results/loc.txt"
cat "$SPIKE/results/loc.txt"
