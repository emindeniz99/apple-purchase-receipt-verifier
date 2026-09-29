#!/bin/sh
# Task 6: lines, unsafe and C before (the repository's pure-Rust security
# path) and after (the no-asn1 tree: adapter + policy + payload), with
# py/loc.py. The no-asn1 tree and adapter copy come from build.sh native-new.
#   scripts/loc.sh > results/loc.txt
set -eu
. "$(dirname "$0")/env.sh"
L="$EV/py/loc.py"; R="$REPO/rust/src"; T="$SCRATCH/tree-new/rust/src"; A="$C/adapter-new/security-openssl/src"
python3 "$L" "before: repository, pure Rust" "$R/asn1.rs" "$R/x509.rs" "$R/cms.rs" "$R/crypto.rs" "$R/chain.rs" \
  "$R/receipt_payload.rs" "$R/receipt.rs" "$R/jws.rs" "$R/roots.rs"
python3 "$L" "after: no-asn1 tree, templates (a)" "$A/lib.rs" "$A/cms_path.rs" "$A/payload.rs" "$A/payload_templates.rs" \
  "$A/payload.c" "$T/substrate.rs" "$T/receipt_payload.rs" "$T/receipt.rs" "$T/jws.rs" "$T/roots.rs"
python3 "$L" "after: no-asn1 tree, payload-any (b)" "$A/lib.rs" "$A/cms_path.rs" "$A/payload.rs" "$A/payload_any.rs" \
  "$T/substrate.rs" "$T/receipt_payload.rs" "$T/receipt.rs" "$T/jws.rs" "$T/roots.rs"
python3 "$L" "payload only, before" "$R/asn1.rs" "$R/receipt_payload.rs"
python3 "$L" "payload only, after (a)" "$A/payload.rs" "$A/payload_templates.rs" "$A/payload.c" "$T/receipt_payload.rs"
python3 "$L" "payload only, after (b)" "$A/payload.rs" "$A/payload_any.rs" "$T/receipt_payload.rs"
O="$(find "$SCRATCH/cargo198/registry/src" -maxdepth 1 -name 'index.crates.io-*' | head -1)/openssl-src-400.0.1+4.0.2/openssl"
echo "# for scale, not ours: OpenSSL 4.0.2 crypto/asn1/*.c, $(cat "$O"/crypto/asn1/*.c | wc -l) lines in $(ls "$O"/crypto/asn1/*.c | wc -l) files (the template decoder tasn_dec.c: $(wc -l < "$O/crypto/asn1/tasn_dec.c"))"
