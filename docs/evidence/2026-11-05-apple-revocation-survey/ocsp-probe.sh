#!/usr/bin/env bash
# Asks Apple's OCSP responder about the WWDR G6 intermediate, three ways:
# without a nonce, with one, and with a SHA-256 CertID. Prints the
# responder, the response's producedAt, thisUpdate and nextUpdate.
# openssl writes each request and curl posts it, so an HTTP proxy that
# refuses openssl's own client still works.
#
# Usage: REPO=/path/to/repo SCRATCH=/some/dir bash ocsp-probe.sh
set -euo pipefail
: "${REPO:?set REPO to the repository root}"
: "${SCRATCH:?set SCRATCH to a directory outside the repository}"
out="$SCRATCH/ocsp"
mkdir -p "$out"
openssl x509 -inform DER -in "$REPO/certs/AppleRootCA-G3.cer" -out "$out/g3.pem"
openssl x509 -inform DER -in "$REPO/certs/revocation-issuers/AppleWWDRCAG6.cer" -out "$out/g6.pem"
url=$(openssl x509 -in "$out/g6.pem" -noout -ocsp_uri)
echo "responder URL from WWDR G6's AIA: $url"

probe() {
  label=$1; shift
  echo "== $label"
  # The digest option must come before -cert.
  openssl ocsp "$@" -issuer "$out/g3.pem" -cert "$out/g6.pem" -reqout "$out/req-$label.der" > /dev/null
  curl -sS --data-binary "@$out/req-$label.der" -H 'Content-Type: application/ocsp-request' \
    -o "$out/resp-$label.der" "$url"
  echo "   now: $(date -u '+%b %e %H:%M:%S %Y GMT')"
  openssl ocsp -respin "$out/resp-$label.der" -noverify -resp_text 2>&1 \
    | grep -E 'Responder Id|Produced At|This Update|Next Update|Cert Status|Hash Algorithm|Nonce' || true
}
probe no_nonce -no_nonce
probe nonce
probe sha256 -sha256 -no_nonce
