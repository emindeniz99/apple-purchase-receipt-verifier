#!/usr/bin/env bash
# Checks the signature of each list fetch-lists.sh downloaded against the
# Apple certificate that should have signed it, from the repository.
#
# Usage: REPO=/path/to/repo SCRATCH=/some/dir bash verify-lists.sh
set -euo pipefail
: "${REPO:?set REPO to the repository root}"
: "${SCRATCH:?set SCRATCH to the directory fetch-lists.sh used}"
in="$SCRATCH/crls"
pem="$SCRATCH/issuers"
mkdir -p "$pem"

issuer_of() {
  case "$1" in
    *crl.apple.com_root.crl|*appleca_root.crl|*certificateauthority_root.crl)
      echo "$REPO/certs/AppleIncRootCertificate.cer" ;;
    *applerootcag3.crl) echo "$REPO/certs/AppleRootCA-G3.cer" ;;
    *wwdrg5.crl) echo "$REPO/certs/revocation-issuers/AppleWWDRCAG5.cer" ;;
    *wwdrg6.crl) echo "$REPO/certs/revocation-issuers/AppleWWDRCAG6.cer" ;;
  esac
}

for list in "$in"/http*-*.crl; do
  cer=$(issuer_of "$list")
  [ -n "$cer" ] || continue
  openssl crl -inform DER -in "$list" -noout 2>/dev/null || continue
  p="$pem/$(basename "$cer" .cer).pem"
  openssl x509 -inform DER -in "$cer" -out "$p"
  printf '%s against %s: ' "$(basename "$list")" "$(basename "$cer")"
  # `openssl crl -verify` also matches the list's issuer Name against the
  # certificate's subject, so the retired-name list fails here although
  # Apple Root CA's key signed it; the fixture README under
  # fixtures/apple-crls/ checks that one over its TBSCertList instead.
  openssl crl -inform DER -in "$list" -CAfile "$p" -noout -verify 2>&1 | tail -1 || true
done
