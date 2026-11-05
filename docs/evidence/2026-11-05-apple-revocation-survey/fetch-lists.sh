#!/usr/bin/env bash
# Downloads every Apple revocation list the survey looked at into
# $SCRATCH/crls and prints, per URL: the HTTP status, Cache-Control, size,
# SHA-256 and, for a DER list, the header fields of `openssl crl -text`.
# The full text dump of each list goes beside it as <name>.txt.
#
# Usage: SCRATCH=/some/dir bash fetch-lists.sh
# Add G1=1 to also fetch the frozen 2.3 MB WWDR G1 list (its dump is about
# 10 MB, so the survey keeps only its numbers).
set -euo pipefail
: "${SCRATCH:?set SCRATCH to a directory outside the repository}"
out="$SCRATCH/crls"
mkdir -p "$out"

urls=(
  # The four lists the built-in file tracks (certs/revocations.json).
  http://crl.apple.com/root.crl
  http://crl.apple.com/applerootcag3.crl
  http://crl.apple.com/wwdrg5.crl
  http://crl.apple.com/wwdrg6.crl
  # The same four over HTTPS (answered 404 on 2026-11-05).
  https://crl.apple.com/root.crl
  https://crl.apple.com/applerootcag3.crl
  https://crl.apple.com/wwdrg5.crl
  https://crl.apple.com/wwdrg6.crl
  # WWDR G3 and G4 carry the WWDR marker but have no list (404).
  http://crl.apple.com/wwdrg3.crl
  http://crl.apple.com/wwdrg4.crl
  # Linked from https://www.apple.com/certificateauthority/: a stale Apple
  # Root CA list and a list under Apple Root CA's retired name.
  https://www.apple.com/appleca/root.crl
  https://www.apple.com/certificateauthority/root.crl
)
if [ "${G1:-}" = 1 ]; then
  urls+=(http://developer.apple.com/certificationauthority/wwdrca.crl)
fi

for url in "${urls[@]}"; do
  name=$(printf '%s' "$url" | sed -E 's#^https?://##; s#/#_#g')
  scheme=${url%%:*}
  file="$out/$scheme-$name"
  status=$(curl -sS -L -o "$file" -D "$file.hdr" -w '%{http_code}' "$url" || echo ERR)
  cache=$(grep -i '^cache-control:' "$file.hdr" | tail -1 | tr -d '\r' || true)
  echo "== $url"
  echo "   status $status, $(wc -c < "$file") bytes, sha256 $(sha256sum < "$file" | cut -c1-64), ${cache:-no cache-control}"
  if [ "$status" = 200 ] && openssl crl -inform DER -in "$file" -noout 2>/dev/null; then
    openssl crl -inform DER -in "$file" -noout -text > "$file.txt"
    echo "   entries $(grep -c 'Serial Number' "$file.txt" || true)"
    openssl crl -inform DER -in "$file" -noout -text \
      | sed -n '1,/Revoked Certificates/p' \
      | grep -E 'Signature Algorithm|Issuer:|Last Update|Next Update' || true
    openssl crl -inform DER -in "$file" -noout -text \
      | grep -A1 -E 'CRL Number|Issuing Distribution|Delta CRL|2\.5\.29\.60' | sed 's/^/   /' || true
  fi
done
