#!/bin/sh
# Writes the roots files the harness reads into "$1" (a directory outside
# the repository). Run from the repository root.
set -eu
out=$1
mkdir -p "$out"
f=fixtures/apple-official/certs

# Files that read: the three Apple roots as PEM (LF and CRLF), as base64
# lines, one indented block, a block with a blank line in its body, a file
# mixing comments, a base64 line, a PEM block and a base64 line of PEM bytes,
# and Apple's test PKI files as they stand in fixtures/.
for c in certs/*; do openssl x509 -inform DER -in "$c" -outform PEM; done > "$out/apple-bundle.pem"
sed 's/$/\r/' "$out/apple-bundle.pem" > "$out/apple-bundle-crlf.pem"
for c in certs/*; do base64 -w0 "$c"; echo; done > "$out/apple-lines.txt"
printf '  -----BEGIN CERTIFICATE-----  \n%s\n  -----END CERTIFICATE-----\n' \
  "$(base64 -w 64 certs/AppleRootCA-G2.cer)" > "$out/indented.pem"
printf -- '-----BEGIN CERTIFICATE-----\nAQ\n\nID\n-----END CERTIFICATE-----\n' > "$out/blank-in-block.pem"
{ echo "# mixed"; echo; base64 -w0 certs/AppleRootCA-G3.cer; echo; cat "$f/testCA.pem"; base64 -w0 "$f/testCA.pem"; echo; } > "$out/mixed.txt"
cp "$f"/*.pem "$out/"
cat "$f"/*.pem > "$out/fixtures-bundle.pem"

# Files that are refused.
printf '# nothing\n' > "$out/bad-empty.txt"
printf 'not base64!\n' > "$out/bad-b64.txt"
printf -- '-----BEGIN CERTIFICATE-----\nAQID\n' > "$out/bad-noend.pem"
printf -- '-----BEGIN PRIVATE KEY-----\nAQID\n-----END PRIVATE KEY-----\n' > "$out/bad-key.pem"
printf -- '-----BEGIN CERTIFICATE-----\nAQID\n-----END X509 CRL-----\n' > "$out/bad-mismatch.pem"
printf -- '-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n' > "$out/bad-emptyblock.pem"
printf -- '-----BEGIN CERTIFICATE-----\nAQ!D\n-----END CERTIFICATE-----\n' > "$out/bad-body.pem"
printf -- '-----BEGIN CERTIFICATE-----\nAQ ID\n-----END CERTIFICATE-----\n' > "$out/bad-space-in-body.pem"
printf -- '-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----AQID\n' > "$out/bad-trail.pem"
printf -- '-----BEGIN CERTIFICATE-----AQID\nAQID\n-----END CERTIFICATE-----\n' > "$out/bad-trail-begin.pem"
printf -- '-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----x-----\n' > "$out/bad-trail-dashes.pem"
printf -- '-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE----------\n' > "$out/bad-ten-dashes.pem"
printf -- '-----END CERTIFICATE-----\n' > "$out/bad-stray.pem"
printf -- '-----\n' > "$out/bad-dashes.pem"
printf -- '-----BEGIN CERTIFICATE-----\nAQID\n-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n' > "$out/bad-nested.pem"
printf -- '-----BEGIN CERTIFICATE-----\nProc-Type:4,ENCRYPTED\n\nAQID\n-----END CERTIFICATE-----\n' > "$out/bad-header.pem"
printf -- '-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\n\nAQID\n-----END CERTIFICATE-----\n' > "$out/bad-header-space.pem"
printf -- '-----BEGIN CERTIFICATE-----\n# c\nAQID\n-----END CERTIFICATE-----\n' > "$out/bad-comment-in-block.pem"
