#!/bin/bash -eu
# Draft of projects/apple-purchase-receipt-verifier/build.sh for
# google/oss-fuzz. Builds the five cargo-fuzz targets in rust/fuzz and
# gives each a seed corpus from the fixtures rust/fuzz/run.sh seeds it
# with. abi-call (rust/fuzz/abi) is left out; README.md says why.
#
# OSS-Fuzz's CC and CFLAGS carry the sanitizer and coverage flags, and
# openssl-src builds OpenSSL with them, so libFuzzer follows edges inside
# OpenSSL's CMS, X.509 and ASN.1 code as rust/fuzz/asan-openssl.sh does
# in the nightly job. --debug-assertions keeps the overflow checks and
# debug assertions the repository's own fuzz jobs run with.

repo="$SRC/apple-purchase-receipt-verifier"
fixtures="$repo/fixtures"
cd "$repo/rust/fuzz"
cargo fuzz build -O --debug-assertions

targets="verify-receipt verify-receipt-base64 verify-transaction endpoint-json ffi"
for target in $targets; do
  cp "target/x86_64-unknown-linux-gnu/release/$target" "$OUT/"
done

# One flat zip per target, each file named by its SHA-1 as libFuzzer names
# corpus units, so files of the same name in different directories do not
# collide.
seed() {
  local target="$1"
  shift
  local dir
  dir="$(mktemp -d)"
  find "$@" -type f -print0 | while IFS= read -r -d '' f; do
    cp "$f" "$dir/$(sha1sum < "$f" | cut -c1-40)"
  done
  (cd "$dir" && zip -q "$OUT/${target}_seed_corpus.zip" ./*)
  rm -rf "$dir"
}
seed verify-receipt "$fixtures/generated" "$fixtures/generated-0.7" "$fixtures/apple-official/certs"
seed verify-receipt-base64 "$fixtures/generated/receipt-b64" "$fixtures/public-receipts" "$fixtures/apple-official/xcode"
seed verify-transaction "$fixtures/generated" "$fixtures/apple-official/mock_signed_data" "$fixtures/apple-official/xcode"
seed endpoint-json "$repo/rust/fuzz/seeds/endpoint-json"
seed ffi "$fixtures/generated/receipt-b64" "$fixtures/generated" "$repo/rust/fuzz/seeds/endpoint-json"
