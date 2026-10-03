#!/bin/sh
# Counts the fixture DER receipts the Rust core verifies under the anchor
# set PHP's verify-receipt fuzz target builds: Apple's three roots plus one
# fixture receipt root, once with the 0.6 root and once with the 0.7 root.
#
#   sh count-core.sh <repo> <scratch>
#
# PHP reaches the core through aprv-server, which this measurement did not
# build. It runs tools/private-receipt-check.mjs instead, over the module
# the Go package commits, both taken from commit e9cff0e, where the tool
# and the module agree on the WIT names (aprv:verifier@1.0.0). The tool
# prints one verdict per file, numbered by the sorted listing; this script
# maps the verified numbers back to file names.
set -eu

repo=$1
scratch=$2
rev=e9cff0e

mkdir -p "$scratch/tool/tools"
git -C "$repo" show "$rev:tools/private-receipt-check.mjs" > "$scratch/tool/tools/private-receipt-check.mjs"
git -C "$repo" show "$rev:go/internal/wasm/aprv.wasm" > "$scratch/aprv.wasm"
sha256sum "$scratch/aprv.wasm" | cut -d' ' -f1

# The tool refuses a directory inside the repository, so the seeds are copied.
for set in generated generated-0.7; do
  mkdir -p "$scratch/seeds/$set"
  cp "$repo/fixtures/$set"/*.der "$scratch/seeds/$set/"
done

for root in generated/receipt-root.der generated-0.7/receipt-root.der; do
  echo "== Apple roots + $root"
  for set in generated generated-0.7; do
    dir="$scratch/seeds/$set"
    out="$scratch/out.txt"
    node "$scratch/tool/tools/private-receipt-check.mjs" "$dir" --module "$scratch/aprv.wasm" \
      --root "$repo/certs/AppleIncRootCertificate.cer" \
      --root "$repo/certs/AppleRootCA-G2.cer" \
      --root "$repo/certs/AppleRootCA-G3.cer" \
      --root "$repo/fixtures/$root" > "$out"
    echo "fixtures/$set/*.der: $(tail -n 1 "$out")"
    grep '^#[0-9]* receipt verified' "$out" | sed 's/^#\([0-9]*\) .*/\1/' | while read -r n; do
      echo "    $(find "$dir" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort | sed -n "${n}p")"
    done
  done
done
