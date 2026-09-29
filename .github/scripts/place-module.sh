#!/usr/bin/env bash
# Puts the module rust-wasm built from this tree where a host package reads
# it, and writes that build's hash into the host's tracked pin.
#
#   place-module.sh <artifact-dir> <host>...
#
# <artifact-dir> is the downloaded `aprv-wasm` artifact (aprv.wasm,
# aprv.component.wasm, aprv.wit, SHA256SUMS); every file is checked against
# its SHA256SUMS first. <host> is one of go, swift, python, ruby, dotnet,
# java, node (node takes the component, every other host the core module).
#
# No host commits the module (only Go and Swift will, once, at integration:
# DECISIONS.md R14), so a CI checkout has none until this runs. The pins
# (`aprv.wasm.sha256`, Node's `aprv.component.wasm.sha256`) are tracked and
# lag the core between releases, the same way the committed copies do
# (`wasm-copies`); a job tests the module this tree builds, so the pin is
# rewritten in the checkout and a difference is reported as a warning.
# release-please.yml rewrites the tracked pins on the release branch.
#
# Nothing here reads the module's contents beyond hashing it: every host
# checks the pair again itself when it loads the module.
set -euo pipefail

if [[ $# -lt 2 ]]; then
  echo "usage: $0 <artifact-dir> <host>..." >&2
  exit 2
fi
src="$1"
shift
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

# Hashes stdin rather than a named file: GNU sha256sum escapes a name that
# holds a backslash (every Windows path) by prefixing the line with one.
sha256() {
  if command -v sha256sum > /dev/null 2>&1; then
    sha256sum < "$1" | cut -c1-64
  else
    shasum -a 256 < "$1" | cut -c1-64
  fi
}

# The artifact against its own SHA256SUMS.
while read -r want name; do
  [[ -n "$name" ]] || continue
  name="${name#\*}"
  got="$(sha256 "$src/$name")"
  if [[ "$got" != "$want" ]]; then
    echo "place-module: $src/$name is $got, its SHA256SUMS says $want" >&2
    exit 1
  fi
done < "$src/SHA256SUMS"

for host in "$@"; do
  file=aprv.wasm
  case "$host" in
    go) dir=go/internal/wasm ;;
    swift) dir=swift/Sources/ApplePurchaseReceiptVerifier/Resources ;;
    python) dir=python/apple_purchase_receipt_verifier ;;
    ruby) dir=ruby/lib/apple_purchase_receipt_verifier ;;
    dotnet) dir=dotnet/src/ApplePurchaseReceiptVerifier/wasm ;;
    java) dir=java-wasm/src/main/wasm ;;
    node) dir=node/wasm file=aprv.component.wasm ;;
    *) echo "place-module: unknown host $host" >&2; exit 2 ;;
  esac
  mkdir -p "$repo/$dir"
  cp "$src/$file" "$repo/$dir/$file"
  hash="$(sha256 "$repo/$dir/$file")"
  pin="$repo/$dir/$file.sha256"
  tracked=""
  if [[ -f "$pin" ]]; then tracked="$(cut -c1-64 "$pin")"; fi
  if [[ "$tracked" != "$hash" ]]; then
    echo "::warning file=$dir/$file.sha256::$dir/$file.sha256 pins ${tracked:-nothing}; this tree builds $hash, so the job tests that (release-please.yml rewrites the pin on the release branch)"
  fi
  printf '%s  %s\n' "$hash" "$file" > "$pin"
  echo "place-module: $dir/$file is $hash"
done
