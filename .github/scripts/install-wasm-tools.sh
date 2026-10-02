#!/usr/bin/env bash
# Installs wasm-tools from its GitHub release for the CI jobs that read a
# component back or assemble one (rust-wasm-checks, aprv-server-linux).
#
#   install-wasm-tools.sh <dir>     puts wasm-tools in <dir>
#
# The URL and SHA-256 are read from tools/wasm-toolchain.sh, the one pin the
# module build uses too, so a new wasm-tools release changes one file.
set -euo pipefail

if [[ $# -ne 1 || -z "$1" ]]; then
  echo "usage: $0 <dir>" >&2
  exit 2
fi
if [[ "$(uname -s)-$(uname -m)" != Linux-x86_64 ]]; then
  echo "install-wasm-tools: the pin is for x86_64-linux only" >&2
  exit 1
fi
toolchain="$(dirname "${BASH_SOURCE[0]}")/../../tools/wasm-toolchain.sh"
pin() { sed -n "s/^$1=\(.*\)$/\1/p" "$toolchain"; }
url="$(pin WASM_TOOLS_URL)"
sha256="$(pin WASM_TOOLS_SHA256)"
if [[ -z "$url" || -z "$sha256" ]]; then
  echo "install-wasm-tools: no WASM_TOOLS_URL or WASM_TOOLS_SHA256 in $toolchain" >&2
  exit 1
fi
mkdir -p "$1"
dir="$(cd "$1" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL --retry 4 --retry-delay 2 -o "$work/wasm-tools.tar.gz" "$url"
echo "$sha256  $work/wasm-tools.tar.gz" | sha256sum -c - > /dev/null
tar -C "$dir" --strip-components=1 -xzf "$work/wasm-tools.tar.gz"
echo "install-wasm-tools: $("$dir/wasm-tools" --version) in $dir" >&2
