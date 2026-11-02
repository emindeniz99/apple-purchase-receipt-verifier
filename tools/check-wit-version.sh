#!/usr/bin/env bash
# Fails when the WIT's interface changed but its package version did not.
#
#   tools/check-wit-version.sh <base.wit> <head.wit>
#
# A name or a type in rust/bindings/abi/wit/aprv.wit is the ABI: every
# host binds the export names, which carry the package version, so such a
# change must move the version (and every wrapper with it, AGENTS.md). A
# doc-comment-only edit changes nothing a host binds and needs no new
# version. This script tells the two apart: when both files name the same
# `package` line, it renders each with `wasm-tools component wit` (which
# normalises layout), drops the `///` doc lines, and requires the rest to be
# identical. When the package lines differ, the version moved and the
# interface may change freely. Needs wasm-tools on PATH. Exit status: 0 on
# a pass, 1 on an interface change without a version change, 2 on a usage
# error.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <base.wit> <head.wit>" >&2
  exit 2
fi
base="$1"
head="$2"

package() { # file -> its `package` line
  grep -m1 -E '^[[:space:]]*package[[:space:]]' "$1" || true
}
base_package="$(package "$base")"
head_package="$(package "$head")"
if [[ -z "$head_package" ]]; then
  echo "check-wit-version: $head has no package line" >&2
  exit 2
fi
if [[ "$base_package" != "$head_package" ]]; then
  echo "check-wit-version: the package moved (${base_package:-none} -> $head_package); the interface may change"
  exit 0
fi

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
render() { # wit file -> its rendering without doc lines
  wasm-tools component wit "$1" | grep -v -E '^[[:space:]]*///' || true
}
render "$base" > "$work/base"
render "$head" > "$work/head"
if ! diff -u "$work/base" "$work/head" > "$work/diff"; then
  echo "::error file=$head::the WIT's interface changed but its package line ($head_package) did not. A name or a type is the ABI: move the package version and every wrapper with it (AGENTS.md); only a doc-comment-only edit keeps the version"
  cat "$work/diff"
  exit 1
fi
echo "check-wit-version: $head_package unchanged, and so is the interface (doc comments aside)"
