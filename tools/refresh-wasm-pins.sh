#!/usr/bin/env bash
# Makes every committed copy of aprv.wasm and every tracked pin of it name
# one build of the module:
#
#   tools/refresh-wasm-pins.sh <aprv.wasm> <aprv.component.wasm>
#
# run from the repository root (release-please.yml's refresh job, on the
# release branch). Writes, for the files git tracks:
#
#   */aprv.wasm                    the module itself (Go's and Swift's
#                                  committed copies, DECISIONS.md R14)
#   */aprv.wasm.sha256             "<sha256>  aprv.wasm" (Go, Swift, Java,
#                                  Python, Ruby, .NET)
#   */aprv.component.wasm.sha256   "<sha256>  aprv.component.wasm" (Node,
#                                  whose build transpiles the component)
#
# and prints each path it changed, one per line, on stdout (nothing when
# every file already names this build). A committed copy is then checked
# against its own pin, the pair each package verifies when it loads the
# module. Needs git and sha256sum; reads nothing but the two files and the
# index.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <aprv.wasm> <aprv.component.wasm>" >&2
  exit 2
fi
module="$1"
component="$2"
wasm_sha="$(sha256sum "$module" | cut -c1-64)"
component_sha="$(sha256sum "$component" | cut -c1-64)"
echo "refresh-wasm-pins: aprv.wasm $wasm_sha, aprv.component.wasm $component_sha" >&2

changed=()
write_if_different() { # path content
  if [[ ! -f "$1" ]] || [[ "$(cat "$1")" != "$2" ]]; then
    printf '%s\n' "$2" > "$1"
    changed+=("$1")
  fi
}

while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  if ! cmp -s "$module" "$f"; then
    cp "$module" "$f"
    changed+=("$f")
  fi
done < <(git ls-files -- '*aprv.wasm')

while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  write_if_different "$f" "$wasm_sha  aprv.wasm"
done < <(git ls-files -- '*aprv.wasm.sha256')

while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  write_if_different "$f" "$component_sha  aprv.component.wasm"
done < <(git ls-files -- '*aprv.component.wasm.sha256')

while IFS= read -r f; do
  [[ -n "$f" ]] || continue
  (cd "$(dirname "$f")" && sha256sum -c --quiet aprv.wasm.sha256) >&2
done < <(git ls-files -- '*aprv.wasm')

if [[ ${#changed[@]} -gt 0 ]]; then
  printf '%s\n' "${changed[@]}"
fi
echo "refresh-wasm-pins: ${#changed[@]} file(s) changed" >&2
