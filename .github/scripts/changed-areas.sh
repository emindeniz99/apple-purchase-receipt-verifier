#!/usr/bin/env bash
# Decide which ports' CI jobs a change needs.
#
#   changed-areas.sh <base-sha> <head-sha>
#   changed-areas.sh all            (or CHANGED_AREAS_ALL=1)
#
# Prints one `area=true|false` line per port to stdout, for $GITHUB_OUTPUT,
# and explains the decision on stderr.
#
# Classification is an allowlist: a path under a port's folder selects that
# port, a documentation path selects nothing, and ANY other path selects
# every port. A path this script does not know about may cost a slower run;
# it must never skip a test. A port's own README is under its folder, so it
# counts as that port: several jobs test README examples.
#
# Under rust/ the rule follows what ships from it (MIGRATION.md, "CI
# matrix"): the core, its OpenSSL adapter and the aprv.wasm bindings
# become the one module every host runs, so a change there selects every
# area; aprv-server (rust/server) is an area of its own; the C ABI, the
# fuzz targets, the tests, the examples and the crate's own docs select
# `rust` alone. java-wasm/ (the -wasm artifact) is part of `java`.
set -euo pipefail

AREAS=(java node python ruby php go rust swift dotnet server)
declare -A selected=()
for area in "${AREAS[@]}"; do selected[$area]=false; done

emit() {
  for area in "${AREAS[@]}"; do printf '%s=%s\n' "$area" "${selected[$area]}"; done
}

select_all() {
  for area in "${AREAS[@]}"; do selected[$area]=true; done
}

if [[ "${CHANGED_AREAS_ALL:-}" == "1" || "${1:-}" == "all" ]]; then
  echo "all mode: every area selected" >&2
  select_all
  emit
  exit 0
fi

if [[ $# -ne 2 ]]; then
  echo "usage: $0 <base-sha> <head-sha> | $0 all" >&2
  exit 2
fi

# Prints the area for a path, `docs` for documentation, or `all`.
classify() {
  case "$1" in
    java/* | java-wasm/* | java-bench/* | jvm-interop/*) echo java ;;
    node/*) echo node ;;
    python/*) echo python ;;
    ruby/*) echo ruby ;;
    php/* | composer.json) echo php ;;
    go/*) echo go ;;
    rust/server/*) echo server ;;
    rust/ffi/* | rust/fuzz/* | rust/tests/* | rust/examples/*) echo rust ;;
    rust/*/*) echo all ;;
    rust/*.md) echo rust ;;
    rust/*) echo all ;;
    swift/* | Package.swift | Package.resolved) echo swift ;;
    dotnet/*) echo dotnet ;;
    docs/* | .claude/* | .github/ISSUE_TEMPLATE/* | .github/PULL_REQUEST_TEMPLATE*) echo docs ;;
    .github/*/*) echo all ;;
    .github/*.md) echo docs ;;
    # case patterns let `*` cross `/`, so anything nested that got this far
    # is outside every folder above: fixtures/, certs/, tools/, ...
    */*) echo all ;;
    *.md | LICENSE) echo docs ;;  # root level only, CLAUDE.md included
    *) echo all ;;
  esac
}

files="$(git diff --no-renames --name-only "$1" "$2")"
count=0
while IFS= read -r path; do
  [[ -z "$path" ]] && continue
  count=$((count + 1))
  area="$(classify "$path")"
  printf '  %-7s %s\n' "$area" "$path" >&2
  case "$area" in
    docs) ;;
    all) select_all ;;
    *) selected[$area]=true ;;
  esac
done <<<"$files"

echo "$count changed file(s) between $1 and $2" >&2
emit
