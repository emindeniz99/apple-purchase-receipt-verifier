#!/usr/bin/env bash
# Runs inside tools/reproduce/Dockerfile: fetches the ref's own
# tools/reproduce-wasm.sh and runs it without a container. The script's own
# clone is the one that builds; this one only supplies the script.
#   aprv-reproduce <tag-or-ref> <expected-sha256>
set -euo pipefail
[[ $# -eq 2 ]] || { echo "usage: aprv-reproduce <tag-or-ref> <expected-sha256>" >&2; exit 2; }
repo="${APRV_REPO_URL:-https://github.com/emindeniz99/apple-purchase-receipt-verifier.git}"
tmp="$(mktemp -d)"
git clone --quiet --no-checkout "$repo" "$tmp/script"
git -C "$tmp/script" -c advice.detachedHead=false checkout --quiet "$1" -- tools/reproduce-wasm.sh
exec bash "$tmp/script/tools/reproduce-wasm.sh" "$1" "$2"
