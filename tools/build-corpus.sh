#!/usr/bin/env bash
# Builds the parity corpus archive for one build of the module
# (docs/rust-core/DECISIONS.md R35):
#
#   tools/build-corpus.sh <aprv.wasm> <aprv.component.wasm> <aprv.wit> <version> <out-dir>
#
# run from the repository root. The rows belong to one module, so a module
# that differs from the archive fixtures/corpus.json pins needs a new one.
# This fetches the pinned archive and checks its SHA-256, keeps its calls
# and clocks, regenerates every row from the given module with
# tools/wasm-trap-host.mjs (twice: the two runs must match), compares the
# rows with the previous ones (tools/corpus-compare.py: a flipped
# `verified` or `status` fails), and packs the archive deterministically.
#
# <version> is the release the module belongs to (X.Y.Z). The archive is
# named corpus-<version>-<first 8 hex digits of the module's SHA-256>, so
# the same module always gets the same name. What lands in <out-dir>:
#
#   nothing          the pinned archive already holds this module;
#   state            "built" (a new archive, to be published) or "reused"
#                    (a release of that name already holds this module);
#   corpus.json      the new pin for fixtures/corpus.json;
#   <name>.tar.gz, <name>.tar.gz.sha256 and README.md, when built.
#
# release-please.yml runs it on the release branch with the module that
# branch builds, so the release PR carries the corpus pin beside the module
# pins; refresh-corpus.yml runs it by hand on a published release's assets.
# It publishes nothing. Needs curl, tar, gzip, sha256sum, jq, node 22+ and
# python3; reads only public fixtures and test keys.
set -euo pipefail

if [[ $# -ne 5 ]]; then
  echo "usage: $0 <aprv.wasm> <aprv.component.wasm> <aprv.wit> <version> <out-dir>" >&2
  exit 2
fi
module="$1"
component="$2"
wit="$3"
version="$4"
out="$5"
repo_url=https://github.com/emindeniz99/apple-purchase-receipt-verifier
corpora=(cases hostile algorithms substrate fuzz)

cmp "$wit" rust/bindings/abi/wit/aprv.wit
wasm_sha="$(sha256sum "$module" | cut -c1-64)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]
name="corpus-$version-${wasm_sha:0:8}"
archive="$name.tar.gz"
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

archive_module() { # archive.tar.gz -> the SHA-256 of its aprv.wasm
  tar -xzOf "$1" ./aprv.wasm | sha256sum | cut -c1-64
}
pin() { # sha256 generated
  jq -n --arg url "$repo_url/releases/download/$name/$archive" --arg sha256 "$1" \
    --arg generated "$2" --arg module "$wasm_sha" \
    '{url: $url, sha256: $sha256, generated: $generated, module: $module}' > "$out/corpus.json"
}

url="$(jq -er --arg p "$repo_url/releases/download/corpus-" '.url | select(type == "string" and startswith($p))' fixtures/corpus.json)"
hash="$(jq -er '.sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' fixtures/corpus.json)"
curl -fsSL --retry 3 "$url" -o "$work/previous.tar.gz"
echo "$hash  $work/previous.tar.gz" | sha256sum -c -
if [[ "$(archive_module "$work/previous.tar.gz")" == "$wasm_sha" ]]; then
  echo "build-corpus: fixtures/corpus.json already pins an archive of aprv.wasm $wasm_sha"
  exit 0
fi

# A release of this name was built from this module before: an earlier run
# on a release branch that was rebuilt since. Reuse it rather than publish
# the same archive twice.
code="$(curl -sSL --retry 3 -o "$work/existing.tar.gz" -w '%{http_code}' "$repo_url/releases/download/$name/$archive")"
if [[ "$code" == 200 ]]; then
  got="$(archive_module "$work/existing.tar.gz")"
  if [[ "$got" != "$wasm_sha" ]]; then
    echo "::error::release $name holds aprv.wasm $got, not $wasm_sha" >&2
    exit 1
  fi
  generated="$(tar -xzOf "$work/existing.tar.gz" ./README.md | sed -n 's/^Generated: \([0-9-]*\)\.$/\1/p')"
  [[ "$generated" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]
  pin "$(sha256sum "$work/existing.tar.gz" | cut -c1-64)" "$generated"
  echo reused > "$out/state"
  echo "build-corpus: reusing release $name"
  exit 0
elif [[ "$code" != 404 ]]; then
  echo "::error::checking for release $name answered HTTP $code" >&2
  exit 1
fi

g1="$work/g1"
mkdir -p "$g1"
tar -xzf "$work/previous.tar.gz" -C "$g1"
# The previous rows are the baseline of the comparison. Keep them before
# the loop below overwrites them in place.
cp -r "$g1/rows" "$work/previous-rows"
cp "$module" "$g1/aprv.wasm"
cp "$component" "$g1/aprv.component.wasm"
cp "$wit" "$g1/aprv.wit"
(cd "$g1" && sha256sum aprv.wasm aprv.component.wasm aprv.wit > SHA256SUMS)
# The .err files hold the host's summary of the run that wrote the rows
# beside them. Drop the previous archive's, so none ships describing
# another module.
rm -f "$g1"/rows/module-*.err
for corpus in "${corpora[@]}"; do
  rows="$g1/rows/module-$corpus.jsonl"
  err="$g1/rows/module-$corpus.err"
  if ! node tools/wasm-trap-host.mjs calls "$g1/aprv.wasm" "$g1/calls/$corpus.pinned.jsonl" > "$rows" 2> "$err"; then
    cat "$err" >&2
    echo "::error::the trap host failed on the $corpus corpus (a trap, or an import other than random-get)" >&2
    exit 1
  fi
  cat "$err"
  node tools/wasm-trap-host.mjs calls "$g1/aprv.wasm" "$g1/calls/$corpus.pinned.jsonl" > "$work/repeat.jsonl"
  cmp "$rows" "$work/repeat.jsonl"
done
python3 -I tools/corpus-compare.py "$work/previous-rows" "$g1/rows" "$work/compare.txt" "${corpora[@]}"

generated="$(date -u +%F)"
{
  echo "# $name: aprv.wasm of $version"
  echo
  echo "Generated: $generated."
  echo
  echo "Source commit: $(git rev-parse HEAD)."
  echo "Calls and clocks are unchanged from the previous pinned corpus."
  echo "Reference rows and their .err summaries were regenerated by tools/wasm-trap-host.mjs, twice for the rows: identical, no traps or unexpected imports."
  echo "Compared row by row with the previous pinned corpus (a flipped row has a different verified or status; none is allowed):"
  echo
  sed 's/^/- /' "$work/compare.txt"
  echo
  echo "Only public repository fixtures and test keys; no production receipt."
  echo
  cat "$g1/SHA256SUMS"
} > "$g1/README.md"
tar --sort=name --mtime="$generated 00:00:00Z" --owner=0 --group=0 --numeric-owner -C "$g1" -cf - . | gzip -n > "$out/$archive"
(cd "$out" && sha256sum "$archive" > "$archive.sha256")
cp "$g1/README.md" "$out/README.md"
pin "$(cut -c1-64 "$out/$archive.sha256")" "$generated"
echo built > "$out/state"
echo "build-corpus: built $name"
