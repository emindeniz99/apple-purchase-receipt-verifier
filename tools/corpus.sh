#!/usr/bin/env bash
# The parity corpus (docs/rust-core/DECISIONS.md R35). fixtures/corpus.json
# pins an archive by URL and SHA-256, and the only part of it anything reads
# is calls/<corpus>.pinned.jsonl: the frozen inputs, every clock pinned
# (their provenance is in fixtures/README.md). The rows are not stored: each
# run derives them from the module it tests.
#
#   tools/corpus.sh calls <dir>
#       Fetches the pinned archive, checks its SHA-256 and writes the five
#       corpora's calls to <dir>/calls/<corpus>.pinned.jsonl. Reads the old
#       full archive (module, rows and calls) and the calls-only one alike.
#   tools/corpus.sh rows <aprv.wasm> <calls-dir> <rows-dir> [<trap-host.mjs>]
#       The module's own answers: rows-dir/module-<corpus>.jsonl, with the
#       host's summary in module-<corpus>.err, from tools/wasm-trap-host.mjs
#       (or the given copy of it). Every corpus runs twice and the two runs
#       must be identical; a trap or an import other than random-get fails.
#   tools/corpus.sh release-rows <vX.Y.Z> <calls-dir> <rows-dir>
#       The same for a published release's aprv.wasm, checked against that
#       release's SHA256SUMS, run by the trap host of the release's tag: a
#       host binds one ABI version, so this tree's may not run an older
#       module.
#   tools/corpus.sh g1 <module-dir> <g1-dir>
#       Assembles the G1 directory every host's corpus script reads from a
#       build of the module (rust/bindings/abi/build.sh's output: aprv.wasm,
#       aprv.component.wasm, aprv.wit and SHA256SUMS): those four files,
#       same.py (tools/corpus-same.py), calls/ and rows/.
#   tools/corpus.sh pack <calls-dir> <out-dir>
#       Packs the calls into a calls-only archive, byte for byte the same
#       for the same calls, named corpus-calls-<first 8 hex digits of its
#       SHA-256>. Writes <name>.tar.gz, <name>.tar.gz.sha256, README.md and
#       corpus.json, the pin for fixtures/corpus.json. Publishes nothing.
#
# Run from the repository root. Needs bash, curl, tar, gzip, sha256sum, jq,
# git (release-rows), node 22+ (rows) and python3; reads only public
# fixtures and test keys.
set -euo pipefail

repo_url=https://github.com/emindeniz99/apple-purchase-receipt-verifier
corpora=(cases hostile algorithms substrate fuzz)

usage() {
  cat >&2 <<EOF
usage: $0 calls <dir>
       $0 rows <aprv.wasm> <calls-dir> <rows-dir> [<trap-host.mjs>]
       $0 release-rows <vX.Y.Z> <calls-dir> <rows-dir>
       $0 g1 <module-dir> <g1-dir>
       $0 pack <calls-dir> <out-dir>
EOF
  exit 2
}

calls() { # dir
  local out="$1" work url hash c
  url="$(jq -er --arg p "$repo_url/releases/download/" '.url | select(type == "string" and startswith($p))' fixtures/corpus.json)" ||
    { echo "::error::fixtures/corpus.json is missing, is not JSON, or has no url under $repo_url/releases/download/" >&2; exit 1; }
  hash="$(jq -er '.sha256 | select(type == "string" and test("^[0-9a-f]{64}$"))' fixtures/corpus.json)" ||
    { echo "::error::fixtures/corpus.json has no sha256 of 64 lowercase hex digits" >&2; exit 1; }
  work="$(mktemp -d)"
  curl -fsSL --retry 3 "$url" -o "$work/corpus.tar.gz"
  echo "$hash  $work/corpus.tar.gz" | sha256sum -c -
  mkdir -p "$work/x" "$out/calls"
  # Both layouts keep the calls at ./calls/; nothing else is unpacked.
  tar -xzf "$work/corpus.tar.gz" -C "$work/x" --wildcards '*calls/*.pinned.jsonl'
  for c in "${corpora[@]}"; do
    if [[ ! -s "$work/x/calls/$c.pinned.jsonl" ]]; then
      echo "::error::the pinned archive has no calls/$c.pinned.jsonl" >&2
      exit 1
    fi
    mv "$work/x/calls/$c.pinned.jsonl" "$out/calls/"
  done
  rm -rf "$work"
}

rows() { # aprv.wasm calls-dir rows-dir [trap-host.mjs]
  local module="$1" in="$2" out="$3" host="${4:-tools/wasm-trap-host.mjs}" c
  mkdir -p "$out"
  for c in "${corpora[@]}"; do
    if ! node "$host" calls "$module" "$in/$c.pinned.jsonl" > "$out/module-$c.jsonl" 2> "$out/module-$c.err"; then
      cat "$out/module-$c.err" >&2
      echo "::error::the trap host failed on the $c corpus (a trap, or an import other than random-get)" >&2
      exit 1
    fi
    cat "$out/module-$c.err"
    # To a file, not a pipe: node may exit before a pipe drains.
    node "$host" calls "$module" "$in/$c.pinned.jsonl" > "$out/repeat.jsonl" 2> /dev/null
    cmp "$out/repeat.jsonl" "$out/module-$c.jsonl" ||
      { echo "::error::two runs of the $c corpus answered differently" >&2; exit 1; }
  done
  rm -f "$out/repeat.jsonl"
}

release_rows() { # vX.Y.Z calls-dir rows-dir
  local tag="$1" work line
  [[ "$tag" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "::error::not a release tag: $tag" >&2; exit 1; }
  work="$(mktemp -d)"
  curl -fsSL --retry 3 "$repo_url/releases/download/$tag/SHA256SUMS" -o "$work/SHA256SUMS"
  curl -fsSL --retry 3 "$repo_url/releases/download/$tag/aprv.wasm" -o "$work/aprv.wasm"
  line="$(grep -E '^[0-9a-f]{64}  aprv\.wasm$' "$work/SHA256SUMS")" ||
    { echo "::error::$tag's SHA256SUMS has no line for aprv.wasm" >&2; exit 1; }
  (cd "$work" && sha256sum -c - <<< "$line")
  if ! git rev-parse -q --verify "refs/tags/$tag^{commit}" > /dev/null; then
    git fetch -q --no-tags --depth=1 origin "refs/tags/$tag:refs/tags/$tag"
  fi
  # git show, not git archive: .gitattributes export-ignores tools/.
  git ls-tree -r --name-only "$tag" -- tools/wasm-trap-host.mjs tools/lib | while IFS= read -r f; do
    mkdir -p "$work/host/$(dirname "$f")"
    git show "$tag:$f" > "$work/host/$f"
  done
  echo "corpus: rows of $tag's aprv.wasm $(cut -c1-64 <<< "$line"), by $tag's trap host"
  rows "$work/aprv.wasm" "$2" "$3" "$work/host/tools/wasm-trap-host.mjs"
  rm -rf "$work"
}

g1() { # module-dir g1-dir
  local in="$1" out="$2" f
  (cd "$in" && sha256sum -c SHA256SUMS)
  for f in aprv.wasm aprv.component.wasm aprv.wit; do
    grep -qE "^[0-9a-f]{64}  $f\$" "$in/SHA256SUMS" ||
      { echo "::error::$in/SHA256SUMS has no line for $f" >&2; exit 1; }
  done
  cmp "$in/aprv.wit" rust/bindings/abi/wit/aprv.wit
  mkdir -p "$out"
  cp "$in/aprv.wasm" "$in/aprv.component.wasm" "$in/aprv.wit" "$in/SHA256SUMS" "$out/"
  cp tools/corpus-same.py "$out/same.py"
  calls "$out"
  rows "$out/aprv.wasm" "$out/calls" "$out/rows"
}

pack() { # calls-dir out-dir
  local in="$1" out="$2" work stage sha name c
  work="$(mktemp -d)"
  stage="$work/stage"
  mkdir -p "$stage/calls" "$out"
  for c in "${corpora[@]}"; do
    cp "$in/$c.pinned.jsonl" "$stage/calls/"
  done
  (cd "$stage" && sha256sum calls/*.pinned.jsonl) > "$stage/SHA256SUMS"
  {
    echo "# The parity corpus: calls only"
    echo
    echo "The frozen inputs of the nightly corpus job (docs/rust-core/DECISIONS.md R35),"
    echo "one call per line, every clock pinned: cases, hostile, algorithms, substrate"
    echo "and fuzz. Their provenance is in fixtures/README.md. There are no rows: each"
    echo "run derives them from the module it tests (tools/corpus.sh)."
    echo
    echo "Only public repository fixtures and test keys; no production receipt."
    echo
    cat "$stage/SHA256SUMS"
  } > "$stage/README.md"
  tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner --mode='u=rwX,go=rX' \
    -C "$stage" -cf - . | gzip -n -9 > "$work/corpus.tar.gz"
  sha="$(sha256sum "$work/corpus.tar.gz" | cut -c1-64)"
  name="corpus-calls-${sha:0:8}"
  mv "$work/corpus.tar.gz" "$out/$name.tar.gz"
  (cd "$out" && sha256sum "$name.tar.gz" > "$name.tar.gz.sha256")
  cp "$stage/README.md" "$out/README.md"
  jq -n --arg url "$repo_url/releases/download/$name/$name.tar.gz" --arg sha256 "$sha" \
    '{url: $url, sha256: $sha256}' > "$out/corpus.json"
  rm -rf "$work"
  echo "corpus: packed $name"
}

case "${1:-}" in
  calls) [[ $# -eq 2 ]] || usage; calls "$2" ;;
  rows) [[ $# -eq 4 || $# -eq 5 ]] || usage; rows "${@:2}" ;;
  release-rows) [[ $# -eq 4 ]] || usage; release_rows "$2" "$3" "$4" ;;
  g1) [[ $# -eq 3 ]] || usage; g1 "$2" "$3" ;;
  pack) [[ $# -eq 3 ]] || usage; pack "$2" "$3" ;;
  *) usage ;;
esac
