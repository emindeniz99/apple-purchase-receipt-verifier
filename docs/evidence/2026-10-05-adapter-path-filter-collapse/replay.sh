#!/bin/sh
# Evidence only (2026-10-05). Answers every call of the five pinned corpus
# files with the native twin at the checked-out tree, into $OUT/<corpus>.jsonl.
#
#   replay.sh <corpus dir> <out dir>
#
# <corpus dir> is the archive fixtures/corpus.json pins, extracted (its
# calls/ folder). Needs REPO (the repository) and the cargo of
# rust/rust-toolchain.toml; CARGO_TARGET_DIR is honoured.
set -eu
: "${REPO:?}"
CORPUS="$1"
OUT="$2"
HERE="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
cp "$HERE/corpus_replay.rs" "$REPO/rust/ffi/tests/corpus_replay.rs"
trap 'rm -f "$REPO/rust/ffi/tests/corpus_replay.rs"' EXIT
for c in cases hostile algorithms substrate fuzz; do
  APRV_CALLS="$CORPUS/calls/$c.pinned.jsonl" APRV_ROWS="$OUT/$c.jsonl" \
    cargo test --quiet --locked --all-features --manifest-path "$REPO/rust/Cargo.toml" \
      -p apple-purchase-receipt-verifier-ffi --test corpus_replay > /dev/null
  echo "$c: $(wc -l < "$OUT/$c.jsonl") rows"
done
