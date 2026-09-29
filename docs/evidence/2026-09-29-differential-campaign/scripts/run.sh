#!/bin/sh
# Evidence only (2026-09-29): the differential campaign of
# ../../2026-09-29-differential-campaign.md, end to end.
#
#   REPO=<repository> MODULE=<aprv.wasm> CALLS=<dir of <corpus>.pinned.jsonl>
#   OUT=<scratch dir> TRAP_HOST=<tools/wasm-trap-host.mjs> sh run.sh
#
# 1. the ports' fuzz seeds as calls (seeds-calls.mjs);
# 2. tools/differential.sh over the cases, the five corpora and the seeds
#    (a first pass that fails: the corpus rows are not recorded yet);
# 3. every report again with --list, sorted into R20's groups by
#    classify.py, which writes the corpus rows' recorded file;
# 4. tools/differential.sh again with that file: it must pass.
set -eu
: "${REPO:?}" "${MODULE:?}" "${CALLS:?}" "${OUT:?}" "${TRAP_HOST:?}"
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$OUT"
node "$here/seeds-calls.mjs" "$REPO" > "$OUT/seeds.calls.jsonl"
set --
for c in algorithms cases substrate hostile fuzz; do set -- "$@" "$CALLS/$c.pinned.jsonl"; done
TRAP_HOST="$TRAP_HOST" "$REPO/tools/differential.sh" "$MODULE" "$OUT/pass1" "$@" "$OUT/seeds.calls.jsonl" || true
reports=""
for core in "$OUT"/pass1/*.core.jsonl; do
  name="$(basename "$core" .core.jsonl)"
  node "$REPO/tools/differential/compare.mjs" "$core" "$OUT/pass1/$name.java.jsonl" \
    --recorded "$REPO/tools/differential/recorded.json" --list > "$OUT/cmp-$name.txt" || true
  reports="$reports $OUT/cmp-$name.txt"
done
# shellcheck disable=SC2086
python3 "$here/classify.py" "$OUT/recorded-corpus.json" $reports ${OLD:+--old "$OLD"}
TRAP_HOST="$TRAP_HOST" RECORDED="$OUT/recorded-corpus.json" "$REPO/tools/differential.sh" "$MODULE" "$OUT/pass2" "$@" "$OUT/seeds.calls.jsonl"
