#!/bin/sh
# The corpus through the built jar (MIGRATION step 3.7): the 1,179 corpus
# rows and 5,000 mutants of the substrate bake-off, in round 13's mapping,
# through this artifact's Endive guest, compared row by row with ABI v1's
# Node rows by round 13's classify.py. Expected for any module built from
# the 0.6 core (the stand-in): 6,176 identical, 2 clock-moves-chain,
# 1 init-refusal. For the release module the rows to compare against are
# native's, and the expectation is set by lane A's G1.
#
#   corpus.sh OUT_DIR [THREADS]
#
# Needs: the jar and test classes built (mvn -f java-wasm verify, or
# package + test-compile); python3; and
#   CALLS_V1  ABI v1's calls per corpus (<corpus>.jsonl), which
#             calls_bytes.py maps to round 13's interface
#   NODEROWS  ABI v1's Node rows (node-<corpus>.jsonl)
#   JAVA      the java binary to run (default: java on PATH)
# Writes OUT_DIR/calls/<corpus>.jsonl (once), OUT_DIR/<label>-<corpus>.jsonl
# and .err, where label is endive-t<THREADS>, and prints classify.py's lines.
set -eu
: "${CALLS_V1:?}" "${NODEROWS:?}"
out=$1
threads=${2:-1}
here=$(cd "$(dirname "$0")/.." && pwd)
final="$here/../docs/evidence/2026-09-29-canonical-abi-final/py"
java=${JAVA:-java}
mkdir -p "$out/calls"
cp="$out/classpath.txt"
[ -s "$cp" ] || mvn -q -f "$here/pom.xml" dependency:build-classpath -Dmdep.includeScope=test -Dmdep.outputFile="$cp" >/dev/null
jar=$(ls "$here"/target/apple-purchase-receipt-verifier-wasm-*.jar | grep -v -e sources -e javadoc | head -1)
label="endive-t$threads"
for c in cases hostile algorithms substrate fuzz; do
  [ -s "$out/calls/$c.jsonl" ] || python3 "$final/calls_bytes.py" "$CALLS_V1/$c.jsonl" > "$out/calls/$c.jsonl" 2>/dev/null
  "$java" -cp "$jar:$here/target/test-classes:$(cat "$cp")" \
    io.github.emindeniz99.applepurchasereceiptverifier.CorpusMain "$out/calls/$c.jsonl" "$threads" \
    > "$out/$label-$c.jsonl" 2> "$out/$label-$c.err"
  echo "$c: $(tail -1 "$out/$label-$c.err")"
done
python3 "$final/classify.py" "$label" "$out/calls" "$NODEROWS" "$out/$label"
