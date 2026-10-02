#!/bin/sh
# The corpus through the built jar (MIGRATION step 3.7): the five corpora
# of the G1 bundle, 6,179 calls, through this artifact's Endive guest,
# compared byte for byte with the module's reference rows (the answers of
# the same aprv.wasm through the Node trap host, identical to the native
# core). Expected: every row identical, 0 traps.
#
#   corpus.sh CALLS_DIR ROWS_DIR OUT_DIR [THREADS]
#
# CALLS_DIR holds <corpus>.pinned.jsonl (round 13's calls_bytes.py format,
# every clock pinned), ROWS_DIR holds module-<corpus>.jsonl. Needs the jar
# and test classes built with that aprv.wasm (mvn -f java-wasm verify) and
# python3; JAVA picks the java binary (default: java on PATH). With
# APRV_SERVER set to an aprv-server binary, the calls go through the server
# engine's managed child instead (ServerCorpusMain), and a body over the
# server's cap is the module's own answer, sent with 413. Writes
# OUT_DIR/<endive|server>-t<THREADS>-<corpus>.jsonl and .err, prints one line
# per corpus, and exits non-zero if any row differs or traps.
set -eu
calls=$1
rows=$2
out=$3
threads=${4:-1}
here=$(cd "$(dirname "$0")/.." && pwd)
java=${JAVA:-java}
mkdir -p "$out"
cp="$out/classpath.txt"
[ -s "$cp" ] || mvn -q -f "$here/pom.xml" dependency:build-classpath -Dmdep.includeScope=test -Dmdep.outputFile="$cp" >/dev/null
jar=$(ls "$here"/target/apple-purchase-receipt-verifier-wasm-*.jar | grep -v -e sources -e javadoc -e linux- | head -1)
status=0
for c in cases hostile algorithms substrate fuzz; do
  if [ -n "${APRV_SERVER:-}" ]; then
    row="$out/server-t$threads-$c"
    "$java" -cp "$jar:$here/target/test-classes:$(cat "$cp")" \
      io.github.emindeniz99.applepurchasereceiptverifier.ServerCorpusMain "$calls/$c.pinned.jsonl" "$APRV_SERVER" "$threads" \
      > "$row.jsonl" 2> "$row.err"
  else
    row="$out/endive-t$threads-$c"
    "$java" -cp "$jar:$here/target/test-classes:$(cat "$cp")" \
      io.github.emindeniz99.applepurchasereceiptverifier.CorpusMain "$calls/$c.pinned.jsonl" "$threads" \
      > "$row.jsonl" 2> "$row.err"
  fi
  python3 - "$row.jsonl" "$rows/module-$c.jsonl" "$c" <<'PY' || status=1
import json, sys
a = [json.loads(l) for l in open(sys.argv[1], encoding="utf-8") if l.strip()]
b = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
if len(a) != len(b):
    print(f"{sys.argv[3]}: {len(a)} rows here, {len(b)} reference rows"); sys.exit(1)
differ = [(x, y) for x, y in zip(a, b)
          if x["id"] != y["id"] or (x.get("out"), x.get("trap"), x.get("map")) != (y.get("out"), y.get("trap"), y.get("map"))]
traps = sum("trap" in x for x in a)
print(f"{sys.argv[3]}: {len(a)} rows, {len(a) - len(differ)} identical, {len(differ)} differ, {traps} traps")
for x, y in differ[:20]:
    print(f"  {x['id']}\n    here:      {json.dumps(x)[:400]}\n    reference: {json.dumps(y)[:400]}")
sys.exit(1 if differ or traps else 0)
PY
done
exit $status
