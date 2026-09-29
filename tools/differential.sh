#!/usr/bin/env bash
# The differential campaign (DECISIONS.md R33): the Rust core, as aprv.wasm,
# and the 0.7 Java implementation over the same calls, verdict by verdict
# and reason by reason. CI's nightly `java-differential` job runs it on
# fixtures/cases.json; the evidence campaigns add the corpora, which are
# not in the repository.
#
#   tools/differential.sh <aprv.wasm> <out-dir> [<calls.jsonl> ...]
#
# Writes into <out-dir>: cases.calls.jsonl (fixtures/cases.json as calls,
# tools/differential/cases-calls.mjs), and for each call file <name>:
# <name>.core.jsonl, <name>.java.jsonl and <name>.report.txt. Exits 1 when
# a row differs in its verdict, its reason or its payload, or faults on
# either side, and tools/differential/recorded.json (the rows R20 records)
# does not name it with that difference; a recorded row that now agrees is
# reported as stale and does not fail the run. tools/differential/README.md
# explains the classes.
#
# Needs node (20+), a JDK and Maven. TRAP_HOST overrides the host that runs
# the module (default tools/wasm-trap-host.mjs); RECORDED adds recorded-row
# files, space-separated, to tools/differential/recorded.json.
set -euo pipefail

if [[ $# -lt 2 || -z "$1" || -z "$2" ]]; then
  echo "usage: $0 <aprv.wasm> <out-dir> [<calls.jsonl> ...]" >&2
  exit 2
fi
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/.." && pwd)"
module="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"
mkdir -p "$2"
out="$(cd "$2" && pwd)"
shift 2
trap_host="${TRAP_HOST:-$repo/tools/wasm-trap-host.mjs}"
[[ -f "$module" ]] || { echo "differential: no module at $module" >&2; exit 2; }
[[ -f "$trap_host" ]] || { echo "differential: no trap host at $trap_host (set TRAP_HOST)" >&2; exit 2; }
recorded=(--recorded "$here/differential/recorded.json")
for extra in ${RECORDED:-}; do recorded+=(--recorded "$extra"); done

# The Java implementation as it is in this checkout, and the runner.
mvn -B -q -f "$repo/java/pom.xml" -DskipTests package dependency:build-classpath \
  -Dmdep.outputFile="$out/java.classpath" -Dmdep.includeScope=runtime >&2
jar="$(ls "$repo"/java/target/apple-purchase-receipt-verifier-*.jar | grep -v -e '-sources' -e '-javadoc' -e '-tests' | head -n 1)"
classpath="$jar:$(cat "$out/java.classpath")"
mkdir -p "$out/classes"
javac -d "$out/classes" -cp "$classpath" "$here/differential/Differential.java"

node "$here/differential/cases-calls.mjs" "$repo/fixtures/cases.json" > "$out/cases.calls.jsonl"

status=0
for calls in "$out/cases.calls.jsonl" "$@"; do
  name="$(basename "$calls" .jsonl)"
  name="${name%.calls}"
  echo "differential: $name" >&2
  node "$trap_host" calls "$module" "$calls" > "$out/$name.core.jsonl"
  java -cp "$classpath:$out/classes" Differential "$calls" > "$out/$name.java.jsonl"
  if node "$here/differential/compare.mjs" "$out/$name.core.jsonl" "$out/$name.java.jsonl" "${recorded[@]}" \
    > "$out/$name.report.txt"; then
    tail -n 1 "$out/$name.report.txt" >&2
  else
    status=1
    grep -e '^summary' -e '^NOT RECORDED' "$out/$name.report.txt" >&2
  fi
done
exit "$status"
