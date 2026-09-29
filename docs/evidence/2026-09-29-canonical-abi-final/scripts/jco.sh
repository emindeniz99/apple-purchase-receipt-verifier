#!/bin/sh
# Spike only (2026-09-29, round 13). jco 1.35.0 generates the JS bindings
# for the component into $S/jco/out; the same output then runs on Node,
# Deno and Bun ($DENO and $BUN name the binaries; default: on PATH).
#   jco.sh setup                     npm install into $S/jco (once)
#   jco.sh transpile > results/jco-transpile.txt
#   jco.sh tests node|deno|bun       binding-level checks
#   jco.sh cmd node|deno|bun         print the command line for corpus.sh
#   jco.sh startup node|deno|bun [RUNS]   RUNS (7) fresh processes per module, interleaved, taskset -c 0
set -eu
export NO_COLOR=1
. "$(dirname "$0")/env.sh"
J="$S/jco"
DENO=${DENO:-deno}; BUN=${BUN:-bun}
# Deno: jco's glue reads process.env.JCO_DEBUG, which needs an env grant.
rt() { case $1 in node) echo node ;; deno) echo "$DENO run --allow-read --allow-env=JCO_DEBUG" ;; bun) echo "$BUN" ;; esac; }
case "$1" in
setup)
  mkdir -p "$J"; echo '{"name":"r13-jco","private":true,"type":"module"}' > "$J/package.json"
  npm --prefix "$J" install --no-audit --no-fund @bytecodealliance/jco@1.35.0 ;;
transpile)
  echo "# jco $(npx --prefix "$J" jco --version) transpile $(basename "$COMP") --name aprv --instantiation async, $(date -u +%F)"
  rm -rf "${J:?}/out"
  npx --prefix "$J" jco transpile "$COMP" -o "$J/out" --name aprv --instantiation async -q
  (cd "$J/out" && find . -type f | sort | xargs wc -c)
  echo "## what aprv.js imports (none means it runs on any runtime with WebAssembly)"; grep -oE "^import [^;]*;" "$J/out/aprv.js" || echo "(no import statements)"
  echo "## out/aprv.d.ts (ImportObject)"; sed -n '/interface ImportObject/,/^}/p' "$J/out/aprv.d.ts"
  echo "## out/interfaces/*.d.ts"; cat "$J"/out/interfaces/*.d.ts
  echo "## the import key the glue reads"; grep -o "imports\[['\"][^'\"]*['\"]\]" "$J/out/aprv.js" | sort -u ;;
tests) $(rt "$2") "$FE/hosts/jco/run-calls.mjs" "$J/out" tests "$S/calls/cases.jsonl" ;;
cmd) echo "$(rt "$2") $FE/hosts/jco/run-calls.mjs $J/out calls" ;;
startup)
  echo "# $2 start-up, $(date -u +%F), taskset -c 0, fresh process per run, load before: $(cut -d' ' -f1-3 /proc/loadavg)"
  for i in $(seq "${3:-7}"); do
    for m in v1 cabi; do
      [ $m = v1 ] && p="$V1" || p="$J/out"
      t=$(date +%s%N)
      o=$(taskset -c 0 $(rt "$2") "$FE/hosts/jco/startup.mjs" $m "$p" "$S/calls/cases.jsonl")
      echo "${o%\}},\"process_wall_ms\":$(( ($(date +%s%N) - t) / 1000000 ))}"
    done
  done ;;
esac
