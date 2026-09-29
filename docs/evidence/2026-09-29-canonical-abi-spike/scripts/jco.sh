#!/bin/sh
# Spike only (2026-09-29, round 12). jco 1.35.0 generates the JS bindings
# for the (checked) component: `transpile` writes $S/jco/out (and a
# --minify copy in $S/jco/out-min) and prints the generated files and the
# .d.ts; `tests` runs hosts/jco/run-calls.mjs's binding-level checks.
#   jco.sh setup                     npm install into $S/jco (once)
#   jco.sh transpile > results/jco-transpile.txt
#   jco.sh tests     > results/tests-jco.txt
# The corpus: corpus.sh jco -- node $FE/hosts/jco/run-calls.mjs $S/jco/out calls
set -eu
. "$(dirname "$0")/env.sh"
J="$S/jco"
case "$1" in
setup)
  mkdir -p "$J"; echo '{"name":"r12-jco","private":true,"type":"module"}' > "$J/package.json"
  npm --prefix "$J" install --no-audit --no-fund @bytecodealliance/jco@1.35.0 ;;
transpile)
  echo "# jco $(npx --prefix "$J" jco --version) transpile $(basename "$COMPC") --name aprv --instantiation async, $(date -u +%F)"
  for o in out out-min; do
    rm -rf "${J:?}/$o"
    [ $o = out ] && m= || m=--minify
    npx --prefix "$J" jco transpile "$COMPC" -o "$J/$o" --name aprv --instantiation async $m -q
    echo "## $o ($( [ -n "$m" ] && echo "--minify" || echo "default"))"
    (cd "$J/$o" && find . -type f | sort | xargs wc -c)
  done
  echo "## out/aprv.d.ts"; cat "$J/out/aprv.d.ts"
  echo "## out/interfaces/*.d.ts"; cat "$J"/out/interfaces/*.d.ts
  echo "## the import key the glue reads"; grep -o "imports\[['\"][^'\"]*['\"]\]\|'aprv:verifier/host[^']*'" "$J/out/aprv.js" | sort -u ;;
tests)
  echo "## node run-calls.mjs out tests (jco transpile of $(basename "$COMPC"), $(date -u +%F))"
  node "$FE/hosts/jco/run-calls.mjs" "$J/out" tests "$S/calls/cases.jsonl" ;;
esac
