#!/bin/sh
# Task 1a: installs the OpenSSL/LibreSSL tarballs from scripts/npm-pack.sh
# into clean consumers and runs the wasm bake-off's smoke matrix, unchanged:
# Node, Bun, Deno, Chromium, Firefox, WebKitGTK, a Lambda-like Node run and
# `wrangler dev --local` (nothing deployed). One JSON line per run.
#   scripts/npm-smoke.sh > results/npm-smoke.jsonl
# Needs: PLAYWRIGHT_MODULE, FIREFOX (as in the wasm bake-off), WRANGLER.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${WRANGLER:?}"
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
PKGS="aprv-spike-core-openssl aprv-spike-emscripten-openssl aprv-spike-emscripten-libressl aprv-spike-component-openssl"
J="$SCRATCH/fu/consumers/js"; rm -rf "$J"; mkdir -p "$J"
(cd "$J" && npm init -y >/dev/null && npm install --no-audit --no-fund "$SCRATCH"/fu/npm-dist/*.tgz >"$J/npm.log" 2>&1)
cp "$PREV/npm/smoke.mjs" "$PREV/npm/run-smoke.mjs" "$PREV/npm/smoke.html" "$PREV/npm/lambda/"*.mjs "$J/"
node "$PREV/npm/make-vectors.mjs" "$REPO/fixtures" > "$J/vectors.mjs"
for p in $PKGS; do
  (cd "$J" && node run-smoke.mjs $p) || echo "{\"runtime\":\"node\",\"pkg\":\"$p\",\"ok\":false}"
  (cd "$J" && bun run-smoke.mjs $p) || echo "{\"runtime\":\"bun\",\"pkg\":\"$p\",\"ok\":false}"
  (cd "$J" && deno run --allow-read --allow-env run-smoke.mjs $p) || echo "{\"runtime\":\"deno\",\"pkg\":\"$p\",\"ok\":false}"
  for br in chromium firefox webkit; do node "$PREV/npm/browser-smoke.mjs" $br "$J" $p; done
  (cd "$J" && APRV_PKG=$p node --permission --allow-fs-read="$J" lambda-sim.mjs) | sed 's/^{/{"lambdaLike":true,/'
done
# wrangler dev: a Worker per package importing the INSTALLED package.
K="$SCRATCH/fu/consumers/worker"; rm -rf "$K"; mkdir -p "$K/src"
(cd "$K" && npm init -y >/dev/null && npm install --no-audit --no-fund "$SCRATCH"/fu/npm-dist/*.tgz >"$K/npm.log" 2>&1)
printf 'name = "aprv-spike-smoke"\ncompatibility_date = "2026-09-26"\n' > "$K/wrangler.toml"
cp "$PREV/npm/smoke.mjs" "$J/vectors.mjs" "$K/src/"
PORT=28201
for p in $PKGS; do
  s=${p#aprv-spike-}
  printf "import * as pkg from '%s';\nimport { smoke } from './smoke.mjs';\nimport { vectors } from './vectors.mjs';\nexport default { async fetch() { return Response.json({ pkg: '%s', ...smoke(pkg, vectors) }); } };\n" "$p" "$p" > "$K/src/$s.js"
  "$PREV/npm/worker-smoke.sh" "$K" "$s" $PORT || echo "{\"host\":\"wrangler dev (local)\",\"pkg\":\"$p\",\"ok\":false}"
  PORT=$((PORT + 1))
done
