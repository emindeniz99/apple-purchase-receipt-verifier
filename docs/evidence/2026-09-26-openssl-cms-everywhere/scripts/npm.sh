#!/bin/sh
# Task 2 (packages): npm tarball prototypes for the CMS Route C and Route A
# (WASIp1) artifacts, built from the wasm bake-off's facade files, installed
# from the tarballs into clean consumers, and smoked with the wasm
# bake-off's matrix: Node, Bun, Deno, Chromium, Firefox, WebKitGTK, the
# Lambda-like run (node --permission) and `wrangler dev --local`.
# All packages are "private": true; nothing is published or deployed.
#   scripts/npm.sh pack  > results/npm-pack.txt
#   scripts/npm.sh smoke > results/npm-smoke.jsonl
set -eu
. "$(dirname "$0")/env.sh"
B="$C/npm-build"; OUT="$C/npm-dist"
PKGS="aprv-spike-core-openssl-cms aprv-spike-wasip1-openssl-cms"
case "$1" in
pack)
  rm -rf "$B" "$OUT"; mkdir -p "$B" "$OUT" "$C/lic"
  tar -xzf "$SCRATCH/dl/openssl-4.0.2.tar.gz" -C "$C/lic" openssl-4.0.2/LICENSE.txt
  for p in core wasip1; do
    d="$B/$p"; mkdir -p "$d"
    cp "$PREV/npm/core/"*.js "$PREV/npm/common/abi.js" "$PREV/npm/common/index.d.ts" "$d/"
    if [ $p = core ]; then cp "$C/art/cms-c.wasm" "$d/aprv.wasm"; else cp "$EV/npm/wasip1/instantiate.js" "$d/"; cp "$C/art/cms-w1.wasm" "$d/aprv.wasm"; fi
    node -e 'const [t,d,n,s]=process.argv.slice(1);const p=JSON.parse(require("fs").readFileSync(t+"/package.json"));p.name=n;p.description=s;require("fs").writeFileSync(d+"/package.json",JSON.stringify(p,null,2)+"\n")' \
      "$PREV/npm/core" "$d" "aprv-spike-$p-openssl-cms" "Spike only (never published): OpenSSL 4.0.2 CMS path, $p wasm, thin JS facade."
    { echo "This package contains OpenSSL 4.0.2, Rust std and crates (MIT OR Apache-2.0), and wasi-libc"
      echo "(wasi-sdk 34), compiled into its .wasm. The OpenSSL license follows."; echo
      cat "$C/lic/openssl-4.0.2/LICENSE.txt"; } > "$d/THIRD-PARTY-NOTICES.txt"
    (cd "$OUT" && npm pack --silent "$d" >/dev/null)
  done
  for t in "$OUT"/*.tgz; do echo "$(basename "$t") $(stat -c %s "$t") B, $(tar tzf "$t" | wc -l) files, sha256 $(sha256sum "$t" | cut -c1-16)"; tar tzvf "$t" | awk '{print "   ", $3, $6}'; done
  ;;
smoke)
  : "${WRANGLER:?}"
  J="$C/consumers/js"; rm -rf "$J"; mkdir -p "$J"
  (cd "$J" && npm init -y >/dev/null && npm install --no-audit --no-fund "$OUT"/*.tgz >"$J/npm.log" 2>&1)
  cp "$PREV/npm/smoke.mjs" "$PREV/npm/run-smoke.mjs" "$PREV/npm/smoke.html" "$PREV/npm/lambda/"*.mjs "$J/"
  node "$PREV/npm/make-vectors.mjs" "$REPO/fixtures" > "$J/vectors.mjs"
  for p in $PKGS; do
    (cd "$J" && node run-smoke.mjs $p) || echo "{\"runtime\":\"node\",\"pkg\":\"$p\",\"ok\":false}"
    (cd "$J" && bun run-smoke.mjs $p) || echo "{\"runtime\":\"bun\",\"pkg\":\"$p\",\"ok\":false}"
    (cd "$J" && deno run --allow-read --allow-env run-smoke.mjs $p) || echo "{\"runtime\":\"deno\",\"pkg\":\"$p\",\"ok\":false}"
    for br in chromium firefox webkit; do node "$PREV/npm/browser-smoke.mjs" $br "$J" $p; done
    (cd "$J" && APRV_PKG=$p node --permission --allow-fs-read="$J" lambda-sim.mjs) | sed 's/^{/{"lambdaLike":true,/' \
      || echo "{\"lambdaLike\":true,\"pkg\":\"$p\",\"ok\":false}"
  done
  K="$C/consumers/worker"; rm -rf "$K"; mkdir -p "$K/src"
  (cd "$K" && npm init -y >/dev/null && npm install --no-audit --no-fund "$OUT"/*.tgz >"$K/npm.log" 2>&1)
  printf 'name = "aprv-spike-smoke"\ncompatibility_date = "2026-09-26"\n' > "$K/wrangler.toml"
  cp "$PREV/npm/smoke.mjs" "$J/vectors.mjs" "$K/src/"
  PORT=28301
  for p in $PKGS; do
    s=${p#aprv-spike-}
    printf "import * as pkg from '%s';\nimport { smoke } from './smoke.mjs';\nimport { vectors } from './vectors.mjs';\nexport default { async fetch() { return Response.json({ pkg: '%s', ...smoke(pkg, vectors) }); } };\n" "$p" "$p" > "$K/src/$s.js"
    "$PREV/npm/worker-smoke.sh" "$K" "$s" $PORT || echo "{\"host\":\"wrangler dev (local)\",\"pkg\":\"$p\",\"ok\":false}"
    PORT=$((PORT + 1))
  done
  ;;
esac
