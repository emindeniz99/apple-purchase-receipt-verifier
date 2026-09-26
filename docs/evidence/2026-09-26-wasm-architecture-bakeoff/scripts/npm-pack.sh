#!/bin/sh
# Assembles the three npm package prototypes from npm/ + the built
# artifacts and packs them with `npm pack` into $SCRATCH/npm-dist. Every
# package is "private": true; nothing is ever published.
#   scripts/npm-pack.sh
set -eu
: "${REPO:?}" "${SCRATCH:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
B="$SCRATCH/npm-build"; OUT="$SCRATCH/npm-dist"
rm -rf "$B" "$OUT"; mkdir -p "$B" "$OUT"
AWSLC_LICENSE="$(ls -d "$HOME"/.cargo/registry/src/*/aws-lc-sys-0.41.0 | head -1)/LICENSE"
notices() { # dest, extra files...
  d="$1"; shift
  { echo "This package contains AWS-LC 1.73.0 (aws-lc-sys 0.41.0), Rust std and crates (MIT OR Apache-2.0),"
    echo "compiled into its .wasm. Licenses follow."; echo
    cat "$AWSLC_LICENSE"
    for f in "$@"; do echo; echo "================================================================"; cat "$f"; done
  } > "$d/THIRD-PARTY-NOTICES.txt"
}
# 1. Route C core module (AWS-LC), one .wasm for every host.
mkdir -p "$B/core"
cp "$EV/npm/core/"* "$EV/npm/common/abi.js" "$EV/npm/common/index.d.ts" "$B/core/"
cp "$SCRATCH/art/awslc-c.wasm" "$B/core/aprv.wasm"
notices "$B/core"
# 2. Emscripten (AWS-LC): one .wasm, node+web glue and web-only glue.
mkdir -p "$B/emscripten"
cp "$EV/npm/emscripten/"* "$EV/npm/common/abi.js" "$EV/npm/common/index.d.ts" "$B/emscripten/"
cp "$SCRATCH/em/awslc-em/aprv-em.wasm" "$B/emscripten/aprv-em.wasm"
cp "$SCRATCH/em/awslc-em/aprv-em.mjs" "$B/emscripten/aprv-em-node.mjs"
cp "$SCRATCH/em/awslc-em-web/aprv-em.mjs" "$B/emscripten/aprv-em-web.mjs"
cmp "$SCRATCH/em/awslc-em/aprv-em.wasm" "$SCRATCH/em/awslc-em-web/aprv-em.wasm"
notices "$B/emscripten" "$EMSDK_DIR/emscripten/LICENSE"
# 3. Component (AWS-LC), jco 1.35.0 output.
mkdir -p "$B/component"
cp -r "$SCRATCH/comp/awslc-min-jco/"* "$B/component/"
cp "$EV/npm/component/"* "$EV/npm/common/index.d.ts" "$B/component/"
notices "$B/component"
for p in core emscripten component; do (cd "$OUT" && npm pack --silent "$B/$p" >/dev/null); done
for t in "$OUT"/*.tgz; do echo "$(basename "$t") $(stat -c %s "$t") B, $(tar tzf "$t" | wc -l) files, sha256 $(sha256sum "$t" | cut -c1-16)"; tar tzvf "$t" | awk '{print "   ", $3, $6}'; done
