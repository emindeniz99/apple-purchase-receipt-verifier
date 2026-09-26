#!/bin/sh
# Task 1a: the npm package prototypes for OpenSSL (and LibreSSL through
# Emscripten), assembled exactly like the AWS-LC ones of the wasm bake-off
# ($PREV/scripts/npm-pack.sh) from the SAME facade files, with the
# OpenSSL/LibreSSL artifacts that bake-off built. All "private": true;
# nothing is ever published.
#   scripts/npm-pack.sh      -> $SCRATCH/fu/npm-dist/*.tgz, listing on stdout
set -eu
: "${REPO:?}" "${SCRATCH:?}"
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
FU="$REPO/docs/evidence/2026-09-26-substrate-followup"
B="$SCRATCH/fu/npm-build"; OUT="$SCRATCH/fu/npm-dist"
rm -rf "$B" "$OUT"; mkdir -p "$B" "$OUT" "$SCRATCH/fu/lic"
tar -xzf "$SCRATCH/dl/openssl-4.0.2.tar.gz" -C "$SCRATCH/fu/lic" openssl-4.0.2/LICENSE.txt
tar -xzf "$SCRATCH/dl/libressl-4.3.2.tar.gz" -C "$SCRATCH/fu/lic" libressl-4.3.2/COPYING
OSSL_LIC="$SCRATCH/fu/lic/openssl-4.0.2/LICENSE.txt"
LIBRE_LIC="$SCRATCH/fu/lic/libressl-4.3.2/COPYING"
EM_LIC="$EMSDK_DIR/emscripten/LICENSE"
notices() { # dest, library name, license files...
  d="$1"; lib="$2"; shift 2
  { echo "This package contains $lib, Rust std and crates (MIT OR Apache-2.0), compiled into its .wasm."
    echo "Licenses follow."
    for f in "$@"; do echo; echo "================================================================"; cat "$f"; done
  } > "$d/THIRD-PARTY-NOTICES.txt"
}
# package.json from the AWS-LC template, renamed.
pj() { # template dir, dest, name, description
  node -e 'const [t,d,n,s]=process.argv.slice(1);const p=JSON.parse(require("fs").readFileSync(t+"/package.json"));p.name=n;p.description=s;require("fs").writeFileSync(d+"/package.json",JSON.stringify(p,null,2)+"\n")' "$1" "$2" "$3" "$4"
}
# 1. Route C core module, OpenSSL inside (imports clock + random).
d="$B/core-openssl"; mkdir -p "$d"
cp "$PREV/npm/core/"*.js "$PREV/npm/common/abi.js" "$PREV/npm/common/index.d.ts" "$d/"
cp "$SCRATCH/art/ossl-c.wasm" "$d/aprv.wasm"
pj "$PREV/npm/core" "$d" aprv-spike-core-openssl "Spike only (never published): Route C core wasm (OpenSSL 4.0.2 inside) behind a thin JS facade."
notices "$d" "OpenSSL 4.0.2" "$OSSL_LIC"
# 2. Emscripten, OpenSSL and LibreSSL.
for lib in openssl libressl; do
  [ $lib = openssl ] && n=ossl-em || n=libressl-em
  d="$B/emscripten-$lib"; mkdir -p "$d"
  cp "$PREV/npm/emscripten/"*.js "$PREV/npm/common/abi.js" "$PREV/npm/common/index.d.ts" "$d/"
  cp "$SCRATCH/em/$n/aprv-em.wasm" "$d/aprv-em.wasm"
  cp "$SCRATCH/em/$n/aprv-em.mjs" "$d/aprv-em-node.mjs"
  cp "$SCRATCH/em/$n-web/aprv-em.mjs" "$d/aprv-em-web.mjs"
  cmp "$SCRATCH/em/$n/aprv-em.wasm" "$SCRATCH/em/$n-web/aprv-em.wasm"
  if [ $lib = openssl ]; then
    pj "$PREV/npm/emscripten" "$d" aprv-spike-emscripten-openssl "Spike only (never published): Emscripten build (OpenSSL 4.0.2 inside)."
    notices "$d" "OpenSSL 4.0.2" "$OSSL_LIC" "$EM_LIC"
  else
    pj "$PREV/npm/emscripten" "$d" aprv-spike-emscripten-libressl "Spike only (never published): Emscripten build (LibreSSL 4.3.2 inside)."
    notices "$d" "LibreSSL 4.3.2" "$LIBRE_LIC" "$EM_LIC"
  fi
done
# 3. Component (OpenSSL through the WASI 0.2 adapter), jco 1.35.0 output,
#    with the 41-line WASI 0.2 host in the package.
d="$B/component-openssl"; mkdir -p "$d"
cp -r "$SCRATCH/comp/ossl-wasi-jco/"* "$d/"
cp "$PREV/npm/component/node.js" "$PREV/npm/component/browser.js" "$PREV/npm/common/index.d.ts" "$d/"
cp "$FU/npm/component-wasi/facade.js" "$FU/npm/component-wasi/workerd.js" "$PREV/js/wasi-p2-min.mjs" "$d/"
pj "$PREV/npm/component" "$d" aprv-spike-component-openssl "Spike only (never published): the APRV WIT component (OpenSSL 4.0.2 inside, WASI 0.2 adapter), transpiled by jco 1.35.0."
node -e 'const f=process.argv[1];const p=JSON.parse(require("fs").readFileSync(f));p.files.push("*.mjs");require("fs").writeFileSync(f,JSON.stringify(p,null,2)+"\n")' "$d/package.json"
notices "$d" "OpenSSL 4.0.2" "$OSSL_LIC"
for p in core-openssl emscripten-openssl emscripten-libressl component-openssl; do (cd "$OUT" && npm pack --silent "$B/$p" >/dev/null); done
for t in "$OUT"/*.tgz; do echo "$(basename "$t") $(stat -c %s "$t") B, $(tar tzf "$t" | wc -l) files, sha256 $(sha256sum "$t" | cut -c1-16)"; tar tzvf "$t" | awk '{print "   ", $3, $6}'; done
