#!/bin/sh
# Task 2: every CMS artifact on every host it supports, 1,179 rows each,
# against the native CMS build. One run at a time.
#   scripts/matrix.sh
set -eu
. "$(dirname "$0")/env.sh"
P="$EV/scripts/parity.sh"
A="$C/art"
# Route C (freestanding core module): imports aprv.clock_now_ms + aprv.random_get.
for rt in node bun deno; do "$P" js cms-c $rt trap "$A/cms-c.wasm"; done
"$P" wazero cms-c "$A/cms-c.wasm"
"$P" wasmtime cms-c "$A/cms-c.wasm"
"$P" workerd cms-c core "$A/cms-c.wasm" trap
for br in chromium firefox webkit; do "$P" browser cms-c $br "$A" 'kind=core&mod=cms-c.wasm&policy=trap'; done
# Route A (wasm32-wasip1): WASI answered by the minimal host (policy trap).
for rt in node bun deno; do "$P" js cms-w1 $rt trap "$A/cms-w1.wasm"; done
"$P" wazero cms-w1 "$A/cms-w1.wasm"
"$P" wasmtime cms-w1 "$A/cms-w1.wasm"
"$P" workerd cms-w1 core "$A/cms-w1.wasm" trap
for br in chromium firefox webkit; do "$P" browser cms-w1 $br "$A" 'kind=core&mod=cms-w1.wasm&policy=trap'; done
# Route B (Emscripten): node+web glue on Node/Bun/Deno, web-only glue in workerd.
for rt in node bun deno; do "$P" js cms-em $rt emscripten "$A/cms-em/aprv-em.mjs"; done
"$P" workerd cms-em-web emscripten "$A/cms-em-web"
for br in chromium firefox webkit; do "$P" browser cms-em $br "$A/cms-em" 'kind=emscripten&mod=aprv-em.mjs'; done
# Route D (component): Wasmtime's own Component Model and WASI 0.2; jco elsewhere.
"$P" wasmtime-component cms-comp "$A/cms-comp.component.wasm"
for rt in node bun deno; do "$P" jco cms-comp $rt "$A/cms-comp-jco/aprv.js"; done
"$P" workerd cms-comp jco "$A/cms-comp-jco" wasi-p2-min
for br in chromium firefox webkit; do "$P" browser cms-comp $br "$A/cms-comp-jco" 'kind=jco&mod=aprv.js&p2=min'; done
