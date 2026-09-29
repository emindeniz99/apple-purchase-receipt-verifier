#!/bin/sh
# Size and sha256 of every artifact in this bake-off (informational).
#   scripts/sizes.sh > results/sizes.txt
# raw: as built; strip: `wasm-tools strip` (custom sections, incl. names);
# gz: gzip -9 of the stripped file; Oz: `wasm-opt -Oz` (binaryen 132,
# default feature detection) then stripped and gzipped. JS: the glue a
# host must load besides the .wasm (Emscripten's ES module; jco's
# bindings; for core modules the bake-off's own js/hosts.mjs + js/driver.mjs).
set -eu
: "${REPO:?}" "${SCRATCH:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
T="$SCRATCH/sizes-tmp"; mkdir -p "$T"
sz() { stat -c %s "$1"; }
gz() { gzip -9 -c "$1" | wc -c; }
row() { # name wasm js...
  n="$1"; w="$2"; shift 2
  wasm-tools strip "$w" -o "$T/s.wasm"
  wasm-opt -Oz "$w" -o "$T/o.wasm" 2>/dev/null && wasm-tools strip "$T/o.wasm" -o "$T/os.wasm" && oz="$(sz "$T/os.wasm") / $(gz "$T/os.wasm")" || oz="n/a"
  js=0; jsg=0
  for j in "$@"; do js=$((js + $(sz "$j"))); jsg=$((jsg + $(gz "$j"))); done
  printf '%-22s raw %9s | strip %9s | strip+gz %8s | Oz+strip / gz %s | JS %7s B, gz %6s B | sha256 %s\n' \
    "$n" "$(sz "$w")" "$(sz "$T/s.wasm")" "$(gz "$T/s.wasm")" "$oz" "$js" "$jsg" "$(sha256sum "$w" | cut -c1-16)"
}
H="$EV/js/hosts.mjs"; D="$EV/js/driver.mjs"
echo "# $(date +%F). wasm-tools 1.259.0, binaryen 132, gzip -9. JS = bytes the host loads besides the wasm."
for n in rust-uu rust-w1 rust-c awslc-w1 awslc-c ossl-w1 ossl-c; do row "$n" "$SCRATCH/art/$n.wasm" "$H" "$D"; done
for n in awslc-em ossl-em libressl-em; do row "$n" "$SCRATCH/em/$n/aprv-em.wasm" "$SCRATCH/em/$n/aprv-em.mjs" "$D" "$EV/js/emscripten-host.mjs"; done
for n in awslc-em-web ossl-em-web libressl-em-web; do [ -d "$SCRATCH/em/$n" ] && row "$n" "$SCRATCH/em/$n/aprv-em.wasm" "$SCRATCH/em/$n/aprv-em.mjs" "$D" "$EV/js/emscripten-host.mjs"; done
row awslc-comp.component "$SCRATCH/comp/awslc-min.component.wasm"
row ossl-comp.component "$SCRATCH/comp/ossl-wasi.component.wasm"
for n in awslc-min-jco ossl-wasi-jco; do
  C="$SCRATCH/comp/$n"
  extra=""; [ "$n" = ossl-wasi-jco ] && extra="$EV/js/wasi-p2-min.mjs"
  row "$n(core)" "$C/aprv.core.wasm" "$C/aprv.js" "$EV/js/jco-driver.mjs" $extra
  for k in "$C"/aprv.core[0-9]*.wasm; do printf '%-22s raw %9s\n' "  +$(basename "$k")" "$(sz "$k")"; done
done
for n in rust ossl402 libressl432 awslc; do printf '%-22s native C ABI .so raw %s, sha256 %s\n' "$n" "$(sz "$SCRATCH/art/$n.so")" "$(sha256sum "$SCRATCH/art/$n.so" | cut -c1-16)"; done
rm -rf "$T"
