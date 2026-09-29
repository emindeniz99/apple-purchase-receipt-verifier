#!/bin/sh
# Ownership and review-burden counts for this bake-off (results/loc.txt).
# Rust: the previous bake-off's py/loc.py (code, unsafe lines/sites, cfg).
# Other files: py/loc_other.py.
set -eu
: "${REPO:?}" "${SCRATCH:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
cd "$REPO"
R() { python3 "$SPIKE/py/loc.py" "$@"; }
O() { python3 "$EV/py/loc_other.py" "$@"; }
echo "## existing production C ABI (rust/ffi), linked into every wasm artifact here"; R rust/ffi/src/lib.rs
echo; echo "## previous bake-off: adapter (unsafe) + policy, reused unchanged by every C-backed artifact"
R "$SPIKE/security-openssl/src/lib.rs" "$SPIKE/core-patch/substrate.rs"
echo; echo "## this bake-off, Rust: shim (Routes A/B/C) and component guest (Route D)"; R "$EV/shim/src/lib.rs" "$EV/component/guest/src/lib.rs"
echo; echo "## this bake-off, core patch (clock seam, SURFACE.md 4.1): changed lines"
grep -c '^[+-][^+-]' "$EV/core-patch/clock-seam.patch" || true
echo; echo "## hand-written C / build shims"; O "$EV/c/wasi-none.c" "$EV/cmake/emcmake-wasm32.sh"
echo; echo "## WIT"; O "$EV/component/wit/aprv.wit"
echo; echo "## hand-written JS: host glue a package would ship (per route)"
echo "# Route A/C core module: instantiate + C-ABI facade"; O "$EV/npm/core/instantiate.js" "$EV/npm/common/abi.js"
echo "# Route B Emscripten: C-ABI facade (+ Emscripten's generated glue below)"; O "$EV/npm/common/abi.js" "$EV/npm/emscripten/node.js"
echo "# Route D component: typed facade (+ jco's generated glue below)"; O "$EV/npm/component/facade.js"
echo "# optional minimal WASI 0.2 host for the OpenSSL component"; O "$EV/js/wasi-p2-min.mjs"
echo; echo "## generated JS glue (not hand-written; still shipped and reviewable)"
O --generated "$SCRATCH/em/awslc-em/aprv-em.mjs" "$SCRATCH/em/awslc-em-web/aprv-em.mjs" "$SCRATCH/em/libressl-em/aprv-em.mjs" \
  "$SCRATCH/comp/awslc-min-jco/aprv.js" "$SCRATCH/comp/ossl-wasi-jco/aprv.js"
echo; echo "## test harness only (not shipped)"; O "$EV/js/driver.mjs" "$EV/js/hosts.mjs" "$EV/js/run.mjs" "$EV/js/jco-driver.mjs" "$EV/js/run-jco.mjs" "$EV/js/emscripten-host.mjs"
