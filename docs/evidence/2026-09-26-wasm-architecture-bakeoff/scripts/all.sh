#!/bin/sh
# The whole bake-off, in the order it ran on 2026-09-26. Each step is a
# script of its own; this file is the record of how they were combined.
# One heavy build at a time; every run appends to results/parity.txt.
#
#   export REPO=... SCRATCH=... CORPORA=<previous bake-off's corpora dir>
#   export PLAYWRIGHT_MODULE=<playwright's index.mjs>   # Chromium 141 via Playwright 1.56.1
#   scripts/fetch-tools.sh && . $SCRATCH/env.sh
#   scripts/all.sh
#
# CORPORA must hold cases/hostile/algorithms/substrate.jsonl and the Java
# oracle rows jvm25-<corpus>.jsonl from the previous bake-off (its README,
# step 1). WebKit needs `apt-get install webkit2gtk-driver` and xvfb-run.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}" "${WASI_SDK:?}" "${EMSDK_DIR:?}" "${WORKERD:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
S="$EV/scripts"
cd "$SCRATCH"
A="$SCRATCH/art"; mkdir -p "$A"
keep() { # name target file-in-release -> $A/<name>.<ext>
  cp "$SCRATCH/target-$1/$2/release/$3" "$A/$1.${3##*.}"
  cp "$SCRATCH/target-$1/Cargo.lock.used" "$A/$1.Cargo.lock"
}

# 0. Native baseline: rust, ossl402, libressl432, awslc; rows in $SCRATCH/run.
"$S/native-baseline.sh"
for v in rust ossl402 libressl432 awslc; do cp "$SCRATCH/target-$v/release/libapple_purchase_receipt_verifier_ffi.so" "$A/$v.so"; done

# 1. Clock: pure Rust on wasm32-unknown-unknown without and with the seam.
CLOCK_SEAM=0 "$S/build-core.sh" rust-uu-noseam wasm32-unknown-unknown ""; keep rust-uu-noseam wasm32-unknown-unknown aprv_wasm_shim.wasm
"$S/build-core.sh" rust-uu wasm32-unknown-unknown ""; keep rust-uu wasm32-unknown-unknown aprv_wasm_shim.wasm
for n in rust-uu-noseam rust-uu; do for rt in node bun deno; do "$S/run-parity.sh" $n rust $rt trap "$A/$n.wasm"; done; done
W="$SCRATCH/wrun"
python3 "$EV/py/clock_traps.py" "$CORPORA"/cases.jsonl "$CORPORA"/hostile.jsonl "$CORPORA"/algorithms.jsonl "$CORPORA"/substrate.jsonl \
  -- "$W"/rust-uu-noseam-node-trap-cases.jsonl "$W"/rust-uu-noseam-node-trap-hostile.jsonl "$W"/rust-uu-noseam-node-trap-algorithms.jsonl "$W"/rust-uu-noseam-node-trap-substrate.jsonl \
  -- "$W"/rust-uu-node-trap-cases.jsonl "$W"/rust-uu-node-trap-hostile.jsonl "$W"/rust-uu-node-trap-algorithms.jsonl "$W"/rust-uu-node-trap-substrate.jsonl \
  > "$EV/results/clock-traps.txt"

# 2. Route A (WASI p1) and Route C (no WASI): OpenSSL for wasm, then modules.
"$S/build-wasip1.sh" openssl-lib
for l in openssl:ossl awslc:awslc rust:rust; do
  "$S/build-wasip1.sh" ${l#*:}-w1 ${l%%:*}; keep ${l#*:}-w1 wasm32-wasip1 aprv_wasm_shim.wasm
  HOST_CLOCK=1 "$S/build-wasip1.sh" ${l#*:}-w1h ${l%%:*}; keep ${l#*:}-w1h wasm32-wasip1 aprv_wasm_shim.wasm
done
STUB_WASI=1 HOST_CLOCK=1 "$S/build-wasip1.sh" awslc-c awslc; keep awslc-c wasm32-wasip1 aprv_wasm_shim.wasm
STUB_WASI=1 STUB_CFLAGS=-DAPRV_HOST_RANDOM HOST_CLOCK=1 "$S/build-wasip1.sh" ossl-c openssl; keep ossl-c wasm32-wasip1 aprv_wasm_shim.wasm
STUB_WASI=1 HOST_CLOCK=1 "$S/build-wasip1.sh" rust-c rust; keep rust-c wasm32-wasip1 aprv_wasm_shim.wasm
for m in rust-w1:rust ossl-w1:ossl402 awslc-w1:awslc; do for h in nodewasi trap; do "$S/run-parity.sh" ${m%%:*} ${m#*:} node $h "$A/${m%%:*}.wasm"; done; done
for m in rust-w1h:rust ossl-w1h:ossl402 awslc-w1h:awslc; do "$S/run-parity.sh" ${m%%:*} ${m#*:} node trap "$A/${m%%:*}.wasm"; done
for m in awslc-w1h:awslc rust-w1h:rust; do "$S/run-parity.sh" ${m%%:*} ${m#*:} node strict "$A/${m%%:*}.wasm"; done
cat "$CORPORA/cases.jsonl" "$CORPORA/algorithms.jsonl" > "$SCRATCH/cases+alg.jsonl"
node "$EV/js/callsites.mjs" "$A/ossl-w1h.wasm" "$SCRATCH/cases+alg.jsonl" wasi_snapshot_preview1.clock_time_get wasi_snapshot_preview1.random_get > "$EV/results/callsites-openssl-wasip1.txt"
node "$EV/js/callsites.mjs" "$A/awslc-w1h.wasm" "$SCRATCH/cases+alg.jsonl" wasi_snapshot_preview1.clock_time_get wasi_snapshot_preview1.random_get aprv.clock_now_ms > "$EV/results/callsites-awslc-wasip1.txt"
for mode in fail zero; do for c in cases algorithms substrate hostile; do
  APRV_RANDOM=$mode node "$EV/js/run.mjs" --host trap "$A/ossl-w1h.wasm" "$CORPORA/$c.jsonl" > "$W/ossl-w1h-rng$mode-$c.jsonl" 2>/dev/null
done; done
python3 "$EV/py/rng_summary.py" "$SCRATCH/run" "$W" > "$EV/results/rng-openssl-wasip1.txt"
go build -C "$EV/wazero" -o "$SCRATCH/wazero-run" .   # wazero v1.12.0 runner
for rt in node bun deno wazero wasmtime; do
  "$S/run-parity.sh" awslc-c awslc $rt strict "$A/awslc-c.wasm"
  "$S/run-parity.sh" rust-c rust $rt strict "$A/rust-c.wasm"
  "$S/run-parity.sh" ossl-c ossl402 $rt trap "$A/ossl-c.wasm"
done
for rt in wazero wasmtime; do "$S/run-parity.sh" awslc-w1 awslc $rt - "$A/awslc-w1.wasm"; "$S/run-parity.sh" ossl-w1 ossl402 $rt - "$A/ossl-w1.wasm"; done
"$S/workerd-parity.sh" awslc-c core awslc "$A/awslc-c.wasm" strict
"$S/workerd-parity.sh" ossl-c core ossl402 "$A/ossl-c.wasm" trap
"$S/workerd-parity.sh" rust-c core rust "$A/rust-c.wasm" strict
"$S/workerd-parity.sh" rust-uu core rust "$A/rust-uu.wasm" strict
"$S/workerd-parity.sh" awslc-w1 core awslc "$A/awslc-w1.wasm" trap
"$S/workerd-parity.sh" ossl-w1 core ossl402 "$A/ossl-w1.wasm" trap
"$S/workerd-parity.sh" awslc-w1-nodewasi nodewasi - "$A/awslc-w1.wasm"

# 3. Route B (Emscripten): libraries, cores, links, then every host.
"$S/build-emscripten.sh" openssl-lib
"$S/build-emscripten.sh" libressl-lib
"$S/build-emscripten.sh" core ossl-em openssl && "$S/build-emscripten.sh" link ossl-em
"$S/build-emscripten.sh" core awslc-em awslc && "$S/build-emscripten.sh" link awslc-em
"$S/build-emscripten.sh" core libressl-em libressl && "$S/build-emscripten.sh" link libressl-em -sFILESYSTEM=1
for m in ossl-em:ossl402: awslc-em:awslc: libressl-em:libressl432:-sFILESYSTEM=1; do
  n=${m%%:*}; r=${m#*:}; v=${r%%:*}; f=${r#*:}
  OUTNAME=$n-web "$S/build-emscripten.sh" link $n $f -sENVIRONMENT=web,worker
  for rt in node bun deno; do "$S/run-parity.sh" $n $v $rt emscripten "$SCRATCH/em/$n/aprv-em.mjs"; done
  "$S/workerd-parity.sh" $n-web emscripten $v "$SCRATCH/em/$n-web"
done

# 4. Route D (Component Model + WIT + jco).
SHIM="$EV/component/guest" CRATE_FEATURES=world-minimal STUB_WASI=1 STUB_CFLAGS=-DAPRV_CLOCK_TRAP HOST_CLOCK=1 "$S/build-wasip1.sh" awslc-comp awslc
SHIM="$EV/component/guest" STUB_WASI=1 STUB_CFLAGS=-DAPRV_KEEP_WASI_RANDOM_CLOCK "$S/build-wasip1.sh" ossl-comp openssl
"$S/build-wasip2.sh" awslc-p2
"$S/build-wasip3.sh" awslc-p3            # nightly toolchain in $SCRATCH/rustup (RUSTUP_HOME)
C="$SCRATCH/comp"; mkdir -p "$C"
wasm-tools component new "$SCRATCH/target-awslc-comp/wasm32-wasip1/release/aprv_component.wasm" -o "$C/awslc-min.component.wasm"
wasm-tools component new "$SCRATCH/target-ossl-comp/wasm32-wasip1/release/aprv_component.wasm" \
  --adapt wasi_snapshot_preview1="$SCRATCH/dl/wasi_snapshot_preview1.reactor.wasm" -o "$C/ossl-wasi.component.wasm"
cp "$SCRATCH/target-awslc-p2/wasm32-wasip2/release/aprv_component.wasm" "$C/awslc-p2.component.wasm"
cp "$SCRATCH/target-awslc-p3/wasm32-wasip3/release/aprv_component.wasm" "$C/awslc-p3.component.wasm"
JCO="$SCRATCH/jco/node_modules/.bin/jco"
for p in awslc-min:awslc-min-jco ossl-wasi:ossl-wasi-jco awslc-p2:awslc-p2-jco awslc-p3:awslc-p3-jco; do
  "$JCO" transpile "$C/${p%%:*}.component.wasm" -o "$C/${p#*:}" --name aprv --instantiation async
done
for rt in node bun deno; do
  "$S/run-parity.sh" awslc-comp awslc $rt jco "$C/awslc-min-jco/aprv.js"
  "$S/run-parity.sh" ossl-comp ossl402 $rt jco-p2min "$C/ossl-wasi-jco/aprv.js"
done
"$S/run-parity.sh" awslc-comp awslc wasmtime component "$C/awslc-min.component.wasm"
"$S/run-parity.sh" ossl-comp ossl402 wasmtime component-wasi "$C/ossl-wasi.component.wasm"
"$S/run-parity.sh" awslc-p2 awslc wasmtime component-wasi "$C/awslc-p2.component.wasm"
(cd "$SCRATCH/jco" && "$S/run-parity.sh" awslc-p2 awslc node jco-p2shim "$C/awslc-p2-jco/aprv.js" \
  && "$S/run-parity.sh" awslc-p2 awslc node jco-trapstubs "$C/awslc-p2-jco/aprv.js")
"$S/run-parity.sh" awslc-p3 awslc node jco-trapstubs "$C/awslc-p3-jco/aprv.js" || true   # fails to load: results/p3.txt
"$S/workerd-parity.sh" awslc-comp jco awslc "$C/awslc-min-jco"
"$S/workerd-parity.sh" ossl-comp jco ossl402 "$C/ossl-wasi-jco" wasi-p2-min

# 5. Browsers: every successful artifact, full corpus.
for br in chromium firefox webkit; do
  "$S/browser-parity.sh" rust-uu $br rust "$A" "kind=core&mod=rust-uu.wasm&policy=strict"
  "$S/browser-parity.sh" rust-c $br rust "$A" "kind=core&mod=rust-c.wasm&policy=strict"
  "$S/browser-parity.sh" awslc-c $br awslc "$A" "kind=core&mod=awslc-c.wasm&policy=strict"
  "$S/browser-parity.sh" ossl-c $br ossl402 "$A" "kind=core&mod=ossl-c.wasm&policy=trap"
  "$S/browser-parity.sh" awslc-em $br awslc "$SCRATCH/em/awslc-em" "kind=emscripten&mod=aprv-em.mjs"
  "$S/browser-parity.sh" ossl-em $br ossl402 "$SCRATCH/em/ossl-em" "kind=emscripten&mod=aprv-em.mjs"
  "$S/browser-parity.sh" libressl-em $br libressl432 "$SCRATCH/em/libressl-em" "kind=emscripten&mod=aprv-em.mjs"
  "$S/browser-parity.sh" awslc-comp $br awslc "$C/awslc-min-jco" "kind=jco&mod=aprv.js"
  "$S/browser-parity.sh" ossl-comp $br ossl402 "$C/ossl-wasi-jco" "kind=jco&mod=aprv.js&p2=min"
done

# 6. Inspection, sizes, performance, line counts, three-way Java tallies.
cd "$SCRATCH/art" && wasm-opt -Oz awslc-c.wasm -o awslc-c.oz.wasm && wasm-opt -Oz ossl-c.wasm -o ossl-c.oz.wasm && cd "$SCRATCH"
"$S/run-parity.sh" awslc-c.oz awslc node trap "$A/awslc-c.oz.wasm"
"$S/run-parity.sh" ossl-c.oz ossl402 node trap "$A/ossl-c.oz.wasm"
"$S/imports.sh" > "$EV/results/imports.txt"
"$S/sizes.sh" > "$EV/results/sizes.txt"
"$S/bench.sh" 1000
"$S/loc.sh" > "$EV/results/loc.txt"
"$S/java-parity.sh" > "$EV/results/java-parity.txt"

# 7. npm prototypes: pack, install from the tarballs, smoke everywhere.
"$S/npm-pack.sh" > "$EV/results/npm-pack.txt"
J="$SCRATCH/consumers/js"; rm -rf "$J"; mkdir -p "$J"
(cd "$J" && npm init -y >/dev/null && npm install --no-audit --no-fund "$SCRATCH"/npm-dist/*.tgz >/dev/null)
cp "$EV/npm/smoke.mjs" "$EV/npm/run-smoke.mjs" "$EV/npm/smoke.html" "$EV/npm/lambda/"*.mjs "$J/"
node "$EV/npm/make-vectors.mjs" "$REPO/fixtures" > "$J/vectors.mjs"
for p in aprv-spike-core aprv-spike-emscripten aprv-spike-component; do
  (cd "$J" && node run-smoke.mjs $p && bun run-smoke.mjs $p && deno run --allow-read --allow-env run-smoke.mjs $p)
  for br in chromium firefox webkit; do node "$EV/npm/browser-smoke.mjs" $br "$J" $p; done
  (cd "$J" && APRV_PKG=$p node --permission --allow-fs-read="$J" lambda-sim.mjs)
done   # rows collected into results/npm-smoke.jsonl and results/lambda-like.jsonl
K="$SCRATCH/consumers/worker"   # see README: package.json with the three tarballs, src/<pkg>.js, wrangler.toml
PORT=28101; for p in core emscripten component; do "$EV/npm/worker-smoke.sh" "$K" $p $PORT; PORT=$((PORT + 1)); done
