#!/bin/sh
# Evidence only (2026-09-29). Builds aprv.wasm with WASI 0.2's
# get-random-bytes as its one import instead of our host.random-get, and
# runs the corpora through it next to the module as committed.
#
#   run.sh
#
# Needs what ../scripts/parity.sh needs, plus WASI_SDK_DIR, OPENSSL_WASM_DIR
# and PATH as rust/bindings/abi/build.sh reads them. rust/bindings/abi/build.sh
# is run on a copy of rust/ with this folder's WIT and a one-line change in
# the guest (the import's name and its u64 length, and wit-bindgen's
# `generate_all` for the wasi package); it refuses the result
# on the import check, as it must, after writing the module and the
# component, which this script then measures.
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${MODULE:?}" "${TRAPHOST:?}"
HERE="$(cd "$(dirname "$0")" && pwd)"
W="$SCRATCH/wasi-random"
rm -rf "$W/rust"
mkdir -p "$W/out"
(cd "$REPO" && git ls-files -z rust | tar --null -T - -cf -) | tar -xf - -C "$W"
cp "$HERE/aprv.wit" "$W/rust/bindings/abi/wit/aprv.wit"
mkdir -p "$W/rust/bindings/abi/wit/deps"
cp -r "$HERE/deps/random" "$W/rust/bindings/abi/wit/deps/"
sed -i 's#let bytes = bindings::aprv::verifier::host::random_get(wanted);#let bytes = bindings::wasi::random::random::get_random_bytes(u64::from(wanted));#' \
  "$W/rust/bindings/abi/src/lib.rs"
# wit-bindgen generates a package from another namespace only when asked.
sed -i 's#wit_bindgen::generate!({ path: "wit", world: "aprv" });#wit_bindgen::generate!({ path: "wit", world: "aprv", generate_all });#' \
  "$W/rust/bindings/abi/src/lib.rs"
grep -q 'get_random_bytes(u64::from(wanted))' "$W/rust/bindings/abi/src/lib.rs"
grep -q 'generate_all' "$W/rust/bindings/abi/src/lib.rs"
CARGO_TARGET_DIR="$SCRATCH/wasi-random/target" "$W/rust/bindings/abi/build.sh" "$W/out" > "$W/build.log" 2>&1 || true
grep 'build.sh: FAIL' "$W/build.log" || true
V="$W/out/aprv.wasm"
for m in "host.random-get $MODULE" "wasi:random $V"; do
  label=${m%% *}; m=${m#* }
  echo "$label module: $(wc -c < "$m") bytes, sha256 $(sha256sum "$m" | cut -c1-64)"
  echo "  imports: $(wasm-tools print "$m" | grep -oE '^ *\(import "[^"]*" "[^"]*"' | sed -E 's/^ *\(import //' | tr '\n' ' ')"
done
echo "host.random-get component: $(wc -c < "$(dirname "$MODULE")/aprv.component.wasm") bytes"
echo "wasi:random component: $(wc -c < "$W/out/aprv.component.wasm") bytes"
wasm-tools component wit "$W/out/aprv.component.wasm" | sed -n '/^world/,/^}/p'

# A trap host whose one import is wasi:random's get-random-bytes: (len i64, retptr).
sed -e "s#const HOST_MODULE = 'aprv:verifier/host@1.0.0';#const HOST_MODULE = 'wasi:random/random@0.2.6';#" \
    -e "s#const RANDOM_GET = 'random-get';#const RANDOM_GET = 'get-random-bytes';#" \
    -e 's#(len >>> 0)#Number(len)#' "$TRAPHOST" > "$(dirname "$TRAPHOST")/wasm-trap-host-wasi-random.mjs"
H2="$(dirname "$TRAPHOST")/wasm-trap-host-wasi-random.mjs"
grep -q "wasi:random/random@0.2.6" "$H2"
for c in cases hostile algorithms substrate fuzz; do
  P="$SCRATCH/parity/calls/$c.pinned.jsonl"
  s1=$(date +%s%N); node "$TRAPHOST" calls "$MODULE" "$P" > "$W/host-$c.jsonl" 2> /dev/null; s2=$(date +%s%N)
  node "$H2" calls "$V" "$P" > "$W/wasi-$c.jsonl" 2> "$W/wasi-$c.err"; s3=$(date +%s%N)
  echo "== $c: host.random-get $(( (s2 - s1) / 1000000 )) ms, wasi:random $(( (s3 - s2) / 1000000 )) ms; $(cat "$W/wasi-$c.err")"
  python3 "$HERE/../scripts/same.py" "$W/host-$c.jsonl" "$W/wasi-$c.jsonl" | sed 's/^/  /'
done
