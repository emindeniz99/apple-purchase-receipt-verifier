#!/bin/sh
# Spike only (2026-09-27, round 10). Builds aprv-server (the 2026-09-26
# spike's crate plus ../server.patch) as variant B: Wasmtime 49.0.1
# runtime-only with the canonical module precompiled to a Cranelift .cwasm
# for the target's baseline ISA and embedded in the binary.
#
#   build.sh > results/build.txt
#
# 1. aprv-full (host glibc, Cranelift) precompiles one .cwasm per target
#    triple with APRV_TARGET=<triple>: an explicit target means the ISA
#    baseline, no host CPU features.
# 2. One build per row and feature set, into $S/bin/<row>-<set>:
#      rows  gnu            x86_64-unknown-linux-gnu, cargo build, linker: host cc (gcc)
#            musl           x86_64-unknown-linux-musl, cargo build (rustc's self-contained
#                           musl crt objects and libc.a), linker: host cc (gcc)
#            musl-mimalloc  the same with feature mimalloc (mimalloc's C built by cc-rs)
#            a64-musl, a64-musl-mimalloc   aarch64-unknown-linux-musl via cargo zigbuild
#      sets  min    server,embed        (what ships: the size rows)
#            spike  server,embed,spike  (+ /spike/call/{op} and `aprv bench`: the timing,
#                                        corpus and smoke rows)
#    plus gnu-count (spike,alloc-count) for allocation counting, and the
#    *-fastexit-min rows (server,embed,cli-fast-exit): the CLI skips the
#    runtime's teardown (see ../server.patch).
#    ONLY="row row ..." builds just those rows (reusing the .cwasm files) and
#    skips steps 1, 3 and 4.
# 3. aprv-load (the spike's load generator, host glibc).
# 4. Round 9's Rust host with Wasmtime 49.0.1 (feature wt) for
#    aarch64-unknown-linux-musl, static, for the ABI tests under QEMU.
# Each row's build log is kept in $S/run; sizes and link facts are printed.
set -eu
. "$(dirname "$0")/env.sh"
SRC="$S/src/server"
if [ ! -f "$SRC/.patched" ]; then
  rm -rf "$SRC"; mkdir -p "$S/src"; cp -r "$EV/server" "$SRC"
  patch -s -d "$SRC" -p1 < "$FE/server.patch"; touch "$SRC/.patched"
fi
M="$SRC/Cargo.toml"
[ "$(sha256sum "$WASM" | cut -c1-64)" = "$WASM_SHA256" ] || { echo "module hash mismatch" >&2; exit 1; }
echo "# build.sh, $(date -u +%F); $(rustc --version); $(cargo --version); host cc: $(cc --version | head -1)"
echo "# musl-gcc wrapper: $(dpkg-query -W -f '${Package} ${Version}' musl-tools 2>/dev/null); zig $("$ZIGVENV/bin/python" -m ziglang version), cargo-zigbuild $("$ZIGVENV/bin/cargo-zigbuild" --version | cut -d' ' -f2)"

# 1. precompile
export APRV_WASM="$WASM"
if [ -z "${ONLY:-}" ]; then
# wasmtime/all-arch: a Cranelift build has only the host's backend unless
# asked for every one ("Support for this target is disabled" otherwise).
cargo build -q --release --locked --manifest-path "$M" --target x86_64-unknown-linux-gnu --features wasmtime/all-arch > "$S/run/build-full.log" 2>&1 || { tail -30 "$S/run/build-full.log"; exit 1; }
cp "$CARGO_TARGET_DIR/x86_64-unknown-linux-gnu/release/aprv" "$S/bin/aprv-full"
for t in x86_64-unknown-linux-gnu x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  APRV_TARGET=$t "$S/bin/aprv-full" precompile "$S/art/aprv-abi1.$t.cwasm" > "$S/run/precompile.out" 2>&1 || { cat "$S/run/precompile.out"; exit 1; }
  sed "s#$S/art/##" "$S/run/precompile.out"
done
echo "x86_64 gnu vs musl .cwasm: $(cmp -l "$S/art/aprv-abi1.x86_64-unknown-linux-gnu.cwasm" "$S/art/aprv-abi1.x86_64-unknown-linux-musl.cwasm" | wc -l) bytes differ"
fi

# 2. rows
b() { # name triple how(build|zigbuild) cwasm-triple features
  name=$1; triple=$2; how=$3; ct=$4; feats=$5
  if [ -n "${ONLY:-}" ]; then case " $ONLY " in *" $name "*) ;; *) return 0 ;; esac; fi
  export APRV_CWASM="$S/art/aprv-abi1.$ct.cwasm"
  APRV_CWASM_SHA256="$(sha256sum "$APRV_CWASM" | cut -c1-64)"; export APRV_CWASM_SHA256
  start=$(date +%s)
  if [ "$how" = zigbuild ]; then
    PATH="$ZIGVENV/bin:$PATH" cargo zigbuild --release --locked --manifest-path "$M" --target "$triple" \
      --no-default-features --features "$feats" > "$S/run/build-$name.log" 2>&1 || { tail -30 "$S/run/build-$name.log"; exit 1; }
  else
    cargo build --release --locked --manifest-path "$M" --target "$triple" \
      --no-default-features --features "$feats" > "$S/run/build-$name.log" 2>&1 || { tail -30 "$S/run/build-$name.log"; exit 1; }
  fi
  f="$CARGO_TARGET_DIR/$triple/release/aprv"
  cp "$f" "$S/bin/$name"
  llvm-strip -o "$S/bin/$name.stripped" "$f"
  echo "$name | $triple | cargo $how | features $feats | $(( $(date +%s) - start )) s | raw $(stat -c %s "$f") | stripped $(stat -c %s "$S/bin/$name.stripped") | gzip -9 $(gzip -9c "$S/bin/$name.stripped" | wc -c) | xz -9 $(xz -9c "$S/bin/$name.stripped" | wc -c)"
  echo "    file: $(file -b "$f" | sed 's/, BuildID\[[^]]*\]=[0-9a-f]*//')"
  echo "    readelf: $(readelf -l "$f" | grep -c 'INTERP') INTERP, $(readelf -d "$f" 2>/dev/null | grep -c NEEDED) NEEDED$( [ "$(readelf -d "$f" 2>/dev/null | grep -c NEEDED)" -gt 0 ] && echo ": $(readelf -d "$f" | grep NEEDED | grep -o '\[.*\]' | tr '\n' ' ')")"
}
b gnu-min         x86_64-unknown-linux-gnu  build    x86_64-unknown-linux-gnu  server,embed
b musl-min        x86_64-unknown-linux-musl build    x86_64-unknown-linux-musl server,embed
b musl-mimalloc-min x86_64-unknown-linux-musl build  x86_64-unknown-linux-musl server,embed,mimalloc
b gnu-spike       x86_64-unknown-linux-gnu  build    x86_64-unknown-linux-gnu  server,embed,spike
b musl-spike      x86_64-unknown-linux-musl build    x86_64-unknown-linux-musl server,embed,spike
b musl-mimalloc-spike x86_64-unknown-linux-musl build x86_64-unknown-linux-musl server,embed,spike,mimalloc
b gnu-count       x86_64-unknown-linux-gnu  build    x86_64-unknown-linux-gnu  server,embed,spike,alloc-count
b a64-musl-min    aarch64-unknown-linux-musl zigbuild aarch64-unknown-linux-musl server,embed
b a64-musl-mimalloc-min aarch64-unknown-linux-musl zigbuild aarch64-unknown-linux-musl server,embed,mimalloc
b a64-musl-spike  aarch64-unknown-linux-musl zigbuild aarch64-unknown-linux-musl server,embed,spike
b gnu-fastexit-min x86_64-unknown-linux-gnu build   x86_64-unknown-linux-gnu  server,embed,cli-fast-exit
b musl-fastexit-min x86_64-unknown-linux-musl build x86_64-unknown-linux-musl server,embed,cli-fast-exit
b musl-mimalloc-fastexit-min x86_64-unknown-linux-musl build x86_64-unknown-linux-musl server,embed,mimalloc,cli-fast-exit
[ -n "${ONLY:-}" ] && exit 0
echo "# compilers recorded in each binary's .comment section (which toolchain built the C parts):"
for n in gnu-min musl-min musl-mimalloc-min a64-musl-min a64-musl-mimalloc-min; do
  echo "    $n: $(readelf -p .comment "$S/bin/$n" 2>/dev/null | sed -n 's/^ *\[ *[0-9a-f]*\] *//p' | sort -u | tr '\n' ';')"
done

# 3. load generator
cargo build -q --release --manifest-path "$EV/loadtest/Cargo.toml" > "$S/run/build-load.log" 2>&1 || { tail -30 "$S/run/build-load.log"; exit 1; }
cp "$CARGO_TARGET_DIR/release/aprv-load" "$S/bin/aprv-load"

# 4. round 9's host, Wasmtime 49.0.1 (Cranelift), static aarch64 musl, for the ABI tests under QEMU
PATH="$ZIGVENV/bin:$PATH" cargo zigbuild --release --locked --manifest-path "$EM/wasmi-host/Cargo.toml" \
  --target aarch64-unknown-linux-musl --features wt > "$S/run/build-a64-host.log" 2>&1 || { tail -30 "$S/run/build-a64-host.log"; exit 1; }
cp "$CARGO_TARGET_DIR/aarch64-unknown-linux-musl/release/aprv-rt-host" "$S/bin/a64-rt-host-wt"
echo "a64-rt-host-wt | round 9's host, feature wt | $(file -b "$S/bin/a64-rt-host-wt" | cut -d, -f1-2,5-6)"
