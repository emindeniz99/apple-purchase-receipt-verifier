#!/bin/sh
# Spike only (2026-09-26). Builds round 4's Route C template module
# (routec-new) with ONE knob changed at a time. The recipe is round 4's
# scripts/build.sh (adapter, tree, routec), copied here with three inputs
# made variable: the OpenSSL install, cargo's release opt-level, and a
# wasm-opt pass afterwards. Nothing else differs.
#
#   build.sh openssl <name> [extra Configure args...]
#       OpenSSL 4.0.2 for wasm32-wasip1 with exactly the options of the
#       substrate bake-off's build-wasm-libs.sh, plus the extra args.
#       -> $S/inst-<name>
#   build.sh wasm <out> <openssl name> [rust opt-level]
#       -> $ART/<out>.wasm   (rust opt-level default: the shim's own, 3;
#       openssl name r4 = round 4's install, $SCRATCH/inst-wasm/openssl-4.0.2)
#   build.sh opt <in> <out> <wasm-opt args...>
#       -> $ART/<out>.wasm   (binaryen's wasm-opt on a built module)
set -eu
. "$(dirname "$0")/env.sh"
WS="$WASI_SDK"
EMU="-D_WASI_EMULATED_SIGNAL -D_WASI_EMULATED_PROCESS_CLOCKS -D_WASI_EMULATED_MMAN -D_WASI_EMULATED_GETPID"

openssl() { # name, extra args
  N="$1"; shift
  T="$SCRATCH/dl/openssl-4.0.2.tar.gz"
  echo "736b467530f916737b7031310ccb21d8218c6229e61e8e160cd1d3458cd543a8  $T" | sha256sum -c - >/dev/null
  rm -rf "$S/src/$N" "$S/inst-$N"; mkdir -p "$S/src/$N"; tar -C "$S/src/$N" -xzf "$T"
  cd "$S/src/$N/openssl-4.0.2"
  CC="$WS/bin/clang --target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot" AR="$WS/bin/llvm-ar" RANLIB="$WS/bin/llvm-ranlib" \
  ./Configure linux-generic32 no-shared no-module no-dso no-engine no-tests no-docs no-apps \
    no-autoload-config no-asm no-threads no-sock no-ui-console no-afalgeng \
    -DNO_SYSLOG -DNO_CHMOD -DOPENSSL_NO_AFALGENG=1 $EMU "$@" \
    --prefix="$S/inst-$N" --openssldir=/nonexistent/aprv-openssl --libdir=lib > "$S/configure-$N.log" 2>&1
  grep -E '^CFLAGS=|^CNF_CFLAGS=|^LIB_CFLAGS=' Makefile > "$S/cflags-$N.txt"
  perl configdata.pm -o > "$S/configdata-$N.txt" 2>&1 || true
  make -j4 build_libs > "$S/make-$N.log" 2>&1
  make install_dev >> "$S/make-$N.log" 2>&1
  cd "$S"; rm -rf "$S/src/$N"
  echo "openssl $N: $(strings "$S/inst-$N/lib/libcrypto.a" | grep -m1 '^compiler:' | sed "s#$WS#\$WASI_SDK#g")"
}

# Round 4's own scratch paths, so the embedded source paths (panic locations,
# crate hashes) match its module byte for byte and every variant below
# differs from it only by its knob.
AD="$SCRATCH/asn1/adapter-new"; T="$SCRATCH/tree-new-c"; TGT="$SCRATCH/target-new-c"

adapter() { # round 4's adapter(new 1)
  rm -rf "$AD"; mkdir -p "$AD"
  cp -r "$SPIKE/security-openssl" "$AD/"
  patch -s -d "$AD/security-openssl" -p1 < "$FUP/adapter-cms/adapter-cms.patch"
  cp "$FUP/adapter-cms/cms_path.rs" "$AD/security-openssl/src/cms_path.rs"
  patch -s -d "$AD/security-openssl" -p2 < "$A4/adapter/adapter-asn1.patch"
  cp "$A4/adapter/payload.rs" "$A4/adapter/payload_templates.rs" "$A4/adapter/payload_any.rs" \
     "$A4/adapter/payload.c" "$AD/security-openssl/src/"
}

tree() { # round 4's tree(new-c new 1)
  rm -rf "$T"; mkdir -p "$T/rust"
  tar -C "$REPO/rust" --exclude=./target --exclude=./ffi/target --exclude=./fuzz/target -cf - . | tar -C "$T/rust" -xf -
  cp "$REPO/version.txt" "$T/"
  cp "$SPIKE/core-patch/substrate.rs" "$T/rust/src/substrate.rs"
  sed "s#@SPIKE@#$SCRATCH/asn1/adapter-new#" "$SPIKE/core-patch/core.patch" | patch -s -d "$T/rust" -p1
  sed -i 's#^substrate-aws-lc = .*#&\nsubstrate-cms = ["substrate", "aprv-security-openssl/cms"]#' "$T/rust/Cargo.toml"
  patch -s --no-backup-if-mismatch -d "$T/rust" -p1 < "$PREV/core-patch/clock-seam.patch"
  sed -i 's/unix_millis_of(SystemTime::now())/unix_millis_of(crate::clock::system_now())/' "$T/rust/src/substrate.rs"
  cp "$A4/patch/spike_probe.rs" "$T/rust/src/spike_probe.rs"
  printf '\n#[doc(hidden)]\npub mod spike_probe;\n' >> "$T/rust/src/lib.rs"
  mkdir -p "$T/rust/examples"; cp "$A4/examples/spike_payload.rs" "$T/rust/examples/"
  ( cd "$T/rust" && rm src/asn1.rs src/x509.rs src/cms.rs src/crypto.rs src/chain.rs \
      fuzz/fuzz_targets/parse-der.rs fuzz/fuzz_targets/parse-certificate.rs fuzz/fuzz_targets/parse-cms.rs )
  patch -s -d "$T/rust" -p1 < "$A4/patch/no-asn1.patch"
}

wasm() { # out, openssl name, [rust opt-level]
  adapter; tree
  mkdir -p "$T/shim/src"
  sed "s#@TREE@#$T#g" "$PREV/shim/Cargo.toml.in" > "$T/shim/Cargo.toml"
  cp "$PREV/shim/src/lib.rs" "$T/shim/src/lib.rs"
  sed -i 's/^crate-type = \["cdylib", "staticlib"\]/crate-type = ["cdylib", "staticlib", "rlib"]/' "$T/rust/ffi/Cargo.toml"
  cp "$T/rust/ffi/Cargo.lock" "$T/shim/Cargo.lock"
  TT="--target=wasm32-wasip1 --sysroot=$WS/share/wasi-sysroot"
  R="-L native=$WS/share/wasi-sysroot/lib/wasm32-wasip1"
  for l in wasi-emulated-signal wasi-emulated-process-clocks wasi-emulated-mman wasi-emulated-getpid; do R="$R -l static=$l"; done
  R="$R -C link-arg=$WS/share/wasi-sysroot/lib/wasm32-wasip1/crt1-reactor.o -C link-arg=--export=_initialize --cfg aprv_host_clock"
  "$WS/bin/clang" --target=wasm32-wasip1 -O2 -c -DAPRV_HOST_RANDOM -o "$SCRATCH/asn1/wasi-none-new-c.o" "$PREV/c/wasi-none.c"
  R="$R -C link-arg=$SCRATCH/asn1/wasi-none-new-c.o"
  # "r4" is round 4's own OpenSSL install, to prove the recipe reproduces its module.
  OD="$S/inst-$2"; [ "$2" = r4 ] && OD="$SCRATCH/inst-wasm/openssl-4.0.2"
  if [ -n "${3:-}" ]; then export CARGO_PROFILE_RELEASE_OPT_LEVEL="$3"; fi
  CC_wasm32_wasip1=$WS/bin/clang CFLAGS_wasm32_wasip1="$TT" AR_wasm32_wasip1=$WS/bin/llvm-ar \
  OPENSSL_DIR="$OD" OPENSSL_STATIC=1 RUSTFLAGS="$R" \
    cargo build --release --target wasm32-wasip1 --manifest-path "$T/shim/Cargo.toml" \
      --target-dir "$TGT" --features "aprv/substrate-cms" > "$S/cargo-$1.log" 2>&1
  cp "$TGT/wasm32-wasip1/release/aprv_wasm_shim.wasm" "$ART/$1.wasm"
  echo "wasm $1: $(wc -c < "$ART/$1.wasm") bytes, sha256 $(sha256sum "$ART/$1.wasm" | cut -c1-16), imports: $(wasm-tools print "$ART/$1.wasm" | grep -oE '\(import "[^"]*" "[^"]*"' | sed 's/(import "//; s/" "/./; s/"//' | tr '\n' ' ')"
}

case "$1" in
openssl) shift; openssl "$@" ;;
wasm) wasm "$2" "$3" "${4:-}" ;;
opt)
  IN="$2"; OUT="$3"; shift 3
  wasm-opt "$@" "$ART/$IN.wasm" -o "$ART/$OUT.wasm"
  echo "opt $OUT ($*): $(wc -c < "$ART/$OUT.wasm") bytes, imports: $(wasm-tools print "$ART/$OUT.wasm" | grep -oE '\(import "[^"]*" "[^"]*"' | sed 's/(import "//; s/" "/./; s/"//' | tr '\n' ' ')"
  ;;
*) echo "usage: build.sh openssl|wasm|opt ..."; exit 2 ;;
esac
