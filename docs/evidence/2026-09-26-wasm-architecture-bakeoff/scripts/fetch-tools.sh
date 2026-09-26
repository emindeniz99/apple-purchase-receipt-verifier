#!/bin/sh
# Downloads and unpacks every toolchain this bake-off used into
# $SCRATCH/tools, checking each against the sha256 recorded on first
# download (2026-09-26; the GitHub releases publish no checksums, so these
# are trust-on-first-use except Firefox, which matches Mozilla's
# SHA256SUMS). Writes $SCRATCH/env.sh with the paths the other scripts use.
#   SCRATCH=... scripts/fetch-tools.sh
set -eu
: "${SCRATCH:?}"
DL="$SCRATCH/dl"; T="$SCRATCH/tools"; mkdir -p "$DL" "$T/bin"
get() { # url sha256 [name]
  f="$DL/${3:-$(basename "$1")}"
  [ -f "$f" ] || curl -fsSL -o "$f" "$1"
  echo "$2  $f" | sha256sum -c - >/dev/null
}
GH=https://github.com
get $GH/bytecodealliance/wasm-tools/releases/download/v1.259.0/wasm-tools-1.259.0-x86_64-linux.tar.gz 3e9b374b4c7715b771b69bf0d65a337990ed4546ec5e97e01c0ff587dfc52160
get $GH/bytecodealliance/wasmtime/releases/download/v49.0.1/wasmtime-v49.0.1-x86_64-linux.tar.xz c71f7e0d30a92e418f0d17db7c6d8f6664c1ad764340a1278678f4209deab534
get $GH/bytecodealliance/wasmtime/releases/download/v49.0.1/wasi_snapshot_preview1.reactor.wasm efb5f04f1cc9860ff1505b193545f8eed375993d34199e247723e15958fe682d
get $GH/bytecodealliance/wit-bindgen/releases/download/v0.62.0/wit-bindgen-0.62.0-x86_64-linux.tar.gz 3e81cc6523729f7532b4aa7968648a04abf0c711b7d1677150e9121f4e6458fe
get $GH/WebAssembly/binaryen/releases/download/version_132/binaryen-version_132-x86_64-linux.tar.gz 195ddc94f9bc89f45abdabb0b9eea86023d727ba90eac8b35b80f2544fc30572
get $GH/WebAssembly/wabt/releases/download/1.0.37/wabt-1.0.37-ubuntu-20.04.tar.gz cfc675dc9b663d9adc8c75d982c1ba29f661448a2e026a67e71fe3f76a3e09f3
get $GH/WebAssembly/wasi-sdk/releases/download/wasi-sdk-34/wasi-sdk-34.0-x86_64-linux.tar.gz b761e3a0721dbae9c09a0059e5fdb2bf917d1b4a8a7b430fb3b5aafb0984b2c4
# Emscripten 6.0.10: the release hash from emsdk's emscripten-releases-tags.json
# (raw.githubusercontent.com/emscripten-core/emsdk/main/...), fetched the way emsdk does.
get https://storage.googleapis.com/webassembly/emscripten-releases-builds/linux/666337b525e673e769121856d175f6f52b8ead64/wasm-binaries.tar.xz \
  a51dd2829bdf725d268974728e032533b106ea01cb482a62288ec12627a7abbe emscripten-6.0.10-wasm-binaries.tar.xz
get https://ftp.mozilla.org/pub/firefox/releases/156.0.1/linux-x86_64/en-US/firefox-156.0.1.tar.xz 7405c0487fa3e517c1e20e5aec0ed14014185dad6357d99a59b53f65acb10ed6
cd "$T"
for f in wasm-tools-1.259.0-x86_64-linux.tar.gz wit-bindgen-0.62.0-x86_64-linux.tar.gz binaryen-version_132-x86_64-linux.tar.gz \
         wabt-1.0.37-ubuntu-20.04.tar.gz wasi-sdk-34.0-x86_64-linux.tar.gz; do tar xzf "$DL/$f"; done
tar xJf "$DL/wasmtime-v49.0.1-x86_64-linux.tar.xz"; tar xJf "$DL/firefox-156.0.1.tar.xz"
mkdir -p emsdk-6.0.10 && tar -C emsdk-6.0.10 -xJf "$DL/emscripten-6.0.10-wasm-binaries.tar.xz"
ln -sf "$T/wasm-tools-1.259.0-x86_64-linux/wasm-tools" "$T/wasmtime-v49.0.1-x86_64-linux/wasmtime" \
       "$T/wit-bindgen-0.62.0-x86_64-linux/wit-bindgen" "$T/bin/"
for t in wasm-objdump wasm2wat wat2wasm wasm-strip; do ln -sf "$T/wabt-1.0.37/bin/$t" "$T/bin/"; done
for t in wasm-opt wasm-merge wasm-metadce; do ln -sf "$T/binaryen-version_132/bin/$t" "$T/bin/"; done
ln -sfn "$T/wasi-sdk-34.0-x86_64-linux" "$SCRATCH/wasi-sdk-34.0-x86_64-linux"   # path the previous bake-off's scripts use
E="$T/emsdk-6.0.10/install"
printf "LLVM_ROOT = '%s/bin'\nBINARYEN_ROOT = '%s'\nNODE_JS = '%s'\nCACHE = '%s/emcache'\n" "$E" "$E" "$(command -v node)" "$T" > "$T/emscripten.config"
# npm tools (versions pinned): workerd + wrangler, jco + preview2-shim
mkdir -p "$SCRATCH/wd" "$SCRATCH/jco"
(cd "$SCRATCH/wd" && npm init -y >/dev/null && npm install --no-audit --no-fund workerd@1.20260926.1 wrangler@4.141.0 >/dev/null)
(cd "$SCRATCH/jco" && npm init -y >/dev/null && npm install --no-audit --no-fund @bytecodealliance/jco@1.35.0 @bytecodealliance/preview2-shim@0.26.0 >/dev/null)
python3 -m venv "$SCRATCH/pyvenv" && "$SCRATCH/pyvenv/bin/pip" install -q wasmtime==49.0.0
cat > "$SCRATCH/env.sh" <<ENV
export SCRATCH=$SCRATCH
export WASI_SDK=$T/wasi-sdk-34.0-x86_64-linux
export EM_CONFIG=$T/emscripten.config
export EMSDK_DIR=$E
export WORKERD=$SCRATCH/wd/node_modules/.bin/workerd
export WRANGLER=$SCRATCH/wd/node_modules/.bin/wrangler
export FIREFOX=$T/firefox/firefox
export PATH=$T/bin:$E/emscripten:\$PATH
ENV
echo "tools ready; source $SCRATCH/env.sh (and set REPO, CORPORA, PLAYWRIGHT_MODULE)"
