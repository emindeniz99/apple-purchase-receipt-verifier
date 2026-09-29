#!/bin/sh
# Spike only (2026-09-27). Primary sources for the runtime options: PyPI's
# JSON API, the upstream git logs (12 months to the run date), WAMR's
# release assets and Python binding, Wasmtime's tier document, and the
# maintenance notes in the READMEs.
#   facts.sh > results/facts.txt
set -eu
. "$(dirname "$0")/env.sh"
F="$S/facts"; rm -rf "$F"; mkdir -p "$F"
echo "# fetched $(date -u +%FT%TZ); 12-month window from $(date -u -d '-12 months' +%F)"
SINCE=$(date -u -d '-12 months' +%F)
echo "## PyPI"
for p in wasmtime wasmer pywasm3 pywasm wasmedge extism extism-sys wamr-python wamr; do
  code=$(curl -sS -o "$F/pypi-$p.json" -w '%{http_code}' "https://pypi.org/pypi/$p/json")
  if [ "$code" != 200 ]; then echo "$p: not on PyPI (HTTP $code)"; continue; fi
  python3 - "$F/pypi-$p.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1])); i = d["info"]
up = sorted((min(f["upload_time_iso_8601"] for f in fs)[:10], v) for v, fs in d["releases"].items() if fs)
whl = [f["filename"] for f in d["urls"] if f["filename"].endswith(".whl")]
tags = sorted({"-".join(w[:-4].split("-")[-3:]) for w in whl})
print(f"{i['name']}: latest {i['version']} uploaded {up[-1][0]}; requires_python {i['requires_python'] or '-'}; requires {i['requires_dist'] or '-'}; wheels: {', '.join(tags) or 'none (sdist only)'}")
PY
done
echo "## upstream git activity"
for r in bytecodealliance/wasmtime-py bytecodealliance/wasm-micro-runtime wasmerio/wasmer-python wasm3/pywasm3 wasm3/wasm3 mohanson/pywasm extism/python-sdk WasmEdge/WasmEdge; do
  n=$(echo "$r" | tr / _)
  git -c gc.auto=0 clone -q --filter=tree:0 --no-checkout "https://github.com/$r" "$F/$n"
  echo "$r: last commit $(git -C "$F/$n" log -1 --format=%cs); $(git -C "$F/$n" log --since="$SINCE" --oneline | wc -l) commits by $(git -C "$F/$n" log --since="$SINCE" --format=%an | sort -u | wc -l) authors in 12 months"
done
W="$F/bytecodealliance_wasm-micro-runtime"
echo "WAMR language-bindings/python: last commit $(git -C "$W" log -1 --format=%cs -- language-bindings/python); $(git -C "$W" log --since="$SINCE" --oneline -- language-bindings/python | wc -l) commits in 12 months"
echo "WAMR latest tag: $(git -C "$W" tag --sort=-creatordate | head -1) ($(git -C "$W" log -1 --format=%cs "$(git -C "$W" tag --sort=-creatordate | head -1)"))"
git -c gc.auto=0 clone -q --depth 1 --filter=blob:none --no-checkout https://github.com/WasmEdge/WasmEdge "$F/wasmedge-tip"
echo "WasmEdge bindings/ at the tip: $(git -C "$F/wasmedge-tip" ls-tree --name-only HEAD bindings/ | tr '\n' ' ')"
echo "## WAMR's Python binding at $WAMR_TAG (setup.py -> utils/create_lib.sh)"
git -C "$WAMR_SRC" show "$WAMR_TAG:language-bindings/python/utils/create_lib.sh" | grep -E 'DWAMR|ctypesgen' | sed 's/^ *//' | tr '\n' ' '; echo
git -C "$WAMR_SRC" show "$WAMR_TAG:language-bindings/python/src/wamr/wamrapi/wamr.py" | grep -nE 'print\("deleting|heap_size: int = ' | sed 's/^ *//' | tr '\n' ' '; echo
echo "product-mini/platforms/linux: $(git -C "$WAMR_SRC" show "$WAMR_TAG:product-mini/platforms/linux/CMakeLists.txt" | grep -A2 'WAMR_BUILD_DEBUG_INTERP EQUAL 1' | tr -s ' ' | tr '\n' ' ')"
echo "## WAMR $WAMR_TAG release assets (HTTP status of the download URL)"
V=${WAMR_TAG#WAMR-}
for a in wamrc iwasm; do for p in x86_64-ubuntu-22.04 x86_64-ubuntu-24.04 aarch64-ubuntu-22.04 x86_64-macos-13; do
  echo "  $a-$V-$p.tar.gz: $(curl -sSIL -o /dev/null -w '%{http_code}' "https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/$WAMR_TAG/$a-$V-$p.tar.gz")"
done; done
echo "  wamrc-$V-x86_64-ubuntu-22.04.tar.gz.sha256: $(curl -sSIL -o /dev/null -w '%{http_code}' "https://github.com/bytecodealliance/wasm-micro-runtime/releases/download/$WAMR_TAG/wamrc-$V-x86_64-ubuntu-22.04.tar.gz.sha256")"
echo "## Wasmtime v49.0.0 docs/stability-tiers.md"
curl -sS https://raw.githubusercontent.com/bytecodealliance/wasmtime/v49.0.0/docs/stability-tiers.md -o "$F/tiers.md"
grep -E '^\| (Compiler|Execution Backend) ' "$F/tiers.md" | tr -s ' '
grep -E '^\[\^c\]' "$F/tiers.md"
echo "## wasmtime-py 49.0.0 Config.strategy accepts: $("$PY" -c "import inspect, wasmtime; src = inspect.getsource(wasmtime.Config.strategy.fset); print(sorted(set(__import__('re').findall(r'strategy == \"(\w+)\"', src))))")"
echo "## READMEs"
echo "wasm3: $(curl -sS https://raw.githubusercontent.com/wasm3/wasm3/main/README.md | grep -o 'Wasm3 will enter a minimal maintenance phase' | head -1)"
echo "pywasm: $(curl -sS https://raw.githubusercontent.com/mohanson/pywasm/master/README.md | grep -m1 -o 'A WebAssembly interpreter written in pure Python')"
