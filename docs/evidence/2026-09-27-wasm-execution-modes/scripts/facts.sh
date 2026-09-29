#!/bin/sh
# Spike only (2026-09-27, round 9). Primary sources for the rows' settings:
# crates.io (is Wasmi 2.0.0 a final release, its features), docs.rs for the
# exact versions (CompilationMode, Config::compilation_mode, the feature
# table), Wasmi's changelog and usage guide at v2.0.0, the dispatch cfg in
# the 2.0.0 crate source, and WAMR 2.4.5's build switches and the rule that
# a JIT forces the classic interpreter.
#   facts.sh > results/facts.txt
set -eu
. "$(dirname "$0")/env.sh"
F="$S/facts"; rm -rf "$F"; mkdir -p "$F"
UA="aprv-evidence-spike"
text() { python3 -c "
import html, re, sys
t = re.sub(r'<[^>]+>', ' ', sys.stdin.read())
print(html.unescape(re.sub(r'\s+', ' ', t)))"; }
echo "# fetched $(date -u +%FT%TZ)"
echo "## crates.io: wasmi versions (newest first)"
curl -sS -A "$UA" https://crates.io/api/v1/crates/wasmi/versions | python3 -c "
import json, sys
for v in json.load(sys.stdin)['versions'][:14]:
    print(f\"  {v['num']:<16} {v['created_at'][:10]} {'YANKED' if v['yanked'] else ''}\")"
for v in 1.1.0 2.0.0; do
  echo "## crates.io: wasmi $v"
  curl -sS -A "$UA" "https://crates.io/api/v1/crates/wasmi/$v" | python3 -c "
import json, sys
d = json.load(sys.stdin)['version']
print(f\"  published {d['created_at'][:10]}, yanked {d['yanked']}, rust_version {d.get('rust_version')}\")
for k, v in sorted(d['features'].items()): print(f'  feature {k} = {v}')"
done
for v in 1.1.0 2.0.0; do
  echo "## docs.rs wasmi $v: CompilationMode (HTTP $(curl -sS -o "$F/cm-$v.html" -w '%{http_code}' -L "https://docs.rs/wasmi/$v/wasmi/enum.CompilationMode.html"))"
  text < "$F/cm-$v.html" | grep -o 'pub enum CompilationMode.*deterministic amongst multiple Wasm implementations\.' | head -1 | sed 's/ § / | /g; s/^/  /'
  echo "## docs.rs wasmi $v: Config::compilation_mode (HTTP $(curl -sS -o "$F/cfg-$v.html" -w '%{http_code}' -L "https://docs.rs/wasmi/$v/wasmi/struct.Config.html"))"
  text < "$F/cfg-$v.html" | grep -o 'pub fn compilation_mode (&mut self, mode: CompilationMode ) -> &mut Self [^.]*\. By default [^.]*\.' | head -1 | sed 's/^/  /'
done
echo "## docs.rs wasmi 2.0.0: crate feature table (dispatch rows)"
curl -sS -L https://docs.rs/wasmi/2.0.0/wasmi/index.html | text | grep -oE '(auto-dispatch|portable-dispatch|indirect-dispatch) wasmi [^|]*?(Overwritten if .portable-dispatch. is enabled\.|to some extend\.|execution performance\.)' | sed 's/^/  /'
echo "## Wasmi v2.0.0 CHANGELOG.md (dispatch, unstable)"
curl -sS https://raw.githubusercontent.com/wasmi-labs/wasmi/v2.0.0/CHANGELOG.md -o "$F/CHANGELOG.md"
grep -nE 'Operator dispatch is tail-call based|default-enabled .auto-dispatch. crate feature|Enabling the .portable-dispatch. feature still takes precedence|Enable .become. with|Enable to compile Wasmi on any platform|However, this may significantly reduce execution performance|Enable to use less encoding space' "$F/CHANGELOG.md" | sed 's/^/  /'
echo "## Wasmi v2.0.0 docs/usage.md (build profile)"
curl -sS https://raw.githubusercontent.com/wasmi-labs/wasmi/v2.0.0/docs/usage.md -o "$F/usage.md"
grep -nE 'difference between a .debug. Wasmi build|lto = "fat"|codegen-units = 1' "$F/usage.md" | head -3 | sed 's/^/  /'
echo "## wasmi 2.0.0 crate source: which dispatch backend each feature set compiles"
curl -sSL -A "$UA" -o "$F/wasmi-2.0.0.crate" https://static.crates.io/crates/wasmi/wasmi-2.0.0.crate
tar xzf "$F/wasmi-2.0.0.crate" -C "$F"
sed -n '1,14p' "$F/wasmi-2.0.0/src/engine/executor/handler/dispatch/mod.rs" | tr -s ' ' | tr '\n' ' ' | sed 's/^/  /'; echo
grep -n 'fn target_has_tail_calls' -A6 "$F/wasmi-2.0.0/build.rs" | grep -E '"x86"|"x86_64"' | sed 's/^/  build.rs: /'
grep -n 'if has_tail_calls && is_optimizing' "$F/wasmi-2.0.0/build.rs" | sed 's/^/  build.rs: /'
echo "## WAMR $WAMR_TAG ($(git -C "$WAMR_SRC" rev-parse HEAD))"
git -C "$WAMR_SRC" show "$WAMR_TAG:doc/build_wamr.md" | grep -nE 'WAMR_BUILD_JIT\*\*=1/0|WAMR_BUILD_FAST_JIT\*\*=1/0|FAST_JIT\*\*=1 and \*\*WAMR_BUILD_JIT' | sed 's/^/  build_wamr.md:/'
git -C "$WAMR_SRC" show "$WAMR_TAG:build-scripts/runtime_lib.cmake" | grep -nE -A3 'if \(WAMR_BUILD_FAST_JIT EQUAL 1 OR WAMR_BUILD_JIT EQUAL 1\)' | head -4 | sed 's/^/  runtime_lib.cmake:/'
git -C "$WAMR_SRC" show "$WAMR_TAG:build-scripts/config_common.cmake" | grep -nE -A3 'if \(WAMR_BUILD_JIT EQUAL 1\)$' | head -4 | sed 's/^/  config_common.cmake:/'
git -C "$WAMR_SRC" show "$WAMR_TAG:build-scripts/config_common.cmake" | grep -nE -A2 'if \(WAMR_BUILD_FAST_JIT EQUAL 1 AND WAMR_BUILD_JIT EQUAL 1' | head -3 | sed 's/^/  config_common.cmake:/'
git -C "$WAMR_SRC" show "$WAMR_TAG:core/iwasm/common/wasm_runtime_common.c" | grep -nE -A3 'else if \(running_mode == Mode_Multi_Tier_JIT\)' | head -4 | sed 's/^/  wasm_runtime_common.c:/'
git -C "$WAMR_SRC" show "$WAMR_TAG:core/iwasm/interpreter/wasm_loader.c" | grep -nE -B1 -A1 'Wait until all jit functions are compiled for eager mode' | sed 's/^/  wasm_loader.c:/'
git -C "$WAMR_SRC" show "$WAMR_TAG:build-scripts/build_llvm.py" | grep -nE '"branch": "release/18.x"' | head -1 | sed 's/^/  build_llvm.py (the LLVM WAMR builds itself):/'
echo "## distro LLVM used for the LLVM JIT rows"
echo "  $(dpkg -s libllvm18 | grep -E '^Version') (installed runtime library); llvm-18-dev of the same version extracted, not installed"
