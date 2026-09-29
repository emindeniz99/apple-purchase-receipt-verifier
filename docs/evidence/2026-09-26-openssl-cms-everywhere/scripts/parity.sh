#!/bin/sh
# One CMS artifact on one host, all 1,179 rows, compared row by row with the
# native CMS build ($SCRATCH/cms/run/cms-native-<corpus>.jsonl, from
# `parity.sh native`). The runners are the wasm bake-off's, unchanged
# ($PREV/js, $PREV/py, $PREV/browser, $PREV/workerd, the wazero runner);
# only the output goes to this folder's results/parity.txt.
#
#   parity.sh native   <name> <dir with libapple_purchase_receipt_verifier_ffi.so>
#   parity.sh js       <name> <node|bun|deno> <trap|strict|emscripten> <module or glue>
#   parity.sh jco      <name> <node|bun|deno> <jco aprv.js>          (WASI 0.2 via wasi-p2-min)
#   parity.sh wazero   <name> <module>
#   parity.sh wasmtime <name> <module>
#   parity.sh wasmtime-component <name> <component.wasm>           (Wasmtime's own WASI 0.2)
#   parity.sh workerd  <name> <core|emscripten|jco> <artifact> [trap|strict|wasi-p2-min]
#   parity.sh browser  <name> <chromium|firefox|webkit> <artifact dir> '<query>'
# REF=<prefix> compares with another reference row set instead.
set -eu
. "$(dirname "$0")/env.sh"
: "${CORPORA:?}"
KIND="$1"; NAME="$2"; shift 2
REF="${REF:-$C/run/cms-native}"
LIST="${CORPORA_LIST:-cases hostile algorithms substrate}"
OUT="$EV/results/parity.txt"
cmp_rows() { # label, rows prefix
  for c in $LIST; do
    res=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$REF-$c.jsonl" "$2-$c.jsonl" 2>&1 | tail -1)
    calls=""; [ -f "$2-$c.jsonl.err" ] && calls=" | $(tail -1 "$2-$c.jsonl.err" | cut -c1-240)"
    echo "$NAME $1 $c vs $(basename "$REF"): $res$calls" | tee -a "$OUT"
  done
}
case "$KIND" in
native)
  for c in $LIST; do python3 "$PREVPY/run_rust.py" "$REPO" "$1" "$CORPORA/$c.jsonl" > "$C/run/$NAME-$c.jsonl"; done
  cmp_rows native "$C/run/$NAME" ;;
js|jco)
  RT="$1"; HOST="$2"; MOD="${3:-$2}"
  case "$RT" in node) RUN=node ;; bun) RUN=bun ;; deno) RUN="deno run --allow-read --allow-env" ;; esac
  if [ "$KIND" = jco ]; then MOD="$2"; HOST=jco-p2min; fi
  P="$C/wrun/$NAME-$RT-$HOST"
  for c in $LIST; do
    if [ "$KIND" = jco ]; then
      APRV_WASI_P2=min $RUN "$PREV/js/run-jco.mjs" "$MOD" "$CORPORA/$c.jsonl" > "$P-$c.jsonl" 2> "$P-$c.jsonl.err" || true
    else
      $RUN "$PREV/js/run.mjs" --host "$HOST" "$MOD" "$CORPORA/$c.jsonl" > "$P-$c.jsonl" 2> "$P-$c.jsonl.err" || true
    fi
  done
  cmp_rows "$RT/$HOST" "$P" ;;
wazero)
  P="$C/wrun/$NAME-wazero"
  for c in $LIST; do "$SCRATCH/wazero-run" "$1" "$CORPORA/$c.jsonl" > "$P-$c.jsonl" 2> "$P-$c.jsonl.err" || true; done
  cmp_rows wazero "$P" ;;
wasmtime|wasmtime-component)
  P="$C/wrun/$NAME-$KIND"
  for c in $LIST; do
    if [ "$KIND" = wasmtime ]; then
      "$SCRATCH/pyvenv/bin/python" "$PREV/py/run_wasmtime.py" "$1" "$CORPORA/$c.jsonl" > "$P-$c.jsonl" 2> "$P-$c.jsonl.err" || true
    else
      "$SCRATCH/pyvenv/bin/python" "$PREV/py/run_wasmtime_component.py" "$1" "$CORPORA/$c.jsonl" --wasi > "$P-$c.jsonl" 2> "$P-$c.jsonl.err" || true
    fi
  done
  cmp_rows "$KIND" "$P" ;;
browser)
  BR="$1"; ART="$2"; Q="$3"; P="$C/wrun/$NAME-$BR"
  rep=$(node "$PREV/browser/run-browser.mjs" "$BR" "$ART" "$P" "$Q&corpora=$(echo $LIST | tr ' ' ,)" 2>"$P.err")
  echo "$NAME $BR report: $rep" | cut -c1-400 | tee -a "$OUT"
  cmp_rows "$BR" "$P" ;;
workerd)
  # The wasm bake-off's workerd-parity.sh, with the output redirected here.
  W="${WORKERD:?}"; WK="$1"; ART="$2"; POL="${3:-trap}"
  D="$C/wdrun/$NAME"; rm -rf "$D"; mkdir -p "$D"
  cp "$PREV/js/driver.mjs" "$PREV/js/hosts.mjs" "$D/"
  case "$WK" in
  core)
    cp "$ART" "$D/aprv.wasm"; cp "$PREV/workerd/worker-core.mjs" "$D/worker.mjs"
    if [ "$POL" = strict ]; then echo "export const POLICY = { strictAll: true };"; else echo "export const POLICY = { policy: 'trap' };"; fi > "$D/policy.mjs"
    MODS='(name = "worker.mjs", esModule = embed "worker.mjs"), (name = "driver.mjs", esModule = embed "driver.mjs"),
      (name = "hosts.mjs", esModule = embed "hosts.mjs"), (name = "policy.mjs", esModule = embed "policy.mjs"),
      (name = "aprv.wasm", wasm = embed "aprv.wasm")' ;;
  emscripten)
    cp "$ART/aprv-em.mjs" "$ART/aprv-em.wasm" "$PREV/js/emscripten-host.mjs" "$D/"; cp "$PREV/workerd/worker-emscripten.mjs" "$D/worker.mjs"
    MODS='(name = "worker.mjs", esModule = embed "worker.mjs"), (name = "driver.mjs", esModule = embed "driver.mjs"),
      (name = "emscripten-host.mjs", esModule = embed "emscripten-host.mjs"),
      (name = "aprv-em.mjs", esModule = embed "aprv-em.mjs"), (name = "aprv-em.wasm", wasm = embed "aprv-em.wasm")' ;;
  jco)
    cp "$ART"/aprv.js "$ART"/aprv.core*.wasm "$PREV/js/jco-driver.mjs" "$PREV/js/wasi-p2-min.mjs" "$D/"; cp "$PREV/workerd/worker-jco.mjs" "$D/worker.mjs"
    if [ "$POL" = wasi-p2-min ]; then echo "export const WASI_P2 = true;"; else echo "export const WASI_P2 = false;"; fi > "$D/policy.mjs"
    : > "$D/modules.mjs"; WM=""; E=""
    for f in "$D"/aprv.core*.wasm; do
      b=$(basename "$f"); v=$(echo "$b" | tr -c 'a-z0-9\n' _)
      echo "import $v from './$b';" >> "$D/modules.mjs"; E="$E '$b': $v,"
      WM="$WM, (name = \"$b\", wasm = embed \"$b\")"
    done
    echo "export const modules = {$E };" >> "$D/modules.mjs"
    MODS="(name = \"worker.mjs\", esModule = embed \"worker.mjs\"), (name = \"driver.mjs\", esModule = embed \"driver.mjs\"),
      (name = \"wasi-p2-min.mjs\", esModule = embed \"wasi-p2-min.mjs\"), (name = \"policy.mjs\", esModule = embed \"policy.mjs\"),
      (name = \"modules.mjs\", esModule = embed \"modules.mjs\"),
      (name = \"jco-driver.mjs\", esModule = embed \"jco-driver.mjs\"), (name = \"aprv.js\", esModule = embed \"aprv.js\")$WM" ;;
  esac
  PORT=$((20000 + $(echo "$NAME" | cksum | cut -c1-4) % 20000))
  printf 'using Workerd = import "/workerd/workerd.capnp";\nconst config :Workerd.Config = (\n  services = [ (name = "main", worker = .w) ],\n  sockets = [ (name = "http", address = "127.0.0.1:%s", http = (), service = "main") ],\n);\nconst w :Workerd.Worker = (\n  modules = [ %s ],\n  compatibilityDate = "2026-09-26",\n  compatibilityFlags = [ ],\n);\n' "$PORT" "$MODS" > "$D/config.capnp"
  "$W" serve --experimental "$D/config.capnp" > "$D/workerd.log" 2>&1 &
  WPID=$!
  trap 'kill $WPID 2>/dev/null || true' EXIT
  i=0; until curl -s -o /dev/null "http://127.0.0.1:$PORT/imports" || [ $i -gt 100 ]; do i=$((i+1)); sleep 0.2; done
  P="$C/wrun/$NAME-workerd"
  for c in $LIST; do curl -s --max-time 1800 --data-binary @"$CORPORA/$c.jsonl" "http://127.0.0.1:$PORT/run" > "$P-$c.jsonl"; done
  cmp_rows "workerd/$WK/$POL" "$P"
  echo "$NAME workerd imports+calls: $(curl -s "http://127.0.0.1:$PORT/imports" | cut -c1-400)" | tee -a "$OUT"
  kill $WPID 2>/dev/null || true ;;
esac
