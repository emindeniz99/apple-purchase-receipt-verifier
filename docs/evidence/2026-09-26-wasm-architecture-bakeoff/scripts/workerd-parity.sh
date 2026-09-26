#!/bin/sh
# Runs the 1,179-row corpus through one wasm artifact inside workerd
# (local only, nothing deployed) and compares every row with the native
# build of the same backend. Appends to results/parity.txt.
#
#   scripts/workerd-parity.sh <name> core <native> <module.wasm> [strict|trap]
#   scripts/workerd-parity.sh <name> emscripten <native> <dir with aprv-em.mjs + aprv-em.wasm>
#   scripts/workerd-parity.sh <name> jco <native> <dir with jco's aprv.js + aprv.core*.wasm> [wasi-p2-min]
#   scripts/workerd-parity.sh <name> nodewasi - <module.wasm>     (probe workerd's built-in WASI)
#
# WORKERD: the workerd binary (npm workerd 1.20260926.1).
set -eu
: "${REPO:?}" "${SCRATCH:?}" "${CORPORA:?}" "${WORKERD:?}"
EV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
NAME="$1"; KIND="$2"; NATIVE="$3"; ART="$4"; POL="${5:-trap}"
D="$SCRATCH/wdrun/$NAME"; rm -rf "$D"; mkdir -p "$D" "$SCRATCH/wrun"
cp "$EV/js/driver.mjs" "$EV/js/hosts.mjs" "$D/"
FLAGS=""
case "$KIND" in
core)
  cp "$ART" "$D/aprv.wasm"; cp "$EV/workerd/worker-core.mjs" "$D/worker.mjs"
  [ "$POL" = strict ] && echo "export const POLICY = { strictAll: true };" > "$D/policy.mjs" \
                      || echo "export const POLICY = { policy: 'trap' };" > "$D/policy.mjs"
  MODS='(name = "worker.mjs", esModule = embed "worker.mjs"), (name = "driver.mjs", esModule = embed "driver.mjs"),
    (name = "hosts.mjs", esModule = embed "hosts.mjs"), (name = "policy.mjs", esModule = embed "policy.mjs"),
    (name = "aprv.wasm", wasm = embed "aprv.wasm")' ;;
emscripten)
  cp "$ART/aprv-em.mjs" "$ART/aprv-em.wasm" "$EV/js/emscripten-host.mjs" "$D/"; cp "$EV/workerd/worker-emscripten.mjs" "$D/worker.mjs"
  MODS='(name = "worker.mjs", esModule = embed "worker.mjs"), (name = "driver.mjs", esModule = embed "driver.mjs"),
    (name = "emscripten-host.mjs", esModule = embed "emscripten-host.mjs"),
    (name = "aprv-em.mjs", esModule = embed "aprv-em.mjs"), (name = "aprv-em.wasm", wasm = embed "aprv-em.wasm")' ;;
jco)
  cp "$ART"/aprv.js "$ART"/aprv.core*.wasm "$EV/js/jco-driver.mjs" "$EV/js/wasi-p2-min.mjs" "$D/"; cp "$EV/workerd/worker-jco.mjs" "$D/worker.mjs"
  [ "$POL" = wasi-p2-min ] && echo "export const WASI_P2 = true;" > "$D/policy.mjs" || echo "export const WASI_P2 = false;" > "$D/policy.mjs"
  : > "$D/modules.mjs"; W=""; E=""
  for f in "$D"/aprv.core*.wasm; do
    b=$(basename "$f"); v=$(echo "$b" | tr -c 'a-z0-9\n' _)
    echo "import $v from './$b';" >> "$D/modules.mjs"; E="$E '$b': $v,"
    W="$W, (name = \"$b\", wasm = embed \"$b\")"
  done
  echo "export const modules = {$E };" >> "$D/modules.mjs"
  MODS="(name = \"worker.mjs\", esModule = embed \"worker.mjs\"), (name = \"driver.mjs\", esModule = embed \"driver.mjs\"),
    (name = \"wasi-p2-min.mjs\", esModule = embed \"wasi-p2-min.mjs\"), (name = \"policy.mjs\", esModule = embed \"policy.mjs\"),
    (name = \"modules.mjs\", esModule = embed \"modules.mjs\"),
    (name = \"jco-driver.mjs\", esModule = embed \"jco-driver.mjs\"), (name = \"aprv.js\", esModule = embed \"aprv.js\")$W" ;;
nodewasi)
  cp "$ART" "$D/aprv.wasm"; cp "$EV/workerd/worker-nodewasi.mjs" "$D/worker.mjs"
  FLAGS='"nodejs_compat", "enable_nodejs_wasi_module"'
  MODS='(name = "worker.mjs", esModule = embed "worker.mjs"), (name = "aprv.wasm", wasm = embed "aprv.wasm")' ;;
esac
PORT=$((20000 + $(echo "$NAME" | cksum | cut -c1-4) % 20000))
cat > "$D/config.capnp" <<CAPNP
using Workerd = import "/workerd/workerd.capnp";
const config :Workerd.Config = (
  services = [ (name = "main", worker = .w) ],
  sockets = [ (name = "http", address = "127.0.0.1:$PORT", http = (), service = "main") ],
);
const w :Workerd.Worker = (
  modules = [ $MODS ],
  compatibilityDate = "2026-09-26",
  compatibilityFlags = [ $FLAGS ],
);
CAPNP
"$WORKERD" serve --experimental "$D/config.capnp" > "$D/workerd.log" 2>&1 &
WPID=$!
trap 'kill $WPID 2>/dev/null || true' EXIT
i=0; until curl -s -o /dev/null "http://127.0.0.1:$PORT/imports" || [ $i -gt 100 ]; do i=$((i+1)); sleep 0.2; done
if [ "$KIND" = nodewasi ]; then
  echo "$NAME workerd built-in node:wasi (flags nodejs_compat, enable_nodejs_wasi_module): $(curl -s http://127.0.0.1:$PORT/)" | tee -a "$EV/results/parity.txt"
  exit 0
fi
for c in ${CORPORA_LIST:-cases hostile algorithms substrate}; do
  out="$SCRATCH/wrun/$NAME-workerd-$c.jsonl"
  curl -s --max-time 1800 --data-binary @"$CORPORA/$c.jsonl" "http://127.0.0.1:$PORT/run" > "$out"
  res=$(python3 "$SPIKE/py/same.py" "$CORPORA/$c.jsonl" "$SCRATCH/run/$NATIVE-$c.jsonl" "$out" 2>&1 | tail -1)
  echo "$NAME workerd host=$KIND/$POL $c vs native-$NATIVE: $res" | tee -a "$EV/results/parity.txt"
done
echo "$NAME workerd imports+calls: $(curl -s http://127.0.0.1:$PORT/imports | python3 -c 'import json,sys; d=json.load(sys.stdin); print(json.dumps({"imports":[i["module"]+"."+i["name"] for i in d["imports"]],"calls":d["calls"]}))')" | tee -a "$EV/results/parity.txt"
