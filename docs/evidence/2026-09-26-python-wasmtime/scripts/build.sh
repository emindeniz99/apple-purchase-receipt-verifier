#!/bin/sh
# Spike only (2026-09-26). Builds the facade (sdist + wheel) with the ABI v1
# module inside, then installs each into a clean virtual environment that
# takes wasmtime from PyPI, and runs a smoke test from an empty directory:
#   build.sh   -> $S/dist/*, $S/venv-wheel (Python 3.12), $S/venv-sdist (Python 3.10)
set -eu
. "$(dirname "$0")/env.sh"
export PIP_DISABLE_PIP_VERSION_CHECK=1
rm -rf "$S/facade" "$S/dist" "$S/venv-wheel" "$S/venv-sdist" "$S/consumer"
cp -r "$PW/facade" "$S/facade"
cp "$MOD" "$S/facade/src/aprv_wasm/aprv.wasm"
uv build --quiet --sdist --wheel --out-dir "$S/dist" "$S/facade"
for f in "$S"/dist/*; do echo "built: $(basename "$f") $(wc -c < "$f") bytes"; done
echo "wheel contents: $(python3 -m zipfile -l "$S"/dist/*.whl | awk 'NR>1 {print $1}' | tr '\n' ' ')"
# Clean consumers: plain venv + pip, nothing but PyPI and the built file.
mkdir -p "$S/consumer"
cat > "$S/consumer/smoke.py" <<'PY'
import base64, json, pathlib, sys
from importlib import metadata
import aprv_wasm
v = aprv_wasm.Verifier()
g5 = json.loads(sys.argv[1])
r = v.verify_receipt(g5)
print(json.dumps({"python": sys.version.split()[0], "wasmtime": metadata.version("wasmtime"),
                  "facade_from": str(pathlib.Path(aprv_wasm.__file__).parent.parent.name),
                  "verified": r["verified"], "bundleId": r["payload"]["bundleId"]}))
PY
G5=$(python3 -c "import json,base64,sys; [print(json.dumps(base64.b64decode(c['input']).decode())) for c in map(json.loads, open('$CALLS/cases.jsonl')) if c['id']=='receipt/verify-genuine-sandbox-g5-against-apple-roots']")
python3.12 -m venv "$S/venv-wheel"
"$S/venv-wheel/bin/pip" install --quiet --no-cache-dir "$S"/dist/*.whl
echo "wheel consumer: $(cd "$S/consumer" && "$S/venv-wheel/bin/python" smoke.py "$G5")"
python3.10 -m venv "$S/venv-sdist"
"$S/venv-sdist/bin/pip" install --quiet --no-cache-dir "$S"/dist/*.tar.gz
echo "sdist consumer: $(cd "$S/consumer" && "$S/venv-sdist/bin/python" smoke.py "$G5")"
echo "installed (wheel consumer): $("$S/venv-wheel/bin/pip" list --format=freeze | tr '\n' ' ')"
