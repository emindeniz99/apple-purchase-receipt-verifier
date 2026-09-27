# Spike only (2026-09-27, round 11). Shared settings for the final Python
# runtime round. Needs REPO, SCRATCH and CORPORA (see ../README.md). Reads the
# ABI v1 module, calls files and Node rows, and round 9's harness
# (../../2026-09-27-wasm-execution-modes/py: startup.py, procs.py, driver.py
# design); writes under $SCRATCH/r11.
: "${REPO:?}" "${SCRATCH:?}"
FE="$REPO/docs/evidence/2026-09-27-python-runtime-final"   # this folder
EM="$REPO/docs/evidence/2026-09-27-wasm-execution-modes"   # round 9 (read-only)
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"            # abi_compare.py
S="$SCRATCH/r11"
MOD="$SCRATCH/abi/art/aprv-abi1.wasm"
MOD_SHA256=b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3
CALLS="$SCRATCH/abi/calls"
NODEROWS="$SCRATCH/abi/run"
NATIVENEW="$SCRATCH/asn1/run/new"
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$S/cargo-home" CARGO_TARGET_DIR="$S/target"
export PATH="$RUSTUP_HOME/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:$PATH"
PY312=/usr/bin/python3.12                  # CPython 3.12.3, as rounds 8 and 9 ran their Python rows
PYWASM_VENV="$S/venv-pywasm"               # python3.12 -m venv + pip install pywasm==2.2.3
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$S/in" "$S/run" "$S/lib"
[ -f "$S/in/g5.bin" ] || python3 - "$CALLS/cases.jsonl" "$S/in/g5.bin" "$S/in/jws.bin" <<'PYEOF'
import base64, json, sys
rows = {c["id"]: c for c in map(json.loads, open(sys.argv[1]))}
open(sys.argv[2], "wb").write(base64.b64decode(rows["receipt/verify-genuine-sandbox-g5-against-apple-roots"]["input"]))
open(sys.argv[3], "wb").write(base64.b64decode(rows["transaction/verify-shared-sandbox"]["input"]))
PYEOF
