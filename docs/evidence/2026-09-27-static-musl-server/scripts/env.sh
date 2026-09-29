# Spike only (2026-09-27, round 10). Shared settings for the static musl
# aprv-server round. Needs REPO, SCRATCH and CORPORA (see ../README.md).
# Reads the aprv-server spike (../../2026-09-26-aprv-server: server crate,
# load generator, corpus_http.py) and round 9's Rust host
# (../../2026-09-27-wasm-execution-modes/wasmi-host); writes under $SCRATCH/r10.
: "${REPO:?}" "${SCRATCH:?}"
FE="$REPO/docs/evidence/2026-09-27-static-musl-server"     # this folder
EV="$REPO/docs/evidence/2026-09-26-aprv-server"             # the aprv-server spike (read-only)
EM="$REPO/docs/evidence/2026-09-27-wasm-execution-modes"    # round 9 (read-only)
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"             # abi_compare.py
S="$SCRATCH/r10"
WASM="$SCRATCH/abi/art/aprv-abi1.wasm"                      # the canonical module (read-only)
WASM_SHA256=b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3
CALLS="$SCRATCH/abi/calls"                                  # ABI v1 calls per corpus (read-only)
NODEROWS="$SCRATCH/abi/run"                                 # the Node reference rows (read-only)
NATIVENEW="$SCRATCH/asn1/run/new"
export RUSTUP_HOME="$SCRATCH/rustup" RUSTUP_TOOLCHAIN=1.98.1
export CARGO_HOME="$S/cargo-home" CARGO_TARGET_DIR="$S/target"
export PATH="$RUSTUP_HOME/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:$PATH"
ZIGVENV="$SCRATCH/r11/venv-zig"                             # PyPI ziglang + cargo-zigbuild (round 11)
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$S/in" "$S/bin" "$S/art" "$S/run"
# Inputs, from the ABI v1 calls file (byte-identical to the aprv-server spike's):
#   g5.b64            op 1 body: the genuine sandbox g5 receipt, base64 text
#   jws-envelope.bin  op 258 body: the shared-sandbox JWS with test anchors (spike route)
#   jws.txt           op 2 body: a JWS the public route answers (verified=false, foreign root)
#   endpoint-sandbox.json  op 4 body: {"receipt-data": g5}
[ -f "$S/in/endpoint-sandbox.json" ] || python3 - "$CALLS/cases.jsonl" "$S/in" <<'PYEOF'
import base64, json, sys
rows = {c["id"]: c for c in map(json.loads, open(sys.argv[1])) if "op" in c}
d = lambda i: base64.b64decode(rows[i]["input"])
open(sys.argv[2] + "/g5.b64", "wb").write(d("receipt/verify-genuine-sandbox-g5-against-apple-roots"))
open(sys.argv[2] + "/jws-envelope.bin", "wb").write(d("transaction/verify-shared-sandbox"))
open(sys.argv[2] + "/jws.txt", "wb").write(d("transaction/reject-foreign-root"))
g5 = d("receipt/verify-genuine-sandbox-g5-against-apple-roots").decode()
open(sys.argv[2] + "/endpoint-sandbox.json", "w").write(json.dumps({"receipt-data": g5}, separators=(",", ":")))
PYEOF
