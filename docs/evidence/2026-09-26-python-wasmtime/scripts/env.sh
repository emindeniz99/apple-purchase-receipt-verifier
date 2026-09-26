# Spike only (2026-09-26). Shared settings for the Python + wasmtime-py
# round. Needs REPO, SCRATCH and CORPORA (see ../README.md). Uses the ABI v1
# module and calls files of ../../2026-09-26-wasm-abi-v1 (run its build.sh
# and node.sh first). Writes under $SCRATCH/py7.
: "${REPO:?}" "${SCRATCH:?}"
PW="$REPO/docs/evidence/2026-09-26-python-wasmtime"   # this folder
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"      # the ABI v1 round
S="$SCRATCH/py7"
MOD="$SCRATCH/abi/art/aprv-abi1.wasm"
CALLS="$SCRATCH/abi/calls"
NODEROWS="$SCRATCH/abi/run"                         # node-<corpus>.jsonl from the ABI v1 round
NATIVENEW="$SCRATCH/asn1/run/new"                   # round 4's native C ABI rows
mkdir -p "$S/dist" "$S/run"
