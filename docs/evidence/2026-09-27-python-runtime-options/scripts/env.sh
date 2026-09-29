# Spike only (2026-09-27). Shared settings for the Python runtime-options
# round. Needs REPO, SCRATCH and CORPORA (see ../README.md). Uses the ABI v1
# module (sha256 b14e14b2...) and calls files of ../../2026-09-26-wasm-abi-v1,
# and round 7's Python venv with wasmtime 49.0.0 ($SCRATCH/py7/venv-wheel).
# Writes under $SCRATCH/r8.
: "${REPO:?}" "${SCRATCH:?}"
RO="$REPO/docs/evidence/2026-09-27-python-runtime-options"   # this folder
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"
S="$SCRATCH/r8"
MOD="$SCRATCH/abi/art/aprv-abi1.wasm"
CALLS="$SCRATCH/abi/calls"
NODEROWS="$SCRATCH/abi/run"
NATIVENEW="$SCRATCH/asn1/run/new"
PY="$SCRATCH/py7/venv-wheel/bin/python"      # CPython 3.12 + wasmtime 49.0.0
WAMR_TAG=WAMR-2.4.5
WAMR_SRC="$S/wamr-git"                        # git clone of bytecodealliance/wasm-micro-runtime at $WAMR_TAG
LIBS="$S/libs"                                # libiwasm builds, one per mode
export PYTHONPATH="$RO/py"
mkdir -p "$S/run" "$LIBS" "$S/cache"
