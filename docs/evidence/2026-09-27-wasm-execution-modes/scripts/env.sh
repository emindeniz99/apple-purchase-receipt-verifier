# Spike only (2026-09-27, round 9). Shared settings for the execution-mode
# bake-off. Needs REPO, SCRATCH and CORPORA (see ../README.md). Reads the
# ABI v1 module and calls files of ../../2026-09-26-wasm-abi-v1 and the Node
# reference rows; writes under $SCRATCH/r9.
: "${REPO:?}" "${SCRATCH:?}"
EM="$REPO/docs/evidence/2026-09-27-wasm-execution-modes"   # this folder
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"            # the ABI v1 round (abi_compare.py)
S="$SCRATCH/r9"
MOD="$SCRATCH/abi/art/aprv-abi1.wasm"                      # canonical module, read-only
MOD_SHA256=b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3
CALLS="$SCRATCH/abi/calls"                                 # ABI v1 calls per corpus, read-only
NODEROWS="$SCRATCH/abi/run"                                # Node reference rows, read-only
NATIVENEW="$SCRATCH/asn1/run/new"                          # round 4's native rows, read-only
# Rust: the pinned 1.98.1 (and the nightly for Wasmi's `unstable` row) that
# earlier rounds installed under $SCRATCH/rustup; a private CARGO_HOME.
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$S/cargo-home" CARGO_TARGET_DIR="$S/target"
export PATH="$RUSTUP_HOME/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:$PATH"
WAMR_TAG=WAMR-2.4.5
WAMR_SRC="$SCRATCH/r8/wamr-git"        # round 8's clone, checked out at $WAMR_TAG
LLVM_ROOT="$S/llvm18x"                 # llvm-18-dev, libzstd-dev, libxml2-dev, libpfm4-dev extracted, not installed (build-wamr.sh llvm)
PY=python3                             # the harness (standard library only)
PY312="$SCRATCH/py7/venv-wheel/bin/python"  # CPython 3.12.3, round 7/8's interpreter: runs the Python facade rows, as round 8 ran wasmtime-py
export PYTHONDONTWRITEBYTECODE=1
mkdir -p "$S/bin" "$S/run" "$S/in"
