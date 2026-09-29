# Spike only (2026-09-29, round 13). Shared settings for the final
# canonical-ABI check. Needs REPO, SCRATCH and CORPORA (see ../README.md).
# Reads the ABI v1 round's scratch core tree ($SCRATCH/abi/tree, the tree
# that built aprv-abi1.wasm b14e14b2...; round 12 rebuilt it byte for byte),
# its calls files and Node rows; writes under $SCRATCH/r13.
: "${REPO:?}" "${SCRATCH:?}"
FE="$REPO/docs/evidence/2026-09-29-canonical-abi-final"     # this folder
R12="$REPO/docs/evidence/2026-09-29-canonical-abi-spike"    # round 12 (read-only)
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"             # ABI v1 (read-only)
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"   # wasi-none.c
S="$SCRATCH/r13"
TREE="$SCRATCH/abi/tree"                                     # ABI v1's patched core tree (read-only)
V1="$SCRATCH/abi/art/aprv-abi1.wasm"                         # the ABI v1 module (read-only)
V1_SHA256=b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3
CALLS="$SCRATCH/abi/calls"                                   # ABI v1 calls per corpus (read-only)
NODEROWS="$SCRATCH/abi/run"                                  # the Node reference rows (read-only)
NATIVENEW="$SCRATCH/asn1/run/new"
WS="$SCRATCH/wasi-sdk-34.0-x86_64-linux"
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$SCRATCH/cargo198" RUSTUP_TOOLCHAIN=1.98.1
export PATH="$SCRATCH/tools/bin:$RUSTUP_HOME/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:$PATH"
export PYTHONDONTWRITEBYTECODE=1
MOD="$S/art/aprv-cabi.core.wasm"                             # the core module (hand-rolled hosts)
COMP="$S/art/aprv-cabi.component.wasm"                       # the component (typed hosts)
mkdir -p "$S/art" "$S/run"
