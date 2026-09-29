# Spike only (2026-09-26, aprv-server). Shared settings. Needs REPO and
# SCRATCH (the wasm bake-off's scratch directory). Writes under $SCRATCH/server.
: "${REPO:?}" "${SCRATCH:?}"
EV="$REPO/docs/evidence/2026-09-26-aprv-server"          # this folder
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"          # the ABI v1 round (module source, Node bridge)
SV="$SCRATCH/server"                                     # this round's scratch
WASM="$SCRATCH/abi/art/aprv-abi1.wasm"                   # the canonical module (read-only)
WASM_SHA256=b14e14b2c3b8a38953c6ac03d941e42647321fdb86cfb0e3629c006687b636b3
CALLS="$SCRATCH/abi/calls"                               # ABI v1 calls per corpus (read-only)
NODEROWS="$SCRATCH/abi/run"                              # the Node reference rows (read-only)
export RUSTUP_HOME="$SCRATCH/rustup" RUSTUP_TOOLCHAIN=1.98.1
export CARGO_HOME="$SV/cargo-home" CARGO_TARGET_DIR="$SV/target"
export PATH="$RUSTUP_HOME/toolchains/1.98.1-x86_64-unknown-linux-gnu/bin:$PATH"
mkdir -p "$SV/art" "$SV/run" "$SV/bin"
