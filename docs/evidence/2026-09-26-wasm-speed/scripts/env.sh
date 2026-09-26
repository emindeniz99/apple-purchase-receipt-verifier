# Spike only (2026-09-26). Shared settings for the wasm speed round.
# Needs REPO, SCRATCH, CORPORA, WASI_SDK and the JDK homes JDK21, JDK25
# (see ../README.md). Everything this round writes goes under $SCRATCH/speed.
: "${REPO:?}" "${SCRATCH:?}" "${WASI_SDK:?}"
SP="$REPO/docs/evidence/2026-09-26-wasm-speed"                # this folder
A4="$REPO/docs/evidence/2026-09-26-openssl-asn1-payload"      # round 4: adapter, patches, build recipe
R5="$REPO/docs/evidence/2026-09-26-endive-build-time-jvm"     # round 5: Endive library and consumer
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff" # clock seam, shim, wasi-none.c, js/run.mjs
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
FUP="$REPO/docs/evidence/2026-09-26-substrate-followup"
S="$SCRATCH/speed"
ART="$S/art"
# The reference: round 4's template build and its rows.
REFWASM="$SCRATCH/asn1/art/new-c.wasm"
NATIVENEW="$SCRATCH/asn1/run/new"              # native C ABI, same source
NODEROWS="$SCRATCH/asn1/wrun/new-c-node-trap"  # Node, round 4's new-c.wasm
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$SCRATCH/cargo198" RUSTUP_TOOLCHAIN=1.98.1
export PATH="$SCRATCH/tools/bin:$PATH"          # wasm-tools 1.259.0, wasm-opt (binaryen 132)
mkdir -p "$ART" "$S/run" "$S/src"
