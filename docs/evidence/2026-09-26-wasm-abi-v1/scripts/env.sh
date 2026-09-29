# Spike only (2026-09-26, ABI v1). Shared settings. Needs REPO, SCRATCH,
# CORPORA and WASI_SDK (see ../README.md). Writes under $SCRATCH/abi.
: "${REPO:?}" "${SCRATCH:?}" "${WASI_SDK:?}"
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"               # this folder
A4="$REPO/docs/evidence/2026-09-26-openssl-asn1-payload"      # round 4: adapter, patches
R5="$REPO/docs/evidence/2026-09-26-endive-build-time-jvm"     # round 5: Endive plugin setup
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"
FUP="$REPO/docs/evidence/2026-09-26-substrate-followup"
S="$SCRATCH/abi"
MOD="$S/art/aprv-abi1.wasm"
NATIVENEW="$SCRATCH/asn1/run/new"   # round 4's native C ABI rows (templates): the reference
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$SCRATCH/cargo198" RUSTUP_TOOLCHAIN=1.98.1
export PATH="$SCRATCH/tools/bin:$PATH"
mkdir -p "$S/art" "$S/run" "$S/calls"
