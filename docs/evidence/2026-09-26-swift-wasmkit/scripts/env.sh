# Spike only (2026-09-26). Shared settings for the Swift + WasmKit round.
# Needs REPO, SCRATCH, CORPORA and SWIFT_TC (a Swift 6.3.x toolchain from
# download.swift.org, extracted; see ../README.md). Uses the ABI v1 module
# and calls files of ../../2026-09-26-wasm-abi-v1. Writes under $SCRATCH/sw7.
: "${REPO:?}" "${SCRATCH:?}" "${SWIFT_TC:?}"
SW="$REPO/docs/evidence/2026-09-26-swift-wasmkit"     # this folder
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"
S="$SCRATCH/sw7"
MOD="$SCRATCH/abi/art/aprv-abi1.wasm"
CALLS="$SCRATCH/abi/calls"
NODEROWS="$SCRATCH/abi/run"
NATIVENEW="$SCRATCH/asn1/run/new"
export PATH="$SWIFT_TC/usr/bin:$PATH"
PKG="$S/AprvWasm"   # the directory name is the identity a path dependency sees
TOOL="$PKG/.build/release/aprv-tool"
mkdir -p "$S/run"
