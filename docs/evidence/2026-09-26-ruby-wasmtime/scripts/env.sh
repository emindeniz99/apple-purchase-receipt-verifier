# Spike only (2026-09-26). Shared settings for the Ruby + wasmtime-rb round.
# Needs REPO, SCRATCH and CORPORA (see ../README.md); Ruby 3.3 on PATH. Uses
# the ABI v1 module and calls files of ../../2026-09-26-wasm-abi-v1.
# Writes under $SCRATCH/rb7; gems go to a scratch GEM_HOME, never the system.
: "${REPO:?}" "${SCRATCH:?}"
RW="$REPO/docs/evidence/2026-09-26-ruby-wasmtime"      # this folder
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"
S="$SCRATCH/rb7"
MOD="$SCRATCH/abi/art/aprv-abi1.wasm"
CALLS="$SCRATCH/abi/calls"
NODEROWS="$SCRATCH/abi/run"
NATIVENEW="$SCRATCH/asn1/run/new"
export GEM_HOME="$S/consumer-gems" GEM_PATH="$S/consumer-gems"   # the clean consumer's gems
mkdir -p "$S/run"
