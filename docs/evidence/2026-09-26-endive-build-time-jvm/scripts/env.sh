# Spike only (2026-09-26). Shared settings for the Endive build-time spike.
# Needs REPO, SCRATCH, CORPORA and the JDK homes (JDK17, JDK21, JDK25; JDK11
# and JDK8 only for the Java-floor check);
# see ../README.md. Everything this round writes goes under $SCRATCH/endive.
: "${REPO:?}" "${SCRATCH:?}"
EV="$REPO/docs/evidence/2026-09-26-endive-build-time-jvm"   # this folder
A4="$REPO/docs/evidence/2026-09-26-openssl-asn1-payload"      # round 4 (builds aprv.wasm)
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"   # py/same.py, py/tri.py
E="$SCRATCH/endive"
# The artifact under test: round 4's Route C template build (routec-new).
WASM="${WASM:-$SCRATCH/asn1/art/new-c.wasm}"
# Round 4's rows: the native baseline (round-3 CMS build, asn1.rs payload), the
# native build of the same source as the .wasm, and Node running the same .wasm.
BASE="$SCRATCH/asn1/run/base"
NATIVENEW="$SCRATCH/asn1/run/new"          # native C ABI, same source (templates)
NODEROWS="$SCRATCH/asn1/wrun/new-c-node-trap"
ENDIVE_VERSION=1.1.0
export PATH="$SCRATCH/tools/bin:$PATH"   # wasm-tools
mkdir -p "$E/work" "$E/run" "$E/remote-repo"
