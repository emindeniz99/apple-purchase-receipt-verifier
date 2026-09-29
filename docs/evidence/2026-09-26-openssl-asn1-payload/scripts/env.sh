# Sourced by every script here. Everything in this round is built with
# rustc 1.98.1 under $SCRATCH (RUSTUP_HOME/CARGO_HOME there; the system
# toolchain is not used), except the fuzz binaries, which need nightly
# (scripts/fuzz.sh says why). OpenSSL is 4.0.2 only.
: "${REPO:?}" "${SCRATCH:?}"
export RUSTUP_HOME="$SCRATCH/rustup" CARGO_HOME="$SCRATCH/cargo198" RUSTUP_TOOLCHAIN=1.98.1
SPIKE="$REPO/docs/evidence/2026-09-26-security-substrate-bakeoff"   # adapter, policy, tri.py, same.py
PREV="$REPO/docs/evidence/2026-09-26-wasm-architecture-bakeoff"     # clock seam, shim, wasi-none.c, js/, browser/, workerd/
FUP="$REPO/docs/evidence/2026-09-26-substrate-followup"             # adapter-cms/
R3="$REPO/docs/evidence/2026-09-26-openssl-cms-everywhere"         # round 3 (fuzz_campaign.py)
EV="$REPO/docs/evidence/2026-09-26-openssl-asn1-payload"            # this folder
PREVPY="$REPO/docs/evidence/2026-09-25-java-native-image-spike/py" # run_rust.py
C="$SCRATCH/asn1"                                                   # this round's scratch
mkdir -p "$C/art" "$C/run" "$C/wrun"
