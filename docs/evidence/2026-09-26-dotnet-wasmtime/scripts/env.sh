# Spike only (2026-09-26). Shared settings for the .NET + wasmtime-dotnet
# round. Needs REPO, SCRATCH, CORPORA and DOTNET_ROOT (an SDK installed into
# scratch with Microsoft's dotnet-install.sh; see ../README.md). Uses the
# ABI v1 module and calls files of ../../2026-09-26-wasm-abi-v1. Writes
# under $SCRATCH/dn7; NuGet's package folder is in scratch too.
: "${REPO:?}" "${SCRATCH:?}" "${DOTNET_ROOT:?}"
DW="$REPO/docs/evidence/2026-09-26-dotnet-wasmtime"   # this folder
AB="$REPO/docs/evidence/2026-09-26-wasm-abi-v1"
S="$SCRATCH/dn7"
MOD="$SCRATCH/abi/art/aprv-abi1.wasm"
CALLS="$SCRATCH/abi/calls"
NODEROWS="$SCRATCH/abi/run"
NATIVENEW="$SCRATCH/asn1/run/new"
export PATH="$DOTNET_ROOT:$PATH" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export NUGET_PACKAGES="$S/nuget-build"
W="$S/work"
TOOL="$W/Tool/bin/Release/net10.0/Tool.dll"
TOOL8="$W/Tool/bin/Release/net8.0/Tool.dll"
mkdir -p "$S/run"
