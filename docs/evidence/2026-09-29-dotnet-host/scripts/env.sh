# Settings for the .NET host round (2026-09-29). Needs REPO and SCRATCH.
# Everything this round writes goes under $S (default $SCRATCH/dotnet-host).
: "${REPO:?}" "${SCRATCH:?}"
DH="$REPO/docs/evidence/2026-09-29-dotnet-host"     # this folder
S="${S:-$SCRATCH/dotnet-host}"
export DOTNET_CLI_HOME="$S/dotnet-home" NUGET_PACKAGES="$S/nuget"
export DOTNET_NOLOGO=1 DOTNET_CLI_TELEMETRY_OPTOUT=1
mkdir -p "$S"
