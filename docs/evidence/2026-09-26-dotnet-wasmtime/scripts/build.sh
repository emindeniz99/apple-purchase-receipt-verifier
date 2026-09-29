#!/bin/sh
# Spike only (2026-09-26).
#   build.sh tool       the facade + harness (Release, net10.0 and net8.0)
#   build.sh consumer   pack the facade to a local feed, then a clean consumer
#                       with an EMPTY NUGET_PACKAGES restores it plus Wasmtime
#                       from nuget.org, builds and runs
set -eu
. "$(dirname "$0")/env.sh"
case "$1" in
tool)
  rm -rf "$W"; mkdir -p "$W"; cp -r "$DW/AprvWasm" "$DW/Tool" "$W/"
  start=$(date +%s)
  dotnet build -c Release "$W/Tool/Tool.csproj" -p:AprvWasmFile="$MOD" > "$S/build-tool.log" 2>&1 || { grep -E 'error|Error' "$S/build-tool.log" | head -30; exit 1; }
  echo "tool: $(( $(date +%s) - start )) s wall (restore + build, net10.0 and net8.0)"
  grep -E 'Warn|warn' "$S/build-tool.log" | grep -v 'NETSDK1138' | sort -u | head -5 || true
  echo "Wasmtime native files restored: $(cd "$NUGET_PACKAGES/wasmtime/48.0.2" && find runtimes -type f | sort | tr '\n' ' ')"
  echo "Wasmtime lib folders: $(ls "$NUGET_PACKAGES/wasmtime/48.0.2/lib" | tr '\n' ' ')"
  ;;
consumer)
  rm -rf "$S/feed" "$S/consumer" "$S/nuget-consumer"; mkdir -p "$S/feed"
  dotnet pack -c Release "$W/AprvWasm/AprvWasm.csproj" -p:AprvWasmFile="$MOD" -o "$S/feed" > "$S/pack.log" 2>&1 || { tail -20 "$S/pack.log"; exit 1; }
  NUPKG=$(ls "$S"/feed/*.nupkg)
  echo "packed: $(basename "$NUPKG") $(wc -c < "$NUPKG") bytes"
  cp -r "$DW/Consumer" "$S/consumer"
  cat > "$S/consumer/nuget.config" <<XML
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
    <add key="local" value="$S/feed" />
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>
XML
  export NUGET_PACKAGES="$S/nuget-consumer"
  start=$(date +%s)
  dotnet build -c Release -p:AprvSpikePackageVersion=0.0.0-spike "$S/consumer/Consumer.csproj" > "$S/build-consumer.log" 2>&1 || { grep -E 'error' "$S/build-consumer.log" | head -20; exit 1; }
  echo "consumer: $(( $(date +%s) - start )) s wall (restore from an empty package folder + build)"
  echo "consumer restored: $(ls "$NUGET_PACKAGES" | tr '\n' ' ')"
  G5=$(python3 -c "import json,base64; [print(base64.b64decode(c['input']).decode()) for c in map(json.loads, open('$CALLS/cases.jsonl')) if c['id']=='receipt/verify-genuine-sandbox-g5-against-apple-roots']")
  echo "consumer run: $(cd "$S" && dotnet "$S/consumer/bin/Release/net10.0/Consumer.dll" "$G5")"
  ;;
*) echo "usage: build.sh tool|consumer"; exit 2 ;;
esac
# The SDK leaves compiler servers running; stop them.
dotnet build-server shutdown > /dev/null 2>&1 || true
