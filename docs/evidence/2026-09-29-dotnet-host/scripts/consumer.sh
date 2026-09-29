#!/bin/sh
# Packs the library, then builds and runs a clean consumer that restores it from
# a local folder feed and Wasmtime from nuget.org, starting from an empty
# package folder. Prints the nupkg's size and file list first.
#   REPO=... SCRATCH=... sh consumer.sh
set -eu
. "$(dirname "$0")/env.sh"
rm -rf "$S/feed" "$S/consumer" "$S/nuget-consumer"; mkdir -p "$S/feed"
dotnet pack -c Release "$REPO/dotnet/src/ApplePurchaseReceiptVerifier/ApplePurchaseReceiptVerifier.csproj" -o "$S/feed" > "$S/pack.log" 2>&1 \
  || { tail -20 "$S/pack.log"; exit 1; }
NUPKG=$(ls "$S"/feed/*.nupkg)
VERSION=$(basename "$NUPKG" .nupkg); VERSION=${VERSION#ApplePurchaseReceiptVerifier.}
echo "packed: $(basename "$NUPKG") $(wc -c < "$NUPKG") bytes"
python3 - "$NUPKG" <<'PY'
import sys, zipfile
for i in zipfile.ZipFile(sys.argv[1]).infolist():
    print("  %10d %s" % (i.file_size, i.filename))
PY
cp -r "$DH/Consumer" "$S/consumer"
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
dotnet build -c Release -p:AprvPackageVersion="$VERSION" "$S/consumer/Consumer.csproj" > "$S/build-consumer.log" 2>&1 \
  || { grep -E 'error' "$S/build-consumer.log" | head -20; exit 1; }
echo "consumer: $(( $(date +%s) - start )) s wall (restore from an empty package folder + build)"
echo "consumer restored: $(ls "$NUGET_PACKAGES" | tr '\n' ' ')"
echo "consumer run:"
dotnet "$S/consumer/bin/Release/net10.0/Consumer.dll" "$REPO/fixtures/public-receipts/receipt-sandbox-g5.b64"
dotnet build-server shutdown > /dev/null 2>&1 || true
