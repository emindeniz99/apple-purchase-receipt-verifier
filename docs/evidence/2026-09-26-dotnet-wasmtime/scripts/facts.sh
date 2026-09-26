#!/bin/sh
# Spike only (2026-09-26). Primary-source facts for the Wasmtime NuGet
# package: nuget.org's registration (versions, dates), the 48.0.2 nuspec
# (target frameworks, dependencies), the native files in the restored
# package, their glibc floor, the git log of bytecodealliance/wasmtime-dotnet,
# and Microsoft's .NET release index.
#   facts.sh > results/facts.txt   (after build.sh tool)
set -eu
. "$(dirname "$0")/env.sh"
F="$S/facts"; rm -rf "$F"; mkdir -p "$F"
echo "# fetched $(date -u +%FT%TZ)"
curl -sSL --compressed https://api.nuget.org/v3/registration5-gz-semver2/wasmtime/index.json -o "$F/reg.json"
python3 - "$F/reg.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
items = [it["catalogEntry"] for p in d["items"] for it in p.get("items", [])]
print(f"nuget.org Wasmtime: {len(items)} versions; last 8: " + ", ".join(f"{c['version']} ({c['published'][:10]})" for c in items[-8:]))
PY
curl -sS https://api.nuget.org/v3-flatcontainer/wasmtime/48.0.2/wasmtime.nuspec -o "$F/nuspec"
echo "48.0.2 nuspec: $(grep -oE '<license[^>]*>[^<]*|targetFramework="[^"]*"|<dependency id="[^"]*" version="[^"]*"' "$F/nuspec" | tr '\n' ' ')"
P="$S/nuget-build/wasmtime/48.0.2"
echo "native files in the package: $(cd "$P" && find runtimes -type f | sort | tr '\n' ' ')"
for r in linux-x64 linux-arm64; do
  echo "$r libwasmtime.so: highest glibc symbol version needed: $(objdump -T "$P/runtimes/$r/native/libwasmtime.so" | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1)"
done
git -c gc.auto=0 clone -q --filter=blob:none --no-checkout https://github.com/bytecodealliance/wasmtime-dotnet "$F/git"
echo "git: $(git -C "$F/git" log --since=2025-09-26 --oneline | wc -l) commits by $(git -C "$F/git" log --since=2025-09-26 --format=%an | sort -u | wc -l) authors in the 12 months to 2026-09-26; latest:"
git -C "$F/git" log -3 --format='  %cs %s' | cut -c1-110
echo "the package's own TargetFrameworks: $(git -C "$F/git" show HEAD:src/Wasmtime.csproj | grep -oE '<TargetFrameworks>[^<]*')"
curl -sS https://dotnetcli.blob.core.windows.net/dotnet/release-metadata/releases-index.json -o "$F/rel.json"
python3 - "$F/rel.json" <<'PY'
import json, sys
for r in json.load(open(sys.argv[1]))["releases-index"][:4]:
    print(f".NET {r['channel-version']}: {r['release-type']}, {r['support-phase']}, latest SDK {r['latest-sdk']}, end of support {r.get('eol-date')}")
PY
