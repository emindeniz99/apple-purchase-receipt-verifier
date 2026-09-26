#!/bin/sh
# Spike only (2026-09-26). Primary-source facts for the wasmtime gem:
# RubyGems' API (every platform gem of the latest version, its Ruby
# requirement, dates), the git log of bytecodealliance/wasmtime-rb, and
# where wasmtime-rb releases the GVL.
#   facts.sh > results/facts.txt
set -eu
. "$(dirname "$0")/env.sh"
F="$S/facts"; rm -rf "$F"; mkdir -p "$F"
echo "# fetched $(date -u +%FT%TZ)"
curl -sS https://rubygems.org/api/v1/versions/wasmtime.json -o "$F/versions.json"
curl -sS https://rubygems.org/api/v1/gems/wasmtime.json -o "$F/gem.json"
python3 - "$F/versions.json" "$F/gem.json" <<'PY'
import json, sys
vs = json.load(open(sys.argv[1])); g = json.load(open(sys.argv[2]))
print(f"RubyGems wasmtime: latest {g['version']}, total downloads {g['downloads']}, licenses {g['licenses']}, source {g['source_code_uri']}")
top = g["version"]
print(f"gems of {top}:")
for v in vs:
    if v["number"] == top:
        print(f"  {v['platform']:<20} ruby {v['ruby_version']:<16} {v['created_at'][:10]}")
src = [v for v in vs if v["platform"] == "ruby"]
print("last 12 source-gem releases:", ", ".join(f"{v['number']} ({v['created_at'][:10]})" for v in src[:12]))
PY
git -c gc.auto=0 clone -q --filter=blob:none --no-checkout https://github.com/bytecodealliance/wasmtime-rb "$F/git"
echo "git: $(git -C "$F/git" log --since=2025-09-26 --oneline | wc -l) commits by $(git -C "$F/git" log --since=2025-09-26 --format=%an | sort -u | wc -l) authors in the 12 months to 2026-09-26; latest:"
git -C "$F/git" log -3 --format='  %cs %s' | cut -c1-110
echo "GVL released (nogvl) at: $(git -C "$F/git" grep -n 'nogvl(' HEAD -- ext/src | sed 's/^HEAD://' | cut -d: -f1,2 | tr '\n' ' ')"
echo "native gem matrix exclusion (commit message): $(git -C "$F/git" log --format='%s' | grep -m1 -i 'arm-linux-musl')"
