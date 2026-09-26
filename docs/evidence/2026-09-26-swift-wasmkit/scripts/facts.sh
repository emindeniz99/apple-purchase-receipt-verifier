#!/bin/sh
# Spike only (2026-09-26). Primary-source facts: swift.org's release list,
# the toolchain signature check, and for WasmKit: its tags and dates, git
# activity, swift-tools-version and platforms, whether it has a JIT, how it
# bounds-checks memory per platform, and what its CI builds for iOS.
#   facts.sh > results/facts.txt
set -eu
. "$(dirname "$0")/env.sh"
F="$S/facts"; rm -rf "$F"; mkdir -p "$F"
echo "# fetched $(date -u +%FT%TZ)"
curl -sS https://www.swift.org/api/v1/install/releases.json -o "$F/releases.json"
python3 -c "
import json
for r in json.load(open('$F/releases.json'))[-5:]: print(f\"swift.org release {r['name']} ({r['date']})\")"
echo "toolchain used: $(swift --version 2>&1 | head -1)"
echo "signature: $(cat "$S/sigcheck.txt" 2>/dev/null || echo 'see README (gpg --verify against swift.org/keys/all-keys.asc)')"
echo "WasmKit CLI bundled with that toolchain: $(wasmkit --version 2>&1 | head -1)"
git -c gc.auto=0 clone -q --filter=blob:none https://github.com/swiftwasm/WasmKit "$F/git"
G="$F/git"
echo "WasmKit tags (newest first): $(for t in $(git -c gc.auto=0 -C "$G" tag --sort=-creatordate | head -4); do printf '%s (%s) ' "$t" "$(git -c gc.auto=0 -C "$G" log -1 --format=%cs "$t")"; done)"
echo "git: $(git -c gc.auto=0 -C "$G" log --since=2025-09-26 --oneline | wc -l) commits by $(git -c gc.auto=0 -C "$G" log --since=2025-09-26 --format=%an | sort -u | wc -l) authors in the 12 months to 2026-09-26"
echo "0.4.0 Package.swift: $(git -c gc.auto=0 -C "$G" show 0.4.0:Package.swift | head -1); $(git -c gc.auto=0 -C "$G" show 0.4.0:Package.swift | grep -m1 -oE 'platforms: \[[^]]*\]')"
echo "README, platforms: $(git -c gc.auto=0 -C "$G" show 0.4.0:README.md | grep -m1 'macOS 15+')"
echo "README, toolchains: $(git -c gc.auto=0 -C "$G" show 0.4.0:README.md | grep -m1 -o 'Starting with Swift 6.2[^.]*')"
echo "JIT: $(git -c gc.auto=0 -C "$G" grep -c -i 'jit' 0.4.0 -- Sources | awk -F: '{s+=$NF} END {print s+0}') mentions in Sources; Documentation/MprotectMemoryBoundsChecking.md: $(git -c gc.auto=0 -C "$G" show 0.4.0:Documentation/MprotectMemoryBoundsChecking.md | grep -m1 -o 'Today, WasmKit interpreters do \*\*not\*\*[^.]*')"
echo "mprotect bounds checking only on: $(git -c gc.auto=0 -C "$G" show 0.4.0:Sources/_CWasmKit/include/Platform.h | grep -B1 -m1 'WASMKIT_MPROTECT_BOUND_CHECKING 1' | head -1)"
echo "CI builds (does not run) for iOS: $(git -c gc.auto=0 -C "$G" show 0.4.0:.github/workflows/main.yml | grep -m1 -o 'build -scheme WasmKit-Package -destination generic/platform=iOS')"
