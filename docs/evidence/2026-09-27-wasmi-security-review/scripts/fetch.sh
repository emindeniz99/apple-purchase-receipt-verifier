#!/bin/sh
# Spike only (2026-09-27). Fetch the exact third-party sources this review
# read, into $SCRATCH/secrev, and record versions and hashes.
#   REPO=... SCRATCH=... scripts/fetch.sh > results/crates.txt
#
# 1. Resolve wasmi 2.0.0 (the proposal's features: std, validate, memory64,
#    stable, auto-dispatch) plus wasmi_c_api_impl 2.0.0 in a throwaway
#    manifest, vendor the resolved crates, and print name, version, the
#    Cargo.lock checksum and the sha256 of the .crate file downloaded again
#    from static.crates.io (they must match).
# 2. Print crates.io's own record for every wasmi-family crate at 2.0.0
#    (publish date, yanked flag, checksum).
# 3. Shallow-clone wasmi at tag v2.0.0 (fuzz targets, CI, spec harness and
#    the audit PDFs are not in the published crates), and fetch the
#    CVE-2025-66627 fix commit for the note.
# Nothing is built. Sources stay in $SCRATCH; the repository gets none.
set -eu
: "${REPO:?}" "${SCRATCH:?}"
S="$SCRATCH/secrev"; mkdir -p "$S"
UA="aprv-evidence-spike"

mkdir -p "$S/resolve/src"; : > "$S/resolve/src/lib.rs"
cat > "$S/resolve/Cargo.toml" <<'EOF'
[package]
name = "resolve"
version = "0.0.0"
edition = "2021"
publish = false
[lib]
path = "src/lib.rs"
[dependencies]
wasmi = { version = "=2.0.0", default-features = false, features = ["std", "validate", "memory64", "stable", "auto-dispatch"] }
wasmi_c_api_impl = { version = "=2.0.0" }
EOF
cargo generate-lockfile --manifest-path "$S/resolve/Cargo.toml" 2>/dev/null
rm -rf "$S/vendor"
cargo vendor --manifest-path "$S/resolve/Cargo.toml" "$S/vendor" >/dev/null 2>&1
echo "# fetched $(date -u +%FT%TZ), $(cargo --version)"
echo "## normal dependency tree (cargo tree -e normal,build)"
cargo tree --manifest-path "$S/resolve/Cargo.toml" -e normal,build 2>/dev/null | sed "s|$S|\$SCRATCH/secrev|; s/^/  /"
echo "## crate, version, Cargo.lock checksum, sha256 of static.crates.io download (must match)"
echo "  (cargo vendor copies every locked package, including optional ones the"
echo "   tree above does not enable, e.g. serde/syn/hashbrown/indexmap)"
python3 - "$S/resolve/Cargo.lock" <<'EOF' | while read -r name ver sum; do
import sys, tomllib
for p in tomllib.load(open(sys.argv[1], "rb"))["package"]:
    if "checksum" in p:
        print(p["name"], p["version"], p["checksum"])
EOF
  got=$(curl -sSfL -A "$UA" "https://static.crates.io/crates/$name/$name-$ver.crate" | sha256sum | cut -d' ' -f1)
  [ "$got" = "$sum" ] && ok=match || ok=MISMATCH
  printf '  %-20s %-9s %s %s\n' "$name" "$ver" "$sum" "$ok"
done
echo "## crates.io records at 2.0.0 (publish date, yanked, checksum)"
for c in wasmi wasmi_core wasmi_ir wasmi_collections wasmi_c_api_impl wasmi_c_api_macros; do
  curl -sS -A "$UA" "https://crates.io/api/v1/crates/$c/2.0.0" | python3 -c "
import json, sys
v = json.load(sys.stdin)['version']
print(f\"  {v['crate']:<20} {v['num']} published {v['created_at'][:10]} yanked={v['yanked']} rust_version={v.get('rust_version')}\")"
done
echo "## wasmi versions on crates.io, newest first (is 2.0.0 final?)"
curl -sS -A "$UA" https://crates.io/api/v1/crates/wasmi/versions | python3 -c "
import json, sys
for v in json.load(sys.stdin)['versions'][:4]:
    print(f\"  {v['num']:<14} {v['created_at'][:10]} {'YANKED' if v['yanked'] else ''}\")"

G="$S/wasmi-git"
[ -d "$G" ] || git clone -q --depth 1 --branch v2.0.0 https://github.com/wasmi-labs/wasmi.git "$G"
echo "## upstream tag v2.0.0: $(git -C "$G" rev-parse HEAD) ($(git -C "$G" log -1 --format=%cI))"
for f in resources/audit-2023-12-20.pdf resources/audit-2024-11-27.pdf; do
  echo "  $(sha256sum "$G/$f" | cut -d' ' -f1)  $f"
done
git -C "$G" fetch -q --depth 2 origin 0e6f0d2a8325602c58d6a53ce1c0e6045eb6a490 || true
echo "## CVE-2025-66627 fix commit"
git -C "$G" show --stat --format='  %H %aI %s' 0e6f0d2a8325602c58d6a53ce1c0e6045eb6a490 | sed 's/^/  /'
