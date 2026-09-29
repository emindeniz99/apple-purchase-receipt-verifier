#!/bin/sh
# Spike only (2026-09-27). Advisory status of every crate in the Wasmi 2.0.0
# dependency graph the APRV Python runtime would ship.
#   SCRATCH=... scripts/advisories.sh > results/advisories.txt
#
# Three sources:
#   - OSV (api.osv.dev), which merges the GitHub Advisory Database and
#     RustSec for the crates.io ecosystem;
#   - a shallow clone of the RustSec advisory-db (crates/<name>/ folders);
#   - Wasmi's own GitHub security advisories page was read by hand the same
#     day (the GitHub API is not reachable from this environment); it lists
#     the same two GHSA IDs OSV returns.
set -eu
: "${SCRATCH:?}"
S="$SCRATCH/secrev"; mkdir -p "$S"
CRATES="wasmi wasmi_core wasmi_ir wasmi_collections wasmi_c_api_impl wasmi_c_api_macros wasmparser spin libm bitflags"
echo "# queried $(date -u +%FT%TZ)"
echo "## OSV: POST https://api.osv.dev/v1/query {package:{name,ecosystem:crates.io}}"
for c in $CRATES; do
  curl -sS -X POST https://api.osv.dev/v1/query \
    -d "{\"package\":{\"name\":\"$c\",\"ecosystem\":\"crates.io\"}}" | python3 -c "
import json, sys
vs = json.load(sys.stdin).get('vulns', [])
print(f'  {\"$c\":<20} {len(vs)} advisories')
for v in vs:
    rng = []
    for a in v.get('affected', []):
        for r in a.get('ranges', []):
            ev = {k: x for e in r.get('events', []) for k, x in e.items()}
            rng.append(f\"{ev.get('introduced','?')}..{ev.get('fixed','open')}\")
    print(f\"    {v['id']} {v.get('aliases', [])} published {v.get('published','')[:10]}: {v.get('summary','')}\")
    print(f\"      affected (introduced..fixed): {', '.join(rng)}\")"
done
A="$S/advisory-db"
[ -d "$A" ] || git clone -q --depth 1 https://github.com/rustsec/advisory-db.git "$A"
echo "## RustSec advisory-db $(git -C "$A" rev-parse HEAD) ($(git -C "$A" log -1 --format=%cI))"
for c in $CRATES; do
  printf '  %-20s %s\n' "$c" "$(ls "$A/crates/$c" 2>/dev/null | tr '\n' ' ' || true)"
done
echo "  (empty = no RustSec advisory for that crate)"
for f in "$A"/crates/spin/*.md; do
  printf '  spin %s: %s | patched %s\n' "$(basename "$f" .md)" \
    "$(grep -m1 '^# ' "$f" | cut -c3-)" "$(grep -m1 '^patched' "$f" | sed 's/^patched = //')"
done
