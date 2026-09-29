#!/bin/sh
# Task 5: the Rust ASN.1 crates, measured rather than recalled.
#   meta   crates.io metadata (version, last release, downloads, licence,
#          dependents and the most-downloaded ones), the published source
#          scanned for `unsafe`, `forbid(unsafe_code)` and BER/indefinite
#          handling, a shallow clone of each repository listed for fuzz and
#          audit files, and RustSec's advisories per crate.
#   probe  probe/ (der, rasn, bcder) over scripts/ber.sh's payloads.
# Sources and clones go to $C/crates (not committed).
#
#   scripts/crates.sh meta  > results/crates.txt
#   scripts/crates.sh probe > results/crate-probe.txt
set -eu
. "$(dirname "$0")/env.sh"
D="$C/crates"; mkdir -p "$D"; cd "$D"
UA="aprv-evidence-spike (research)"
case "$1" in
meta)
  echo "# $(date -u +%F). crates.io API, published .crate sources, repository HEAD, rustsec.org/packages."
  echo "# crate | version | released | downloads all/90d | licence | dependents (top by downloads) | src lines | unsafe blocks/fns | forbid(unsafe_code) | 'indefinite' mentions | repo fuzz/audit files | last commit | RustSec"
  for spec in der:RustCrypto/formats rasn:librasn/rasn asn1:alex/rust-asn1 der-parser:rusticata/der-parser \
              asn1-rs:rusticata/asn1-rs bcder:NLnetLabs/bcder yasna:qnighy/yasna.rs simple_asn1:acw/simple_asn1 \
              picky-asn1:Devolutions/picky-rs picky-asn1-der:Devolutions/picky-rs; do
    c=${spec%%:*}; repo=${spec#*:}
    curl -sS -A "$UA" "https://crates.io/api/v1/crates/$c" -o "$c.json"
    curl -sS -A "$UA" "https://crates.io/api/v1/crates/$c/reverse_dependencies?per_page=8" -o "$c.rev.json"
    v=$(python3 -c "import json;print(json.load(open('$c.json'))['crate']['max_stable_version'])")
    [ -d "$c-$v" ] || { curl -sSL -A "$UA" "https://static.crates.io/crates/$c/$c-$v.crate" -o "$c-$v.crate"; tar xzf "$c-$v.crate"; }
    g=git/$(echo "$repo" | tr / _); mkdir -p git
    [ -d "$g" ] || git clone -q --depth 1 --filter=blob:none --no-checkout "https://github.com/$repo" "$g"
    rs=$(curl -sS "https://rustsec.org/packages/$c.html" | grep -oE 'RUSTSEC-[0-9]{4}-[0-9]{4}' | sort -u | tr '\n' ' ')
    lines=$(cat $(find "$c-$v/src" -name '*.rs') | wc -l)
    uns=$(grep -rwn 'unsafe' "$c-$v/src" | grep -v 'forbid(unsafe\|deny(unsafe\|allow(unsafe' | grep -vE '^[^:]+:[0-9]+:\s*//' | wc -l)
    forbid=$(grep -rl 'forbid(unsafe_code)' "$c-$v/src" | wc -l)
    indef=$(grep -rin 'indefinite' "$c-$v/src" | wc -l)
    fuzz=$(git -C "$g" ls-tree -r HEAD --name-only | grep -iE '(^|/)fuzz[^/]*/|audit|SECURITY' | cut -d/ -f1-2 | sort -u | tr '\n' ' ')
    last=$(git -C "$g" log -1 --format=%cs)
    python3 - "$c" "$v" "$lines" "$uns" "$forbid" "$indef" "$fuzz" "$last" "$rs" <<'EOF'
import json, sys
c, v, lines, uns, forbid, indef, fuzz, last, rs = sys.argv[1:]
k = json.load(open(f"{c}.json"))
crate = k["crate"]
ver = next(x for x in k["versions"] if x["num"] == v)
r = json.load(open(f"{c}.rev.json"))
names = {x["id"]: x["crate"] for x in r.get("versions", [])}
top = []
for dep in r.get("dependencies", []):
    n = names.get(dep["version_id"])
    if n and n not in top:
        top.append(n)
print(f"{c} | {v} | {ver['created_at'][:10]} | {crate['downloads']:,}/{crate['recent_downloads']:,} | {ver['license']} | "
      f"{r['meta']['total']} ({', '.join(top[:6])}) | {lines} | {uns} | {'yes' if int(forbid) else 'no'} | {indef} | "
      f"{fuzz.strip() or '-'} | {last} | {rs.strip() or 'none'}")
EOF
  done ;;
probe)
  rm -rf "$D/probe"; cp -r "$EV/probe" "$D/probe"
  cargo build --release --manifest-path "$D/probe/Cargo.toml" --target-dir "$SCRATCH/target-probe" >&2
  cp "$D/probe/Cargo.lock" "$D/probe.Cargo.lock"
  echo "# probe/ (der 0.8.2 from_ber, rasn 0.28.15 ber::decode, bcder 0.7.7 Mode::Ber) over scripts/ber.sh's payloads."
  echo "# Per crate: attribute count and FNV-1a of the (type, value) list in encoding order, or its error. A BER"
  echo "# spelling re-encodes the nested values too, so its digest differs from the DER original's; crates agree"
  echo "# with each other on one file when they read the same attributes."
  "$SCRATCH/target-probe/release/aprv-asn1-crate-probe" "$C"/ber/der/* "$C"/ber/var/* | sed 's/\t/ | /g'
  ;;
esac
