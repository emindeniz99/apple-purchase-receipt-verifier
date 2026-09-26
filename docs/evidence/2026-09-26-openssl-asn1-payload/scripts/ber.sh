#!/bin/sh
# Task 3: BER in the payload itself. The payloads of the genuine receipts
# (g5, legacy, the three Xcode receipts) and of three generated ones are
# taken out by the adapter's OpenSSL 4.0.2 CMS parser, re-spelled in BER by
# py/ber_variants.py, and read by all three payload readers
# (examples/spike_payload.rs --raw). results/ber-variants.txt lists each
# spelling, what the base reader (asn1.rs) returns, and whether the
# OpenSSL readers return the same bytes-for-bytes string, and whether that
# string equals the one for the original DER payload.
#
#   scripts/ber.sh > results/ber-variants.txt
set -eu
. "$(dirname "$0")/env.sh"
F="$REPO/fixtures"; D="$C/ber"; rm -rf "$D"; mkdir -p "$D/der" "$D/var"
# The eContent, taken by the adapter's OpenSSL 4.0.2 CMS parser (the example's --dump).
"$C/art/spike_payload-new" --dump="$D/der" "$F"/public-receipts/*.b64 "$F"/apple-official/xcode/xcode-app-receipt-* \
  "$F/generated/receipt.der" "$F/generated/receipt-double-wrapped.der" "$F/generated/receipt-ids.der" > /dev/null
python3 "$EV/py/ber_variants.py" "$D/var" "$D"/der/*
for t in base new any; do "$C/art/spike_payload-$t" --raw "$D"/der/* "$D"/var/* > "$D/$t.tsv"; done
python3 - "$D" <<'EOF'
import sys
d = sys.argv[1]
rows = {t: [l.rstrip("\n").split("\t") for l in open(f"{d}/{t}.tsv", encoding="utf-8")] for t in ("base", "new", "any")}
orig = {r[0]: r for r in rows["base"] if "." not in r[0]}
print("# payload spelling | bytes | base (asn1.rs) | new == base | any == base | base == base on the DER original")
counts = {}
for b, n, a in zip(rows["base"], rows["new"], rows["any"]):
    stem = b[0].split(".")[0]
    same_orig = b[2:] == orig[stem][2:]
    verdict = "OK" if b[3].startswith("OK") else b[3]
    print(f"{b[0]} | {b[1]} | {verdict} | {'yes' if b == n else 'NO'} | {'yes' if b == a else 'NO'} | {'yes' if same_orig else 'no'}")
    key = b[0].split(".", 1)[1] if "." in b[0] else "der"
    c = counts.setdefault(key, [0, 0, 0])
    c[0] += 1; c[1] += b == n; c[2] += b == a
for k, (total, new, any_) in counts.items():
    print(f"# {k}: {total} payloads, new identical on {new}, any identical on {any_}")
EOF
