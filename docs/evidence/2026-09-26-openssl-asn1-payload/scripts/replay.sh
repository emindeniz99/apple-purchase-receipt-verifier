#!/bin/sh
# Task 3: every receipt fixture in the repository, read by both payload
# readers (examples/spike_payload.rs built in the base tree = asn1.rs, and in
# the no-asn1 tree = OpenSSL templates, and payload-any), and compared line
# by line. The eContent is taken by OpenSSL's CMS parser in all three, so the
# only difference is the payload reader. The full lines stay in $C/replay
# (they print receipt contents); results/payload-replay.txt keeps, per file,
# the verdict, the in-app count, the content length and whether the three
# lines are byte-identical.
#
#   scripts/build.sh examples && scripts/replay.sh > results/payload-replay.txt
set -eu
. "$(dirname "$0")/env.sh"
F="$REPO/fixtures"
D="$C/replay"; mkdir -p "$D"
set -- "$F"/public-receipts/*.b64 "$F"/apple-official/xcode/xcode-app-receipt-* \
       "$F"/generated/receipt-b64/01-genuine.txt "$F"/limits/receipt-b64-at-cap.txt
for r in "$F"/generated/receipt*.der; do case "$r" in *-root.der) ;; *) set -- "$@" "$r" ;; esac; done
for t in base new any; do "$C/art/spike_payload-$t" "$@" > "$D/$t.tsv"; done
python3 - "$D" <<'EOF'
import sys, re
d = sys.argv[1]
rows = {t: [l.rstrip("\n").split("\t") for l in open(f"{d}/{t}.tsv", encoding="utf-8")] for t in ("base", "new", "any")}
print("# file | content bytes | creation date read before trust | payload verdict (base) | in-app purchases | new == base | any == base")
same_new = same_any = 0
for b, n, a in zip(rows["base"], rows["new"], rows["any"]):
    if b[1] == "-":  # not a signedData: no payload to read
        verdict, date = "not a signedData", "-"
    else:
        verdict = "OK" if b[3].startswith("OK") else b[3]
        date = "none" if b[2] == "None" else "some"
    iap = len(re.findall(r"InAppPurchase \{", b[3]))
    same_new += b == n
    same_any += b == a
    print(f"{b[0]} | {b[1]} | {date} | {verdict} | {iap} | {'yes' if b == n else 'NO'} | {'yes' if b == a else 'NO'}")
print(f"# {len(rows['base'])} files: new identical on {same_new}, any identical on {same_any}")
EOF
