#!/usr/bin/env python3
"""Evidence only (2026-09-29). Sorts every difference tools/differential/
compare.mjs reports into the R20 group that explains it, by the two
answers' reasons and messages, and writes the recorded-row file the
campaign's corpora are then compared against.

    classify.py <out-recorded.json> <report.txt>... [--old <rows.jsonl>]...

A report is compare.mjs's output with --list. --old names the 0.7 Rust
core's rows for the same ids (the OpenSSL core parity note's rows) so each
group says how many of its rows 0.7 answered as the core does. Prints one
table row per group and corpus; exits 1 if any difference fits no group.
"""
import collections
import json
import re
import sys

args = sys.argv[1:]
out_path = args.pop(0)
olds = [args[i + 1] for i, a in enumerate(args) if a == "--old"]
reports = [a for i, a in enumerate(args) if a != "--old" and (i == 0 or args[i - 1] != "--old")]

old = {}
for path in olds:
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        o = r.get("out")
        if isinstance(o, str):
            try:
                o = json.loads(o)
            except ValueError:
                o = None
        if isinstance(o, dict):
            old[r["id"]] = "ok" if o.get("verified") else o.get("reason", "endpoint")

FIXTURE_GROUPS = {
    "core-review-receipt-econtent-7-levels": "java-aligns",
    "core-review-receipt-value-7-levels": "java-aligns",
    "core-review-receipt-eleven-crls": "java-aligns",
    "core-review-receipt-five-octet-length": "java-aligns",
    "der-jws-intermediate-extensions-twice": "tolerant-envelope-decoding",
    "der-receipt-certificates-field-twice": "tolerant-envelope-decoding",
    "der-receipt-intermediate-extensions-twice": "tolerant-envelope-decoding",
    "review-receipt-malformed-signed-attrs-second": "tolerant-envelope-decoding",
    "lookup-receipt-twin-ahead-of-signer": "signer-identity-twin",
}


def group(cls, rid, core, java):
    """The R20 group for one difference, or None."""
    for fixture, name in FIXTURE_GROUPS.items():
        if f"/{fixture}." in rid and not rid.startswith("fuzz/"):
            return name
    creason, cmsg = (core.split(": ", 1) + [""])[:2]
    jreason, jmsg = (java.split(": ", 1) + [""])[:2]
    if cls != "reason":
        return None
    if creason == "INVALID_CERTIFICATE" and cmsg == "receipt signer certificate does not decode" \
            and jmsg == "an embedded certificate is not a valid certificate":
        return "signer-certificate-refusal-stage"
    if creason == "MALFORMED" and (cmsg.startswith("malformed CMS structure") or "CRLs" in cmsg):
        return "envelope-decode-stage"
    if jreason == "MALFORMED" and jmsg.startswith("unexpected java."):
        return "java-catch-all"
    if jreason == "MALFORMED" and jmsg == "receipt has trailing or unparseable bytes":
        return "bouncycastle-refuses-first"
    if creason == "INVALID_CERTIFICATE" and cmsg == "x5c entry is not a valid certificate":
        return "x5c-openssl-refuses-first"
    if jreason == "INVALID_CERTIFICATE" and re.fullmatch(r"x5c\[\d\] does not decode", jmsg):
        return "x5c-jdk-refuses-first"
    if creason == "INVALID_CERTIFICATE_PURPOSE" and jmsg == "receipt signer certificate does not decode":
        return "check-order-marker-before-key"
    return None


rows = {}
table = collections.defaultdict(lambda: collections.Counter())
agree07 = collections.defaultdict(lambda: collections.Counter())
unclassified = []
for path in reports:
    corpus = path.rsplit("/", 1)[-1].removeprefix("cmp-").removesuffix(".txt")
    lines = open(path, encoding="utf-8").read().split("\n")
    for i, line in enumerate(lines):
        m = re.match(r"^(reason|payload|verdict|fault|message-only|java-no-call)\s+(\S+)$", line)
        if not m:
            continue
        cls, rid = m.groups()
        if cls in ("message-only", "java-no-call"):
            table[(corpus, cls)]["rows"] += 1
            continue
        core = lines[i + 1].strip()[len("core: "):]
        java = lines[i + 2].strip()[len("java: "):]
        if i + 3 < len(lines) and lines[i + 3].strip() == f"recorded: {cls}":
            # tools/differential/recorded.json already records it (a case row).
            table[(corpus, "recorded case row")][cls] += 1
            continue
        g = group(cls, rid, core, java)
        if g is None:
            unclassified.append((corpus, cls, rid, core, java))
            continue
        rows[rid] = {"class": cls, "group": g}
        table[(corpus, g)][cls] += 1
        creason = "ok" if core == "verified" else core.split(":")[0]
        if rid in old:
            agree07[(corpus, g)]["same as 0.7" if old[rid] == creason else f"0.7 {old[rid]}"] += 1

json.dump({"comment": "Corpus rows of the 2026-09-29 differential campaign, by R20 group (classify.py).", "rows": rows},
          open(out_path, "w", encoding="utf-8"), indent=1, sort_keys=True)
for (corpus, g), counts in sorted(table.items()):
    extra = dict(agree07.get((corpus, g), {}))
    print(f"{corpus:12} {g:36} {dict(counts)} {extra if extra else ''}")
for u in unclassified:
    print("UNCLASSIFIED", *u)
sys.exit(1 if unclassified else 0)
