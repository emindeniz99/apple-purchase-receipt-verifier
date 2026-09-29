#!/usr/bin/env python3
"""Spike only (2026-09-27). Extract the facts this review cites from the two
audit PDFs shipped in the wasmi v2.0.0 tag (resources/audit-*.pdf).

Usage: python -m pip install pypdf   (into a scratch venv)
       audit_facts.py $SCRATCH/secrev/wasmi-git > results/audits.txt

Prints: page count, the scope/version sentences, every finding title with
its severity and status line, and the unsafe-count sentence of the Runtime
Verification report. Text comes from pypdf's extraction, so spacing inside
quoted lines can differ from the rendered PDF.
"""
import hashlib
import re
import sys

import pypdf


def text(path):
    r = pypdf.PdfReader(path)
    return len(r.pages), "\n".join(p.extract_text() or "" for p in r.pages)


def main():
    g = sys.argv[1]
    for name in ("audit-2023-12-20.pdf", "audit-2024-11-27.pdf"):
        p = f"{g}/resources/{name}"
        data = open(p, "rb").read()
        n, t = text(p)
        print(f"## resources/{name}: {n} pages, sha256 {hashlib.sha256(data).hexdigest()}")
        flat = re.sub(r"\s+", " ", t)
        for pat in [
            r"v1\.3 – Dec\s*20\s*,\s*202\s*3",
            r"This review was performed via 2 main workstreams on version v0\.31\.0",
            r"No issues were uncovered during this dedicated audit workstream[^.]*\.",
            r"The audit team created two new differential fuzzing harnesses[^.]*\.",
            r"Delivered: November 27, 2024",
            r"The audit was conducted over the course of 8 calendar weeks \([^)]*\)",
            r"The version that is the target of the audit is tagged release v0\.36\.0 which has commit hash [0-9a-f]+",
            r"Commits addressing the findings presented in this report \(with versions 0\.36\.1-5 \) have also been analyzed[^.]*\.",
            r"There are 112 usages of the unsafe keyword in wasmi v0\.36\.0 that are in scope of the audit\.",
            r"At the time of writing, all crashes and output differences have been fixed[^.]*\.",
            r"The potential errors in exceeding bounds and the fuel miscalculation have been acknowledged but not addressed\.",
        ]:
            m = re.search(pat, flat)
            if m:
                print(f"  \"{m.group(0)}\"")
        for m in re.finditer(r"\n(\[[A-Z]+\d\][^\n]*(?:\n[^\n]*){0,2}?)\nSeverity:([^\n]*)", t):
            title = re.sub(r"\s+", " ", m.group(1))
            print(f"  {title} | Severity:{m.group(2)}")


if __name__ == "__main__":
    main()
