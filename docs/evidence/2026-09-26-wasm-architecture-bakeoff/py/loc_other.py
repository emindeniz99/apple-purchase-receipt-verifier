#!/usr/bin/env python3
"""Code lines (not blank, not a comment-only line) for JS, C, shell and
CMake files; for generated glue, total lines and bytes as shipped.

    python3 loc_other.py [--generated] FILE...
"""
import os
import re
import sys

gen = "--generated" in sys.argv
files = [a for a in sys.argv[1:] if a != "--generated"]
tot = 0
print(f"{'file':60} {'lines':>7} {'code':>7} {'bytes':>9}")
for p in files:
    text = open(p, encoding="utf-8", errors="replace").read()
    text_nc = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    code = 0
    for l in text_nc.splitlines():
        s = l.strip()
        if not s or s.startswith("//") or s.startswith("#") and not s.startswith("#include") and not s.startswith("#if") \
                and not s.startswith("#define") and not s.startswith("#endif") and not s.startswith("#else") and not s.startswith("#ifdef") and not s.startswith("#ifndef"):
            continue
        code += 1
    n = len(text.splitlines())
    tot += code
    name = os.path.basename(os.path.dirname(p)) + "/" + os.path.basename(p)
    print(f"{name:60} {n:7} {code:7} {len(text.encode()):9}")
print(f"{'sum':60} {'':7} {tot:7}")
