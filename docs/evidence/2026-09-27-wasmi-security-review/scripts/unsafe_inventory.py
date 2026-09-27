#!/usr/bin/env python3
"""Spike only (2026-09-27). Grep-level inventory of `unsafe` in vendored crates.

Usage: unsafe_inventory.py VENDOR_DIR CRATE... > results/unsafe-raw.tsv

For every `unsafe` keyword outside comments and string literals it prints one
TSV row: crate, path (relative to VENDOR_DIR), line, kind, scope, source text.

kind:  block      `unsafe {`
       fn         `unsafe fn` / `unsafe extern "C" fn`
       impl       `unsafe impl`
       trait      `unsafe trait`
       attr       `unsafe(no_mangle)` inside `#[...]` or `#[cfg_attr(..)]`
                  (edition 2024 spelling of an exported C symbol)
       extern     `unsafe extern "C" {` block
       other      anything else (read by hand)
scope: test       file under tests/ or benches/, a tests.rs, or inside a
                  `#[cfg(test)]` item (tracked by brace depth)
       build      build.rs
       src        everything else

It is a lexer-free heuristic: it strips `//` comments, `/* */` comments and
"..." strings on a line-by-line basis. Raw strings and char literals
containing quotes are rare in these crates; the per-file totals were
cross-checked against `grep -c '\\bunsafe\\b'`.
"""
import os
import re
import sys

KINDS = [
    ("attr", re.compile(r"unsafe\s*\(\s*(no_mangle|export_name|link_section)")),
    ("impl", re.compile(r"\bunsafe\s+impl\b")),
    ("trait", re.compile(r"\bunsafe\s+(auto\s+)?trait\b")),
    ("fn", re.compile(r"\bunsafe\s+(extern\s+\"[^\"]*\"\s+)?fn\b")),
    ("extern", re.compile(r"\bunsafe\s+extern\s+\"[^\"]*\"\s*\{")),
    ("block", re.compile(r"\bunsafe\s*\{")),
]
TOKEN = re.compile(r"\bunsafe\b")


def strip(line, in_block):
    out = []
    i = 0
    in_str = False
    while i < len(line):
        if in_block:
            j = line.find("*/", i)
            if j < 0:
                return "".join(out), True
            i = j + 2
            in_block = False
            continue
        c = line[i]
        if in_str:
            if c == "\\":
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if line.startswith("//", i):
            break
        if line.startswith("/*", i):
            in_block = True
            i += 2
            continue
        if c == '"':
            in_str = True
            out.append('""')
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out), in_block


def scan(path, rel, crate):
    rows = []
    file_test = (
        "/tests/" in "/" + rel
        or "/benches/" in "/" + rel
        or rel.endswith("/tests.rs")
        or os.path.basename(rel).startswith("test")
    )
    is_build = rel.endswith("build.rs")
    depth = 0
    test_depth = None  # brace depth at which a cfg(test) item started
    pending_test = False
    in_block = False
    with open(path, encoding="utf-8", errors="replace") as f:
        lines = f.read().split("\n")
    for n, raw in enumerate(lines, 1):
        code, in_block = strip(raw, in_block)
        if re.search(r"#\[cfg\((all\()?test\b", code):
            pending_test = True
        opens = code.count("{")
        closes = code.count("}")
        if pending_test and opens > 0 and test_depth is None:
            test_depth = depth
            pending_test = False
        in_test = file_test or test_depth is not None
        for m in TOKEN.finditer(code):
            tail = code[m.start():]
            kind = "other"
            for k, rx in KINDS:
                if rx.match(tail):
                    kind = k
                    break
            scope = "test" if in_test else ("build" if is_build else "src")
            rows.append((crate, rel, n, kind, scope, raw.strip()[:160]))
        depth += opens - closes
        if test_depth is not None and depth <= test_depth and closes > 0:
            test_depth = None
    return rows


def main():
    vendor = sys.argv[1]
    print("crate\tpath\tline\tkind\tscope\tsource")
    for crate in sys.argv[2:]:
        root = os.path.join(vendor, crate)
        for dp, dn, fn in os.walk(root):
            dn.sort()
            for name in sorted(fn):
                if not name.endswith(".rs"):
                    continue
                p = os.path.join(dp, name)
                rel = os.path.relpath(p, vendor)
                for r in scan(p, rel, crate):
                    print("\t".join(str(x) for x in r))


if __name__ == "__main__":
    main()
