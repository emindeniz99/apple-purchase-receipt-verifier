#!/usr/bin/env python3
"""Evidence only (2026-09-29). The Rust and Java rows of
docs/rust-core/TEST-INVENTORY.md: every test function of rust/ (the core,
the adapter, the bindings) and of java/src/test, with the shared cases that
use the same fixture file.

    inventory.py <repo>        prints markdown table rows

A test is matched to a case by the fixture files its body names (a file
name that the registry of fixtures/cases.json lists); a test that names no
registered fixture builds its input in code, and its row says so. The
matching is mechanical: it shows which behaviour a case already carries
across every host, and leaves the rest named for a reader.
"""
import json
import os
import re
import sys

repo = sys.argv[1]
doc = json.load(open(os.path.join(repo, "fixtures/cases.json"), encoding="utf-8"))
by_file = {}
for fid, entry in doc["fixtures"].items():
    by_file.setdefault(os.path.basename(entry["path"]), set()).add(fid)
cases_of = {}
for case in doc["cases"]:
    source = case.get("input", {})
    for key in ("fixture", "requestBody"):
        if key in source:
            cases_of.setdefault(source[key], []).append(case["id"])

FILE = re.compile(r'"([A-Za-z0-9_.\-/]+\.(?:der|jws|b64|json|txt|hex|p7))"')


def functions(path, test_marker, name_pattern):
    text = open(path, encoding="utf-8").read()
    lines = text.split("\n")
    found = []
    for i, line in enumerate(lines):
        if test_marker not in line:
            continue
        for j in range(i + 1, min(i + 6, len(lines))):
            m = re.search(name_pattern, lines[j])
            if m:
                depth, body = 0, []
                for k in range(j, len(lines)):
                    body.append(lines[k])
                    depth += lines[k].count("{") - lines[k].count("}")
                    if depth <= 0 and "{" in "".join(body):
                        break
                found.append((m.group(1), "\n".join(body)))
                break
    return found


def row(port, path, name, body):
    files = {os.path.basename(f) for f in FILE.findall(body)}
    fixtures = sorted({fid for f in files for fid in by_file.get(f, ())})
    covered = sorted({cid for fid in fixtures for cid in cases_of.get(fid, [])})
    rel = os.path.relpath(path, repo)
    if covered:
        shown = ", ".join(f"`{c}`" for c in covered[:3]) + (f" and {len(covered) - 3} more" if len(covered) > 3 else "")
        target = f"same fixture as {shown}"
    elif fixtures:
        target = "fixture registered, no case uses it: stays with the " + port
    else:
        target = "input built in code: stays with the " + port
    return f"| {port} | `{rel}` `{name}` | {target} |"


out = []
for root, _, names in os.walk(os.path.join(repo, "rust")):
    if "/target" in root or "/vendor" in root or "/fuzz" in root or "/examples" in root:
        continue
    for n in sorted(names):
        if n.endswith(".rs"):
            p = os.path.join(root, n)
            for name, body in functions(p, "#[test]", r"fn ([a-z0-9_]+)\("):
                out.append(row("Rust", p, name, body))
for root, _, names in os.walk(os.path.join(repo, "java/src/test")):
    for n in sorted(names):
        if n.endswith(".java"):
            p = os.path.join(root, n)
            for name, body in functions(p, "@Test", r"void ([A-Za-z0-9_]+)\("):
                out.append(row("Java", p, name, body))
print("\n".join(out))
