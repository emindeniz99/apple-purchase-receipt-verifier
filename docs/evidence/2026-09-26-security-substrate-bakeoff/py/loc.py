#!/usr/bin/env python3
"""Line counts for Rust files: total, code (not blank, not a comment),
lines inside `unsafe` blocks and functions, `unsafe` sites, and `#[cfg`
lines (all, and those naming a library: aprv_openssl, aprv_libressl,
aprv_awslc).

    python3 loc.py FILE...

Test modules (`#[cfg(test)] mod tests { ... }`) are counted separately and
left out of code, since the question is what ships.
"""

from __future__ import annotations

import re
import sys


def strip_strings(line: str) -> str:
    return re.sub(r'"(\\.|[^"\\])*"', '""', line)


def count(path: str) -> dict:
    lines = open(path, encoding="utf-8").read().splitlines()
    out = dict(total=len(lines), code=0, tests=0, unsafe_lines=0, unsafe_sites=0, cfg=0, cfg_library=0)
    depth = 0
    unsafe_depth = None
    test_depth = None
    pending_test = False
    for raw in lines:
        line = strip_strings(raw.split("//")[0]) if not raw.strip().startswith("//") else ""
        stripped = raw.strip()
        if stripped.startswith("#[cfg") or stripped.startswith("#![cfg") or "cfg_attr(" in stripped:
            out["cfg"] += 1
            if re.search(r"aprv_(openssl|libressl|awslc)", stripped):
                out["cfg_library"] += 1
        if stripped == "#[cfg(test)]":
            pending_test = True
        is_code = bool(line.strip())
        in_test = test_depth is not None
        if is_code:
            if in_test:
                out["tests"] += 1
            else:
                out["code"] += 1
        if re.search(r"\bunsafe\b", line) and not in_test:
            out["unsafe_sites"] += 1
            if unsafe_depth is None and "{" in line[line.find("unsafe"):]:
                unsafe_depth = depth
        if unsafe_depth is not None and is_code and not in_test:
            out["unsafe_lines"] += 1
        if pending_test and re.match(r"\s*(pub(\(crate\))?\s+)?mod\s", line):
            test_depth = depth
            pending_test = False
        depth += line.count("{") - line.count("}")
        if unsafe_depth is not None and depth <= unsafe_depth:
            unsafe_depth = None
        if test_depth is not None and depth <= test_depth:
            test_depth = None
    return out


def main():
    keys = ["total", "code", "tests", "unsafe_sites", "unsafe_lines", "cfg", "cfg_library"]
    print(f"{'file':60}" + "".join(f"{k:>13}" for k in keys))
    sums = dict.fromkeys(keys, 0)
    for path in sys.argv[1:]:
        c = count(path)
        for k in keys:
            sums[k] += c[k]
        print(f"{path[-60:]:60}" + "".join(f"{c[k]:>13}" for k in keys))
    print(f"{'sum':60}" + "".join(f"{sums[k]:>13}" for k in keys))


if __name__ == "__main__":
    main()
