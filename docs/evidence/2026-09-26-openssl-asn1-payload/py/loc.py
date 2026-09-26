#!/usr/bin/env python3
"""Task 6: lines, unsafe and C, before and after, for the whole security path.

    python3 loc.py <label> FILE...

Per file and in total:
  lines   every line
  code    non-blank lines that are not only a comment, with any
          `#[cfg(test)] mod tests { ... }` block left out
  unsafe  `unsafe` keywords in code (blocks, fns, impls; `deny(unsafe_*)`
          and `forbid(unsafe_code)` attributes are not counted)
  in-unsafe  code lines inside an `unsafe { ... }` block or `unsafe fn` body
  (C files: code lines only; every line of C is outside Rust's checks.)
A line-oriented count, not a parser: strings containing braces or `//`
would confuse it, and none of the counted files has one that matters.
"""
import re
import sys


def strip_comment(line):
    i = line.find("//")
    return line if i < 0 else line[:i]


def rust_counts(text):
    lines = text.split("\n")
    # Drop the #[cfg(test)] module.
    out, skip, depth = [], False, 0
    for i, line in enumerate(lines):
        if not skip and line.strip() == "#[cfg(test)]":
            j = i + 1
            while j < len(lines) and lines[j].strip().startswith("#["):
                j += 1
            if j < len(lines) and lines[j].lstrip().startswith("mod tests"):
                skip, depth = True, 0
                continue
        if skip:
            code = strip_comment(line)
            depth += code.count("{") - code.count("}")
            if depth <= 0 and "}" in code:
                skip = False
            continue
        out.append(line)
    code_lines = [l for l in out if strip_comment(l).strip() and not l.strip().startswith(("//", "/*", "*"))]
    unsafe_kw = 0
    in_unsafe = 0
    depth_stack = []  # brace depths at which an unsafe region started
    depth = 0
    pending = False
    for l in out:
        code = strip_comment(l)
        if not code.strip():
            continue
        if re.search(r"\bunsafe\b", code) and not re.search(r"(deny|forbid|allow|warn)\(unsafe", code):
            unsafe_kw += len(re.findall(r"\bunsafe\b", code))
            pending = True
        inside = bool(depth_stack)
        for ch in code:
            if ch == "{":
                depth += 1
                if pending:
                    depth_stack.append(depth)
                    pending = False
            elif ch == "}":
                if depth_stack and depth_stack[-1] == depth:
                    depth_stack.pop()
                depth -= 1
        if inside or depth_stack or (re.search(r"\bunsafe\s*\{", code)):
            in_unsafe += 1
        if pending and code.rstrip().endswith(";"):
            pending = False  # `unsafe impl ... {}` handled by braces; a declaration ends here
    return len(lines), len(code_lines), unsafe_kw, in_unsafe


def c_counts(text):
    no_block = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    code = [l for l in no_block.split("\n") if l.strip() and not l.strip().startswith("//")]
    return len(text.split("\n")), len(code), 0, 0


def main():
    label, files = sys.argv[1], sys.argv[2:]
    tot = [0, 0, 0, 0, 0]
    print(f"# {label}: file | lines | code | unsafe keywords | code lines in unsafe | C code lines")
    for f in files:
        text = open(f, encoding="utf-8").read()
        name = "/".join(f.split("/")[-2:])
        if f.endswith(".c"):
            lines, code, _, _ = c_counts(text)
            print(f"{name} | {lines} | - | - | - | {code}")
            tot[0] += lines; tot[4] += code
        else:
            lines, code, kw, inside = rust_counts(text)
            print(f"{name} | {lines} | {code} | {kw} | {inside} | -")
            tot[0] += lines; tot[1] += code; tot[2] += kw; tot[3] += inside
    print(f"TOTAL {label} | {tot[0]} | {tot[1]} | {tot[2]} | {tot[3]} | {tot[4]}")


if __name__ == "__main__":
    main()
