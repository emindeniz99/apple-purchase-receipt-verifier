#!/usr/bin/env python3
"""Spike only (2026-09-27). List every C function wasmi_c_api_impl 2.0.0
exports and flag the ones that can panic.

Usage: capi_surface.py VENDOR_DIR > results/capi-functions.tsv

Sources of exported symbols:
  - `extern "C" fn NAME` items in src/**.rs (one symbol each);
  - `declare_own!(T)`  -> T_delete
  - `declare_ty!(T)`   -> T_delete, T_copy
  - `declare_ref!(T)`  -> T_delete, T_copy, T_same, T_get_host_info,
                          T_set_host_info, T_set_host_info_with_finalizer,
                          T_as_ref, T_as_ref_const
    (expansion read from wasmi_c_api_macros 2.0.0 lib.rs)

Panic flags (grep of the function body, read by hand afterwards):
  unimplemented  body is `unimplemented!` (always panics)
  panic          body contains `panic!`/`unreachable!`/`.unwrap()`/
                 `.expect(`/`assert!` or indexes a slice with `[`...`- 1]`
                 (panics on some inputs)
  -              none of the above in the body

Every function is `extern "C"`. Since Rust 1.81 a panic that reaches an
`extern "C"` boundary aborts the process instead of unwinding (the crate's
MSRV is 1.86), so each flagged function is a process abort, not UB.
`wasm_func_call` alone wraps the guest call in `catch_unwind` (std feature)
and turns a panic into a trap.
"""
import os
import re
import sys

FN = re.compile(r'pub\s+(unsafe\s+)?extern\s+"C"\s+fn\s+(\$?[A-Za-z0-9_]+)')
DECL = re.compile(r'declare_(own|ty|ref)!\(\s*([a-z_]+)_t\s*\)')
ALWAYS = re.compile(r'unimplemented!')
MAYBE = re.compile(r'panic!|unreachable!\(|\.unwrap\(\)|\.expect\(|assert!|\[[^\]]*len\(\)\s*-\s*1\]')

GEN = {
    "own": ["delete"],
    "ty": ["delete", "copy"],
    "ref": ["delete", "copy", "same", "get_host_info", "set_host_info",
            "set_host_info_with_finalizer", "as_ref", "as_ref_const"],
}
GEN_PANICS = {"same", "set_host_info", "set_host_info_with_finalizer", "as_ref", "as_ref_const"}


def bodies(text):
    """Yield (name, is_unsafe, line, body) for each extern "C" fn."""
    for m in FN.finditer(text):
        start = text.index("{", m.end())
        depth, i = 0, start
        while True:
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    break
            i += 1
        yield m.group(2), bool(m.group(1)), text.count("\n", 0, m.start()) + 1, text[start:i + 1]


def main():
    root = os.path.join(sys.argv[1], "wasmi_c_api_impl", "src")
    rows = []
    for dp, _, fns in os.walk(root):
        for f in sorted(fns):
            if not f.endswith(".rs"):
                continue
            p = os.path.join(dp, f)
            rel = os.path.relpath(p, sys.argv[1])
            text = open(p).read()
            for name, uns, line, body in bodies(text):
                if name.startswith("$"):
                    # macro templates (vec.rs): expanded below from declare_vecs!
                    continue
                flag = "unimplemented" if ALWAYS.search(body) else ("panic" if MAYBE.search(body) else "-")
                rows.append((name, "unsafe" if uns else "safe-sig", flag, f"{rel}:{line}"))
            for m in DECL.finditer(text):
                kind, base = m.group(1), m.group(2)
                line = text.count("\n", 0, m.start()) + 1
                for suffix in GEN[kind]:
                    flag = "unimplemented" if suffix in GEN_PANICS else "-"
                    rows.append((f"{base}_{suffix}", "safe-sig", flag, f"{rel}:{line} (declare_{kind}!)"))
            # declare_vecs! in vec.rs: each vec type exports new, new_empty,
            # new_uninitialized, copy, delete
            for m in re.finditer(r'fn new: (\w+);\s*fn empty: (\w+);\s*fn uninit: (\w+);\s*fn copy: (\w+);\s*fn delete: (\w+);', text):
                line = text.count("\n", 0, m.start()) + 1
                for i, n in enumerate(m.groups()):
                    uns = "unsafe" if i == 0 else "safe-sig"
                    # as_slice asserts non-null data when size > 0 (copy reads src)
                    flag = "panic" if i == 3 else "-"
                    rows.append((n, uns, flag, f"{rel}:{line} (declare_vecs!)"))
    rows.sort()
    print("function\tsignature\tpanics\tsource")
    for r in rows:
        print("\t".join(r))
    n = len(rows)
    u = sum(1 for r in rows if r[2] == "unimplemented")
    p = sum(1 for r in rows if r[2] == "panic")
    print(f"# total {n} exported functions; {u} always panic (unimplemented!); "
          f"{p} can panic on some inputs; {sum(1 for r in rows if r[1] == 'unsafe')} are declared `unsafe extern`",
          file=sys.stderr)


if __name__ == "__main__":
    main()
