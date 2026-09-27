#!/usr/bin/env python3
"""Spike only (2026-09-27). Apply the hand-written risk classes to the raw
`unsafe` inventory of the Wasmi execution core.

Usage: classify.py results/unsafe-raw.tsv > results/unsafe-classified.tsv
       classify.py --summary results/unsafe-raw.tsv > results/unsafe-summary.txt

Only rows with scope `src` from the core crates are classified (wasmi,
wasmi_core, wasmi_ir, wasmi_collections, and the one wasmparser site).
C-API rows are counted separately and not classified here; test and bench
rows are counted and dropped.

The rules are ordered; the first match wins. Each rule was written after
reading the site in the 2.0.0 source (see the note for the reasoning per
class). A row no rule matches is printed as UNCLASSIFIED, and the summary
fails loudly if there is one.

Classes:
  A  can affect guest/host isolation directly
     A-mem    linear memory buffer and the cached (memory 0) pointer/length
     A-stack  value-stack cells: Sp/slot pointer arithmetic, set_len, host
              call in/out cells
     A-ip     instruction stream and dispatch: unchecked decode at Ip, branch
              offsets, handler pointers and FuncEntry pointers baked into
              the bytecode, handler-table lookups
     A-inst   instance entity cache: thin pointer to the instance, raw
              pointers to table/global/func/segment entities, handle casts
     A-assume `unreachable_unchecked!` in the executor: UB in release if the
              translator/executor invariant it names is ever false
  B  lifetime, provenance, aliasing or concurrency tricks outside the
     per-instruction path (store pruning, lazy-compilation state machine,
     pointer-stable arenas)
  C  unsafe impl Send/Sync
  D  benign or not reachable from APRV (validated-UTF-8 fast paths,
     transmutes between same-size plain data, a validation-bypass API APRV
     never calls)
"""
import csv
import re
import sys
from collections import Counter

CORE = {"wasmi", "wasmi_core", "wasmi_ir", "wasmi_collections", "wasmparser"}

# (path substring, source regex or None, line range or None, class)
RULES = [
    ("", None, None, "C", "kind=impl"),
    ("wasmparser/", None, None, "D", None),
    ("string_interner/detail.rs", None, None, "D", None),
    ("module/custom_section.rs", None, None, "D", None),
    ("wasmi_core/src/simd.rs", None, None, "D", None),
    ("wasmi_ir/src/decode/mod.rs", None, None, "D", None),
    ("wasmi/src/module/mod.rs", None, None, "D", None),
    ("wasmi/src/module/parser/buffered.rs", None, None, "D", None),
    ("code_map/", r"unreachable_unchecked", None, "B", None),
    ("wasmi/src/engine/", r"unreachable_unchecked|StoreError::Internal", None, "A-assume", None),
    ("wasmi_core/src/memory/buffer.rs", None, None, "A-mem", None),
    ("handler/state.rs", None, (380, 390), "A-mem", None),
    ("handler/state.rs", None, (420, 520), "A-ip", None),
    ("handler/state.rs", None, (620, 1500), "A-stack", None),
    ("handler/state.rs", None, (300, 330), "A-inst", None),
    ("handler/utils.rs", r"sp\.(get|set)", None, "A-stack", None),
    ("handler/utils.rs", None, (550, 575), "A-mem", None),
    ("handler/utils.rs", None, None, "A-inst", None),
    ("handler/args.rs", r"decode|\.ip\.", None, "A-ip", None),
    ("handler/args.rs", None, None, "A-inst", None),
    ("handler/exec", r"decode_op\(\)|args\.decode\(\)|ip\.add|ip\.decode|FuncEntryPtr", None, "A-ip", None),
    ("handler/exec.rs", r"memor|memref|data\)", None, "A-mem", None),
    ("handler/exec.rs", None, None, "A-inst", None),
    ("handler/dispatch/", None, None, "A-ip", None),
    ("wasmi_ir/src/opcode.rs", None, None, "A-ip", None),
    ("engine/executor/inout.rs", None, None, "A-stack", None),
    ("wasmi/src/instance/", None, None, "A-inst", None),
    ("wasmi/src/func/", None, None, "B", None),
    ("handler/func.rs", None, None, "B", None),
    ("code_map/", None, None, "B", None),
    ("wasmi/src/store/", None, None, "B", None),
    ("wasmi_collections/src/arena/", None, None, "B", None),
]


def classify(row):
    path, src, kind = row["path"], row["source"], row["kind"]
    line = int(row["line"])
    for sub, rx, rng, cls, special in RULES:
        if special == "kind=impl":
            if kind == "impl":
                return cls
            continue
        if sub not in path:
            continue
        if rx and not re.search(rx, src):
            continue
        if rng and not (rng[0] <= line <= rng[1]):
            continue
        return cls
    return "UNCLASSIFIED"


def main():
    summary = sys.argv[1] == "--summary"
    rows = list(csv.DictReader(open(sys.argv[-1]), delimiter="\t"))
    per_crate = Counter()
    scope = Counter()
    classes = Counter()
    by_file = Counter()
    kinds = Counter()
    out = []
    for r in rows:
        scope[(r["crate"], r["scope"])] += 1
        if r["scope"] != "src":
            continue
        per_crate[(r["crate"], r["kind"])] += 1
        if r["crate"] not in CORE:
            continue
        c = classify(r)
        classes[c] += 1
        kinds[(c, r["kind"])] += 1
        by_file[(c, r["path"])] += 1
        out.append((c, r))
    if not summary:
        print("class\tcrate\tpath\tline\tkind\tsource")
        for c, r in out:
            print("\t".join([c, r["crate"], r["path"], r["line"], r["kind"], r["source"]]))
        return
    print("# unsafe keyword sites by crate and scope (all crates scanned)")
    for (crate, sc), n in sorted(scope.items()):
        print(f"  {crate:<20} {sc:<6} {n}")
    print("\n# src sites by crate and kind")
    for (crate, k), n in sorted(per_crate.items()):
        print(f"  {crate:<20} {k:<7} {n}")
    print("\n# core src sites by risk class (wasmi, wasmi_core, wasmi_ir, wasmi_collections, wasmparser)")
    for c, n in sorted(classes.items()):
        print(f"  {c:<13} {n}")
    print(f"  {'total':<13} {sum(classes.values())}")
    print("\n# core src sites by class and kind")
    for (c, k), n in sorted(kinds.items()):
        print(f"  {c:<13} {k:<7} {n}")
    print("\n# core src sites by class and file")
    for (c, p), n in sorted(by_file.items()):
        print(f"  {c:<13} {n:>3}  {p}")
    if classes.get("UNCLASSIFIED"):
        print("\nERROR: unclassified rows present")
        sys.exit(1)


if __name__ == "__main__":
    main()
