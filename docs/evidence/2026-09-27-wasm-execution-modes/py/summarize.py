#!/usr/bin/env python3
"""Spike only (2026-09-27, round 9). Builds the comparison tables of the
note from the raw results (no numbers typed by hand):

    summarize.py RESULTS_DIR > results/summary.txt

Reads startup.txt, procs.txt, calls-ROW.txt, tests-ROW.txt, build-wasmi.txt
and build-wamr.txt. A row missing from a file shows as "-".
"""
import glob
import json
import os
import re
import sys

R = sys.argv[1]


def jl(name):
    p = os.path.join(R, name)
    return [json.loads(l) for l in open(p) if l.strip().startswith("{")] if os.path.exists(p) else []


startup, procs = jl("startup.txt"), jl("procs.txt")
ROWS = []
for r in startup + procs:
    if r["label"] not in ROWS:
        ROWS.append(r["label"])


def get(rows, label, **kw):
    for r in rows:
        if r["label"] == label and all(r.get(k) == v for k, v in kw.items()):
            return r
    return None


def f(x, nd=0):
    if x is None:
        return "-"
    return f"{x:,.{nd}f}"


# sizes
size = {}
for line in open(os.path.join(R, "build-wasmi.txt")):
    m = re.match(r"(\S+): features=.* stripped (\d+) bytes", line)
    if m:
        size[m.group(1)] = int(m.group(2))
cur = None
for line in open(os.path.join(R, "build-wamr.txt")):
    if line.startswith("== "):
        cur = line.split()[1]
    m = re.search(r"libiwasm.so \d+ bytes \(stripped (\d+)\)", line)
    if m and cur:
        size["wamr-" + cur] = int(m.group(1))


def row_size(label):
    if label.startswith("wasmtime-"):
        return size.get("wasmtime")
    if label.startswith("wamr-"):
        return size.get(label)
    if label.startswith("py-wamr-"):
        return size.get(label[3:])
    return size.get(label.rsplit("-", 1)[0])


def parity(label):
    p = os.path.join(R, f"calls-{label}.txt")
    if not os.path.exists(p):
        return "-"
    same = tot = 0
    for line in open(p):
        m = re.search(r": (\d+) of (\d+) rows byte-identical", line)
        if m:
            same += int(m.group(1))
            tot += int(m.group(2))
    diff = sum(1 for line in open(p) if "DIFFERENT" in line)
    return f"{same:,}/{tot:,}" + (f" ({diff} DIFFERENT lines)" if diff else "")


def tests(label):
    p = os.path.join(R, f"tests-{label}.txt")
    if not os.path.exists(p):
        return "-"
    t = open(p).read()
    m = re.search(r"summary: (\d+) passed, (\d+) failed", t)
    i = re.search(r"isolation summary: (\d+) passed, (\d+) failed", t)
    hang = re.search(r"HANG.*", t)
    if hang:
        return hang.group(0)
    return (f"{m.group(1)}/{int(m.group(1)) + int(m.group(2))}" if m else "?") + (f" + iso {i.group(1)}/{int(i.group(1)) + int(i.group(2))}" if i else "")


print("## Start-up: fresh process to first verified g5 (median of 7; 1 run when a run took > 60 s)\n")
print("| Row | Runtime size (stripped) | 4 CPUs | 1 CPU | 1 CPU: init / load / instantiate / first call | 1 CPU: 2nd call | RSS after first result |")
print("|---|---:|---:|---:|---|---:|---:|")
for label in ROWS:
    a, b = get(startup, label, cpus="all"), get(startup, label, cpus="0")
    if not (a or b):
        continue
    mr = (b or a).get("median_run", {})
    br = " / ".join(f(mr.get(k), 1) for k in ("init_ms", "load_ms", "instantiate_ms", "first_call_ms")) + " ms" if mr else "-"
    runs = lambda r: "" if not r or r.get("runs", 7) == 7 else f" ({r['runs']} run)"
    ms = lambda r: (f(r["first_result_ms_median"], 1) + " ms" + runs(r)) if r and "first_result_ms_median" in r else (r.get("hang") or r.get("error", "-")[:60] if r else "-")
    print(f"| {label} | {f(row_size(label) / 1e6, 2) + ' MB' if row_size(label) else '-'} | {ms(a)} | {ms(b)} | {br} | {f(mr.get('second_call_ms'), 1)} ms | {f(mr.get('hwm_kb', 0) / 1024, 0)} MiB |")

print("\n## Warm-up and steady state (bench: calls #1, #2, #5, #10, #100 of one instance, then >= 20 calls and >= 2 s)\n")
print("| Row | g5 calls #1 / #2 / #5 / #10 / #100 (ms), 1 CPU | g5/s 1 CPU | g5/s per CPU, 4 CPUs | JWS #1 / #100 (ms), 1 CPU | JWS/s 1 CPU | JWS/s per CPU, 4 CPUs | Peak RSS | Parity (identical/rows) | ABI tests |")
print("|---|---|---:|---:|---|---:|---:|---:|---|---|")
only_startup = []
for label in ROWS:
    a, b = get(procs, label, cpus=1), get(procs, label, cpus=4)
    if not (a or b):
        only_startup.append(label)
        continue
    if a and "g5" not in a:
        print(f"| {label} | {a.get('hang') or a.get('error')} | | | | | | | {parity(label)} | {tests(label)} |")
        continue
    marks = " / ".join(f(a["g5"]["calls_us"].get(k, 0) / 1000, 1) for k in ("1", "2", "5", "10", "100")) if a else "-"
    jm = (f(a["jws"]["calls_us"]["1"] / 1000, 1) + " / " + f(a["jws"]["calls_us"]["100"] / 1000, 1)) if a else "-"
    g4 = f(b["g5"]["per_s_mean"], 1) if b and "g5" in b else (b.get("hang") or b.get("error", "-")[:40] if b else "-")
    j4 = f(b["jws"]["per_s_mean"], 1) if b and "jws" in b else "-"
    print(f"| {label} | {marks} | {f(a['g5']['per_s_mean'], 1) if a else '-'} | {g4} | {jm} | {f(a['jws']['per_s_mean'], 1) if a else '-'} | {j4} | "
          f"{f(a['hwm_kb_max'] / 1024, 0) + ' MiB' if a else '-'} | {parity(label)} | {tests(label)} |")

if only_startup:
    print("\nStart-up only (no bench rows): " + ", ".join(only_startup) + ".")
extra = sorted({os.path.basename(p)[6:-4] for p in glob.glob(os.path.join(R, "tests-*.txt"))} - set(ROWS))
if extra:
    print("\n## Correctness only (no timing rows)\n")
    print("| Row | Parity | ABI tests |")
    print("|---|---|---|")
    for label in extra:
        print(f"| {label} | {parity(label)} | {tests(label)} |")
