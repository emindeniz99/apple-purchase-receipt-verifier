#!/usr/bin/env python3
"""Spike only (2026-09-29, round 12). A Python host on wasmtime-py's own
component API (wasmtime.component, wasmtime-py 49.0.0): the component is
typed at run time from its embedded WIT, so there is no generated code
(the old `python -m wasmtime.bindgen` generator no longer exists; see the
note). Values are plain Python: str, int, the enum as its case name,
list<u8> as bytes.

    run_calls.py calls COMPONENT CALLS.jsonl   rows in the Node runner's format (stdout)
    run_calls.py tests COMPONENT CASES.jsonl   the checks a component host can still make
"""
import json
import os
import sys
import time

from wasmtime import Engine, Store, WasmtimeError, Trap
from wasmtime.component import Component, Linker

VERIFY = "aprv:verifier/verify@1.0.0"
ENV = ("production", "sandbox")


# --- component host (hand-written) begin ---
class Aprv:
    def __init__(self, engine, component, linker):
        self.store = Store(engine)
        inst = linker.instantiate(self.store, component)
        iface = inst.get_export_index(self.store, VERIFY)
        self.f = {n: inst.get_func(self.store, inst.get_export_index(self.store, n, iface))
                  for n in ("init", "verify-receipt", "verify-signed-data", "verify-receipt-endpoint")}

    def call(self, fn, *args):
        # no post_return: since wasmtime PR #12498 (Feb 2026) the runtime runs
        # it itself and Func.post_return is a deprecated no-op
        return self.f[fn](self.store, *args)


def make_linker(engine, random=os.urandom):
    linker = Linker(engine)
    with linker.root() as root:
        with root.add_instance("aprv:verifier/host@1.0.0") as host:
            host.add_func("random-get", lambda store, n: random(n))
    return linker
# --- component host (hand-written) end ---


def now_ms():
    return time.time_ns() // 1_000_000


def run(g, r):
    now = r["now"] if r.get("now") is not None else now_ms()
    if r["fn"] == "verify-receipt-endpoint":
        return g.call(r["fn"], ENV[r["env"]], now, r["text"])
    return g.call(r["fn"], now, r["text"])


def calls(engine, component, path):
    linker = make_linker(engine)
    inst, rows, traps = {}, 0, 0
    out = sys.stdout
    for line in open(path, encoding="utf-8"):
        r = json.loads(line)
        rows += 1
        if "map" in r:
            o = {"id": r["id"], "map": r["map"]}
        else:
            g, answer = inst.get(r["config"]), None
            if g is None:
                g = Aprv(engine, component, linker)
                answer = g.call("init", r["config"])
                if answer == '{"ok":true}':
                    inst[r["config"]] = g
            if answer is not None and answer != '{"ok":true}':
                o = {"id": r["id"], "out": answer}
            else:
                try:
                    o = {"id": r["id"], "out": run(g, r)}
                except (WasmtimeError, Trap) as e:
                    traps += 1
                    inst.pop(r["config"], None)
                    o = {"id": r["id"], "trap": str(e).split("\n")[0]}
        out.write(json.dumps(o, separators=(",", ":"), ensure_ascii=False) + "\n")
    print(json.dumps({"host": "wasmtime-py 49.0.0 (wasmtime.component)", "rows": rows, "traps": traps,
                      "instances_left": len(inst)}), file=sys.stderr)


def tests(engine, component, cases):
    rows = {r["id"]: r for r in map(json.loads, open(cases, encoding="utf-8"))}
    g5 = rows["receipt/verify-genuine-sandbox-g5-against-apple-roots"]["text"]
    failed = 0

    def check(name, ok, detail):
        nonlocal failed
        failed += not ok
        print(("PASS" if ok else "FAIL") + f" {name}: {str(detail)[:120]}")

    def attempt(g, fn, *a):
        try:
            return g.call(fn, *a)
        except (WasmtimeError, Trap, TypeError, ValueError, OverflowError) as e:
            return f"{type(e).__name__}: {str(e).splitlines()[0]}"

    linker = make_linker(engine)
    fresh = lambda: Aprv(engine, component, linker)
    g = fresh()
    check("init(\"\") answers {\"ok\":true}", attempt(g, "init", "") == '{"ok":true}', "")
    s = attempt(g, "verify-receipt", now_ms(), g5)
    check("verify-receipt(genuine g5) verifies", '"verified":true' in s, s)
    s = attempt(fresh(), "verify-receipt", now_ms(), g5)
    check("verify before init traps", s.startswith(("WasmtimeError", "Trap")), s)
    s = attempt(g, "init", "")
    check("a second init traps", s.startswith(("WasmtimeError", "Trap")), s)
    s = attempt(g, "verify-receipt", now_ms(), g5)
    check("  ... and the trapped instance refuses further calls", s.startswith(("WasmtimeError", "Trap")), s)
    def refused(name, fn, *a):
        g = fresh(); g.call("init", "")
        s = attempt(g, fn, *a)
        after = attempt(g, "verify-receipt", now_ms(), g5)
        check(name, not s.startswith("{"), s)
        print("     instance afterwards: " + ("usable" if '"verified":true' in after else after[:70]))
    refused("an enum value outside the WIT is refused by the binding", "verify-receipt-endpoint", "xcode", now_ms(), "{}")
    refused("a negative u64 is refused by the binding", "verify-receipt", -1, g5)
    refused("a u64 above 2^64-1 is refused by the binding", "verify-receipt", 2 ** 64, g5)
    refused("a str with a lone surrogate is refused by the binding", "verify-signed-data", now_ms(), "\udcff.x")
    g = fresh(); g.call("init", "")
    g = fresh(); g.call("init", "")
    g.store.set_limits(memory_size=4 << 20)
    s = "ok"
    for i in range(2000):
        s = attempt(g, "verify-receipt", now_ms(), g5)
        if '"verified":true' not in s:
            s = f"call {i}: {s}"
            break
    check("2,000 calls under a 4 MiB memory limit, no post_return in host code (the runtime frees the results)", s.startswith("{"), s[:60])
    bad = make_linker(engine, random=lambda n: os.urandom(max(n - 1, 0)))
    jws = rows["transaction/verify-shared-sandbox"]
    gb = Aprv(engine, component, bad); gb.call("init", jws["config"])
    s = attempt(gb, "verify-signed-data", now_ms(), jws["text"])
    check("random-get answering the wrong length traps (if random-get is called at all)", not s.startswith("{") or '"verified":true' in s, s)
    a, b = fresh(), fresh(); a.call("init", ""); b.call("init", "")
    attempt(a, "init", "")
    s = attempt(b, "verify-receipt", now_ms(), g5)
    check("isolation: a trap in one instance leaves another untouched", '"verified":true' in s, "")
    print(f"summary: {failed} failed")
    return failed


if __name__ == "__main__":
    mode, comp_path, path = sys.argv[1:4]
    t0 = time.perf_counter()
    engine = Engine()
    component = Component.from_file(engine, comp_path)
    print(f"engine + compile: {(time.perf_counter() - t0) * 1000:.1f} ms", file=sys.stderr)
    if mode == "calls":
        calls(engine, component, path)
    else:
        sys.exit(tests(engine, component, path))
