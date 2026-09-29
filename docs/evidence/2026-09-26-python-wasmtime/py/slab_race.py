#!/usr/bin/env python3
"""Spike only (2026-09-26). Why the facade defines its host functions once
on a process-wide Linker instead of per Store.

wasmtime-py 49.0.0 keeps Python callbacks in a `Slab` whose free list spans
several statements; handles are freed from finalizers on whatever thread
runs them. Upstream fixed it after 49.0.0 (wasmtime-py#344, 2026-09-24).

    python slab_race.py per-store   # 4 threads each create and drop store-bound Funcs (the pattern avoided)
    python slab_race.py facade      # 4 threads each create, use and drop Verifiers (the facade's pattern)

A run reports how many callbacks came back as the wrong function (an
aliased handle) and how many exceptions were raised.
"""
import gc
import json
import sys
import threading
import time

import wasmtime

import aprv_wasm

THREADS, SECONDS = 4, 10.0


def per_store(k, stats, stop):
    engine = wasmtime.Engine()
    ty = wasmtime.FuncType([], [wasmtime.ValType.i32()])
    while not stop.is_set():
        try:
            store = wasmtime.Store(engine)
            funcs = [wasmtime.Func(store, ty, (lambda k=k, j=j: k * 1000 + j)) for j in range(20)]
            for j, f in enumerate(funcs):
                if f(store) != k * 1000 + j:
                    stats["aliased"] += 1
            stats["rounds"] += 1
            del funcs, store
            if stats["rounds"] % 50 == 0:
                gc.collect()
        except Exception as e:  # noqa: BLE001
            stats["exceptions"] += 1
            stats["last"] = f"{type(e).__name__}: {e}"[:160]


def facade(k, stats, stop):
    g5 = aprv_wasm.Verifier  # the class; each round builds a fresh instance
    while not stop.is_set():
        try:
            v = g5()
            if not v.call(3, b'{"receipt-data":"AQIDBA=="}').startswith(b"{"):
                stats["aliased"] += 1
            stats["rounds"] += 1
            del v
            if stats["rounds"] % 50 == 0:
                gc.collect()
        except Exception as e:  # noqa: BLE001
            stats["exceptions"] += 1
            stats["last"] = f"{type(e).__name__}: {e}"[:160]


if __name__ == "__main__":
    mode = sys.argv[1]
    # Switch threads as often as CPython allows, so a thread switch can land
    # between two statements of Slab.allocate/deallocate (default: 5 ms).
    sys.setswitchinterval(1e-6)
    target = {"per-store": per_store, "facade": facade}[mode]
    stop = threading.Event()
    stats = [{"rounds": 0, "aliased": 0, "exceptions": 0, "last": ""} for _ in range(THREADS)]
    ts = [threading.Thread(target=target, args=(k, stats[k], stop)) for k in range(THREADS)]
    for t in ts:
        t.start()
    time.sleep(SECONDS)
    stop.set()
    for t in ts:
        t.join()
    total = {key: sum(s[key] for s in stats) for key in ("rounds", "aliased", "exceptions")}
    print(json.dumps({"mode": mode, "wasmtime": "49.0.0", "threads": THREADS, "seconds": SECONDS,
                      "switch_interval_s": sys.getswitchinterval(), **total,
                      "last_exception": next((s["last"] for s in stats if s["last"]), "")}))
