#!/usr/bin/env python3
"""Spike only (2026-09-27, round 11). Resource-exhaustion and trap cases for
the two Wasmi facades. Each case runs in its own child Python process (its
own session, killed as a group after TIMEOUT seconds), so a hang or a crash
is observed, not suffered. After the case, the child checks that it is still
alive and, where the module loaded, that a fresh instance still answers.

    exhaust.py CONFIG WASM_DIR APRV_WASM      (parent: every case, one JSON line each)
    exhaust.py child CONFIG CASE WASM_DIR APRV_WASM

CONFIG:
  rs-bounded    py/aprv_wasmi_rs, fuel APRV_EXHAUST_FUEL per call (default 5,000,000,000), memory cap 64 MiB
  rs-unbounded  py/aprv_wasmi_rs, fuel off, no memory cap
  capi          py/aprv_wasmi_capi (official C API), no fuel, no limiter (none exists)
  capi-fuel     py/aprv_wasmi_capi with wasmi_config_consume_fuel_set(true)
WASM_DIR holds hostile.wasm, two-tables.wasm, big-memory.wasm (from ../wat).
"""
import json
import os
import signal
import subprocess
import sys
import time

TIMEOUT = float(os.environ.get("APRV_EXHAUST_TIMEOUT", "20"))
CONFIGS = {
    "rs-bounded": ("aprv_wasmi_rs", {"APRV_WASMI_FUEL": os.environ.get("APRV_EXHAUST_FUEL", "5000000000"), "APRV_WASMI_MAXMEM": str(64 << 20)}),
    "rs-unbounded": ("aprv_wasmi_rs", {"APRV_WASMI_FUEL": "0", "APRV_WASMI_MAXMEM": "0"}),
    "capi": ("aprv_wasmi_capi", {}),
    "capi-fuel": ("aprv_wasmi_capi", {"APRV_WASMI_FUEL": "1"}),
}
# name -> (module, what the case does); ops are hostile.wat's
CASES = [
    ("benign op returns 42", "hostile", ("raw", 0, 0)),
    ("infinite loop", "hostile", ("raw", 1, 0)),
    ("unbounded recursion, thin frames", "hostile", ("raw", 2, 0)),
    ("unbounded recursion, 33-local frames", "hostile", ("raw", 3, 0)),
    ("grow 1 page at a time towards 4,096 pages (256 MiB), touching each", "hostile", ("raw", 4, 4096)),
    ("one memory.grow of 16,384 pages (1 GiB)", "hostile", ("raw", 5, 16384)),
    ("aprv.random_get with a negative pointer", "hostile", ("raw", 6, 0)),
    ("aprv.random_get straddling the end of memory", "hostile", ("raw", 7, 0)),
    ("i32.store beyond linear memory", "hostile", ("raw", 8, 0)),
    ("call_indirect through an empty table slot", "hostile", ("raw", 9, 0)),
    ("integer divide by zero", "hostile", ("raw", 10, 0)),
    ("unreachable", "hostile", ("raw", 99, 0)),
    ("malformed module (valid header, garbage section)", "malformed", ("load",)),
    ("truncated aprv.wasm (first 4,096 bytes)", "truncated", ("load",)),
    ("not a Wasm module at all", "notwasm", ("load",)),
    ("module with two tables (instance resources above the limit of 1)", "two-tables", ("instantiate",)),
    ("module declaring 2,048 pages (128 MiB) of initial memory", "big-memory", ("instantiate",)),
    ("aprv.wasm: _initialize + one g5 verify", "aprv", ("g5",)),
    ("aprv.wasm: aprv_alloc(96 MiB), then g5 in the same instance", "aprv", ("alloc_then_g5", 96 << 20)),
]


def hwm():
    for line in open("/proc/self/status"):
        if line.startswith("VmHWM:"):
            return int(line.split()[1])
    return 0


def module_path(kind, wasm_dir, aprv):
    if kind == "aprv":
        return aprv
    if kind in ("hostile", "two-tables", "big-memory"):
        return os.path.join(wasm_dir, kind + ".wasm")
    path = os.path.join(wasm_dir, kind + ".wasm")
    data = {"malformed": b"\0asm\x01\0\0\0\x01\xff\xff\xff\x0f\x60",
            "truncated": open(aprv, "rb").read()[:4096],
            "notwasm": b"hello, not wasm"}[kind]
    open(path, "wb").write(data)
    return path


def child(config, case_name, wasm_dir, aprv):
    import importlib
    facade, env = CONFIGS[config]
    kind, action = next((k, a) for n, k, a in CASES if n == case_name)
    os.environ.update(env)
    os.environ["APRV_MODULE"] = module_path(kind, wasm_dir, aprv)
    m = importlib.import_module(facade)
    out = {"config": config, "fuel": os.environ.get("APRV_WASMI_FUEL", "0"), "case": case_name}
    t = time.perf_counter()
    h = None
    try:
        h = m.InProcHost()
        i = h.new()
        if action[0] == "raw":
            out["outcome"] = f"returned {h.raw(i, 'hostile', action[1], action[2])}"
            out["memory_bytes_after"] = h.mem_len(i)
        elif action[0] == "g5":
            g5 = open(os.environ["APRV_G5"], "rb").read()
            out["outcome"] = "g5 verified" if b'"verified":true' in h.invoke(i, 1, 1, g5) else "g5 NOT verified"
        elif action[0] == "alloc_then_g5":
            p = h.raw(i, "aprv_alloc", action[1])
            g5 = open(os.environ["APRV_G5"], "rb").read()
            ok = b'"verified":true' in h.invoke(i, 1, 1, g5)
            out["outcome"] = f"aprv_alloc returned {'0 (refused)' if p == 0 else 'a pointer'}; memory {h.mem_len(i)} bytes; g5 {'verified' if ok else 'NOT verified'} in the same instance"
        else:
            out["outcome"] = f"loaded and instantiated; memory {h.mem_len(i)} bytes"
    except Exception as e:  # noqa: BLE001
        out["outcome"] = f"{type(e).__name__}: {str(e).splitlines()[0][:160] if str(e) else ''}"
    out["ms"] = round((time.perf_counter() - t) * 1000, 1)
    # Survival: this line runs only if the process is alive. Where the module
    # loads, a fresh instance of it must still answer.
    alive = {"process_alive": True}
    if kind == "hostile":
        try:
            j = h.new()
            alive["fresh_instance_op0"] = h.raw(j, "hostile", 0, 0)
        except Exception as e:  # noqa: BLE001
            alive["fresh_instance_op0"] = f"{type(e).__name__}: {str(e)[:100]}"
    out.update(alive)
    out["hwm_kb"] = hwm()
    print(json.dumps(out), flush=True)
    os._exit(0)


def parent(config, wasm_dir, aprv):
    for name, _, _ in CASES:
        t = time.perf_counter()
        p = subprocess.Popen([sys.executable, os.path.abspath(__file__), "child", config, name, wasm_dir, aprv],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
        try:
            out, err = p.communicate(timeout=TIMEOUT)
        except subprocess.TimeoutExpired:
            os.killpg(p.pid, signal.SIGKILL)
            p.communicate()
            print(json.dumps({"config": config, "case": name, "outcome": f"HANG: no answer in {TIMEOUT:.0f} s; process group killed"}), flush=True)
            continue
        line = next((l for l in out.splitlines() if l.startswith("{")), None)
        if p.returncode != 0 or line is None:
            print(json.dumps({"config": config, "case": name, "outcome": f"PROCESS DIED: exit {p.returncode}",
                              "stderr_tail": err.strip()[-200:]}), flush=True)
            continue
        r = json.loads(line)
        r["wall_ms"] = round((time.perf_counter() - t) * 1000)
        print(json.dumps(r), flush=True)


if __name__ == "__main__":
    if sys.argv[1] == "child":
        child(*sys.argv[2:6])
    else:
        parent(*sys.argv[1:4])
