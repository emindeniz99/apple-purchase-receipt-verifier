#!/usr/bin/env python3
"""Spike only (2026-09-27). What a precompiled module pins. Tries
Module.deserialize_file on each .cwasm with engines configured every way
the facade can, and reports which combinations load. Run it with the
wasmtime that made the files (49.0.0) and with another one (48.0.0).

    python pinning.py cwasm-dir
"""
import json
import os
import sys
from importlib import metadata

import wasmtime

os.chdir(sys.argv[1])  # relative file names keep local paths out of the messages
engines = {}
for name in ("cranelift-native", "cranelift-baseline", "winch-baseline", "pulley64"):
    cfg = wasmtime.Config()
    if name.startswith("winch"):
        wasmtime._ffi.wasmtime_config_strategy_set(cfg.ptr(), 2)
    if name.endswith("baseline"):
        cfg.target = "x86_64-unknown-linux-gnu"
    if name == "pulley64":
        cfg.target = "pulley64"
    engines[name] = wasmtime.Engine(cfg)
for f in ("cranelift-native.cwasm", "cranelift-baseline.cwasm", "winch-baseline.cwasm", "pulley64.cwasm"):
    for name, e in engines.items():
        try:
            wasmtime.Module.deserialize_file(e, f)
            r = "loads"
        except Exception as ex:  # noqa: BLE001
            r = "refused: " + " | ".join(x.strip() for x in str(ex).strip().splitlines() if x.strip())[:400]
        print(json.dumps({"wasmtime": metadata.version("wasmtime"), "file": f, "engine": name, "result": r}))
