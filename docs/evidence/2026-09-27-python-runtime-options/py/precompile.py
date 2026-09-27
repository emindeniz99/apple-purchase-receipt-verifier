#!/usr/bin/env python3
"""Spike only (2026-09-27). Precompiles aprv.wasm with the APRV_ENGINE /
APRV_BASELINE settings (Module.serialize) and reports the artifact's size
raw, deflated as a wheel would store it (zipfile, level 9), and xz.

    APRV_ENGINE=... APRV_BASELINE=... python precompile.py aprv.wasm out.cwasm
"""
import hashlib
import io
import json
import lzma
import os
import sys
import time
import zipfile

import wasmtime

import aprv_wasm

cfg, name = aprv_wasm._config()
engine = wasmtime.Engine(cfg)
t = time.perf_counter()
blob = wasmtime.Module(engine, open(sys.argv[1], "rb").read()).serialize()
ms = round((time.perf_counter() - t) * 1000, 1)
open(sys.argv[2], "wb").write(blob)
z = io.BytesIO()
with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
    zf.writestr("aprv.cwasm", bytes(blob))
print(json.dumps({"engine": name, "baseline_target": os.environ.get("APRV_BASELINE") == "1", "compile_ms": ms,
                  "cwasm_bytes": len(blob), "in_wheel_deflate_bytes": len(z.getvalue()), "xz_bytes": len(lzma.compress(bytes(blob))),
                  "sha256": hashlib.sha256(blob).hexdigest()}))
