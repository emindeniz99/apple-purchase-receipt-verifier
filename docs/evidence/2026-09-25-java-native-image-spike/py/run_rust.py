#!/usr/bin/env python3
"""Runs the same request corpus through the Rust core's C ABI (rust/ffi).

    python3 run_rust.py $REPO <dir holding libapple_purchase_receipt_verifier_ffi.so> requests.jsonl > rust.jsonl

The ctypes declarations are the repository's own (rust/ffi/tests/conformance.py
load_library), imported rather than copied. Rows: {"id", "code", "json"}.
A constructor that returns NULL is reported as code "CTOR_REFUSED". The
endpoint call answers Apple's response JSON only, so its code is null.
"""

from __future__ import annotations

import base64
import ctypes
import importlib.util
import json
import sys
from pathlib import Path

ENV_BITS = {"Production": 1, "Sandbox": 2, "Xcode": 4, "LocalTesting": 8}


def main():
    repo, libdir, requests = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    spec = importlib.util.spec_from_file_location("rustffi", repo / "rust/ffi/tests/conformance.py")
    rustffi = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(rustffi)
    lib = rustffi.load_library(libdir)
    handles = {}
    keep = []
    for line in open(requests, encoding="utf-8"):
        if not line.strip():
            continue
        r = json.loads(line)
        opts = json.loads(r["options"])
        data = base64.b64decode(r["input"])
        key = (r["kind"], r["options"])
        if key not in handles:
            roots = opts.get("roots")
            if roots is None:
                ders = lens = None; count = 0
            else:
                blobs = [base64.b64decode(x) for x in roots]
                bufs = [(ctypes.c_uint8 * max(len(b), 1)).from_buffer_copy(b or b"\0") for b in blobs]
                keep.append(bufs)
                ders = (ctypes.POINTER(ctypes.c_uint8) * max(len(bufs), 1))(
                    *[ctypes.cast(b, ctypes.POINTER(ctypes.c_uint8)) for b in bufs])
                lens = (ctypes.c_size_t * max(len(bufs), 1))(*[len(b) for b in blobs])
                count = len(blobs)
            bundle = (opts.get("bundleId") or "").encode()
            if r["kind"] == "jws" and not bundle:
                # The Java adapter's verifyRaw stand-in is "" (the Java
                # constructor accepts it); the Rust ABI refuses an empty
                # bundle id, so it gets rust/ffi/tests/conformance.py's own
                # stand-in, which no fixture carries.
                bundle = b"conformance.unset.bundle.id"
            if r["kind"] == "receipt":
                if opts.get("bundleId") is None:
                    h = None
                else:
                    h = (lib.aprv_verifier_new_receipt(bundle) if roots is None
                         else lib.aprv_verifier_new_receipt_with_roots(bundle, ders, lens, count))
            elif r["kind"] == "jws":
                mask = 0
                for name in opts.get("acceptedEnvironments") or []:
                    mask |= ENV_BITS[name]
                app = opts.get("appAppleId") or 0
                h = (lib.aprv_verifier_new_jws(bundle, mask, app) if roots is None
                     else lib.aprv_verifier_new_jws_with_roots(bundle, mask, app, ders, lens, count))
            else:
                env = ENV_BITS.get(opts.get("environment"), 0)
                clock = None
                if opts.get("nowMillis") is not None:
                    c = ctypes.c_int64(opts["nowMillis"]); keep.append(c); clock = ctypes.byref(c)
                h = lib.aprv_endpoint_new_with_roots_and_clock(env, ders, lens, count, clock)
            handles[key] = h
        h = handles[key]
        if not h:
            row = {"id": r["id"], "code": "CTOR_REFUSED", "json": None}
        elif r["kind"] == "endpoint":
            if b"\0" in data:
                row = {"id": r["id"], "code": "NUL_IN_BODY", "json": None}
            else:
                resp = ctypes.c_void_p()
                st = lib.aprv_verify_receipt_endpoint_json(h, data, ctypes.byref(resp))
                row = {"id": r["id"], "code": None if st == 0 else st, "json": rustffi.take_string(lib, resp.value)}
        else:
            res = rustffi.AprvResult()
            if r["kind"] == "jws":
                if b"\0" in data:
                    row = {"id": r["id"], "code": "NUL_IN_INPUT", "json": None}
                    print(json.dumps(row)); continue
                call = [lib.aprv_verify_transaction, lib.aprv_verify_app_transaction, lib.aprv_verify_raw][r["op"]]
                call(h, data, ctypes.byref(res))
            else:
                guid = bytes.fromhex(r["guidHex"]) if r.get("guidHex") is not None else None
                if r.get("base64"):
                    if b"\0" in data:
                        row = {"id": r["id"], "code": "NUL_IN_INPUT", "json": None}
                        print(json.dumps(row)); continue
                    if guid is not None:
                        gb, gp = rustffi.byte_array(guid)
                        lib.aprv_verify_receipt_base64_with_device_guid(h, data, gp, len(guid), ctypes.byref(res))
                    else:
                        lib.aprv_verify_receipt_base64(h, data, ctypes.byref(res))
                else:
                    db, dp = rustffi.byte_array(data)
                    if guid is not None:
                        gb, gp = rustffi.byte_array(guid)
                        lib.aprv_verify_receipt_der_with_device_guid(h, dp, len(data), gp, len(guid), ctypes.byref(res))
                    else:
                        lib.aprv_verify_receipt_der(h, dp, len(data), ctypes.byref(res))
            row = {"id": r["id"], "code": res.status, "json": rustffi.take_string(lib, res.json)}
        print(json.dumps(row))


if __name__ == "__main__":
    main()
