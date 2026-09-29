#!/usr/bin/env python3
"""Runs a request corpus through a CORE wasm module (Route A or C) on
Wasmtime (wasmtime-py 49.0.0, the Wasmtime C API), the way js/run.mjs
does under Node. Same rows ({"id","code","json"}) for py/same.py.

    python3 run_wasmtime.py <module.wasm> <requests.jsonl> > rows.jsonl

WASI p1 (only when the module imports it): Wasmtime's own, with no
preopened directory, no environment and no arguments. aprv.clock_now_ms
and aprv.random_get (Route C) are Python functions. Import calls are
counted and printed to stderr as one JSON line.
"""
import base64
import json
import os
import struct
import sys
import time

import wasmtime

ENV_BITS = {"Production": 1, "Sandbox": 2, "Xcode": 4, "LocalTesting": 8}
calls = {}


def count(name):
    calls[name] = calls.get(name, 0) + 1


class Host:
    def __init__(self, path):
        self.engine = wasmtime.Engine()
        self.module = wasmtime.Module.from_file(self.engine, path)
        self.imports = {(i.module, i.name) for i in self.module.imports}
        self.uses_wasi = any(m == "wasi_snapshot_preview1" for m, _ in self.imports)
        self.fresh()

    def fresh(self):
        store = wasmtime.Store(self.engine)
        linker = wasmtime.Linker(self.engine)
        if self.uses_wasi:
            store.set_wasi(wasmtime.WasiConfig())  # nothing inherited, nothing preopened
            linker.define_wasi()
        f64 = wasmtime.ValType.f64()
        i32 = wasmtime.ValType.i32()

        def clock_now_ms():
            count("aprv.clock_now_ms")
            return float(int(time.time() * 1000))

        def random_get(caller, buf, n):
            count("aprv.random_get")
            mem = caller["memory"]
            mem.write(caller, os.urandom(n), buf)
            return 0

        if ("aprv", "clock_now_ms") in self.imports:
            linker.define_func("aprv", "clock_now_ms", wasmtime.FuncType([], [f64]), clock_now_ms)
        if ("aprv", "random_get") in self.imports:
            linker.define_func("aprv", "random_get", wasmtime.FuncType([i32, i32], [i32]), random_get, access_caller=True)
        self.store = store
        self.inst = linker.instantiate(store, self.module)
        self.ex = self.inst.exports(store)
        self.mem = self.ex["memory"]
        for name in ("_initialize", "aprv_init"):
            if name in self.ex:
                self.ex[name](store)
        self.handles = {}
        self.pending = []

    def call(self, name, *args):
        return self.ex[name](self.store, *args)

    def alloc(self, n):
        p = self.call("aprv_alloc", max(n, 1))
        self.pending.append((p, max(n, 1)))
        return p

    def release(self):
        for p, n in self.pending:
            self.call("aprv_dealloc", p, n)
        self.pending = []

    def put(self, data, nul=False):
        buf = data + (b"\0" if nul else b"")
        p = self.alloc(len(buf))
        if buf:
            self.mem.write(self.store, buf, p)
        return p

    def take(self, p):
        if not p:
            return ""
        out = bytearray()
        size = self.mem.data_len(self.store)
        chunk = 4096
        i = p
        while i < size:
            b = self.mem.read(self.store, i, min(i + chunk, size))
            z = b.find(b"\0")
            if z >= 0:
                out += b[:z]
                break
            out += b
            i += chunk
        self.call("aprv_string_free", p)
        return out.decode("utf-8", "replace")

    def u32(self, p, v):
        self.mem.write(self.store, struct.pack("<I", v), p)

    def ru32(self, p):
        return struct.unpack("<I", self.mem.read(self.store, p, p + 4))[0]

    def handle(self, r, opts):
        key = (r["kind"], r["options"])
        if key in self.handles:
            return self.handles[key]
        ders = lens = count_ = 0
        if opts.get("roots") is not None:
            blobs = [base64.b64decode(x) for x in opts["roots"]]
            count_ = len(blobs)
            ders = self.alloc(4 * max(count_, 1))
            lens = self.alloc(4 * max(count_, 1))
            for i, b in enumerate(blobs):
                self.u32(ders + 4 * i, self.put(b))
                self.u32(lens + 4 * i, len(b))
        bundle = (opts.get("bundleId") or "").encode()
        if r["kind"] == "jws" and not bundle:
            bundle = b"conformance.unset.bundle.id"
        if r["kind"] == "receipt":
            if opts.get("bundleId") is None:
                h = 0
            else:
                bp = self.put(bundle, True)
                h = (self.call("aprv_verifier_new_receipt", bp) if opts.get("roots") is None
                     else self.call("aprv_verifier_new_receipt_with_roots", bp, ders, lens, count_))
        elif r["kind"] == "jws":
            mask = 0
            for n in opts.get("acceptedEnvironments") or []:
                mask |= ENV_BITS[n]
            app = opts.get("appAppleId") or 0
            if app >= 2**63:
                app -= 2**64
            bp = self.put(bundle, True)
            h = (self.call("aprv_verifier_new_jws", bp, mask, app) if opts.get("roots") is None
                 else self.call("aprv_verifier_new_jws_with_roots", bp, mask, app, ders, lens, count_))
        else:
            env = ENV_BITS.get(opts.get("environment"), 0)
            clock = 0
            if opts.get("nowMillis") is not None:
                clock = self.alloc(8)
                self.mem.write(self.store, struct.pack("<q", opts["nowMillis"]), clock)
            h = self.call("aprv_endpoint_new_with_roots_and_clock", env, ders, lens, count_, clock)
        self.handles[key] = h
        return h

    def row(self, r):
        opts = json.loads(r["options"])
        data = base64.b64decode(r["input"])
        h = self.handle(r, opts)
        rid = r["id"]
        if not h:
            return {"id": rid, "code": "CTOR_REFUSED", "json": None}
        if r["kind"] == "endpoint":
            if b"\0" in data:
                return {"id": rid, "code": "NUL_IN_BODY", "json": None}
            out = self.alloc(4)
            self.u32(out, 0)
            st = self.call("aprv_verify_receipt_endpoint_json", h, self.put(data, True), out)
            return {"id": rid, "code": None if st == 0 else st, "json": self.take(self.ru32(out))}
        res = self.alloc(8)
        self.u32(res, 0)
        self.u32(res + 4, 0)
        if r["kind"] == "jws":
            if b"\0" in data:
                return {"id": rid, "code": "NUL_IN_INPUT", "json": None}
            name = ["aprv_verify_transaction", "aprv_verify_app_transaction", "aprv_verify_raw"][r["op"]]
            self.call(name, h, self.put(data, True), res)
        else:
            guid = bytes.fromhex(r["guidHex"]) if r.get("guidHex") is not None else None
            if r.get("base64"):
                if b"\0" in data:
                    return {"id": rid, "code": "NUL_IN_INPUT", "json": None}
                if guid is not None:
                    self.call("aprv_verify_receipt_base64_with_device_guid", h, self.put(data, True), self.put(guid), len(guid), res)
                else:
                    self.call("aprv_verify_receipt_base64", h, self.put(data, True), res)
            elif guid is not None:
                self.call("aprv_verify_receipt_der_with_device_guid", h, self.put(data), len(data), self.put(guid), len(guid), res)
            else:
                self.call("aprv_verify_receipt_der", h, self.put(data), len(data), res)
        code = struct.unpack("<i", self.mem.read(self.store, res, res + 4))[0]
        return {"id": rid, "code": code, "json": self.take(self.ru32(res + 4))}


def main():
    host = Host(sys.argv[1])
    traps = 0
    rows = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
    for r in rows:
        try:
            row = host.row(r)
            host.release()
        except wasmtime.Trap as e:
            traps += 1
            host.fresh()
            row = {"id": r["id"], "code": "TRAP", "json": None, "trap": str(e).splitlines()[0]}
        print(json.dumps(row))
    print(json.dumps({"host": "wasmtime", "wasi": host.uses_wasi, "calls": calls, "traps": traps, "rows": len(rows)}), file=sys.stderr)


if __name__ == "__main__":
    main()
