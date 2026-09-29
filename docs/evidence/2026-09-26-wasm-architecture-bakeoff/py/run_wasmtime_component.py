#!/usr/bin/env python3
"""Runs a request corpus through the APRV COMPONENT on Wasmtime's native
Component Model support (wasmtime-py 49.0.0, the Wasmtime C API): no jco,
no transpiling. The same typed WIT calls as js/jco-driver.mjs, the same
{"id","code","json"} rows for py/same.py.

    python3 run_wasmtime_component.py <component.wasm> <requests.jsonl> > rows.jsonl

The host supplies the component's only import, clock-now-ms.
"""
import base64
import json
import sys
import time

import wasmtime
import wasmtime.component as wc

REASON = {
    "invalid-jws-format": 1, "invalid-certificate": 2, "invalid-certificate-purpose": 3,
    "invalid-chain": 4, "invalid-signature": 5, "wrong-bundle-id": 6, "wrong-environment": 7,
    "wrong-app-apple-id": 8, "invalid-receipt-format": 9, "device-hash-mismatch": 10,
    "internal-error": 12,
}
ENV = {"Production": "production", "Sandbox": "sandbox", "Xcode": "xcode", "LocalTesting": "local-testing"}
IFACE = "aprv:verifier/verifier@0.1.0"
calls = {}


class Host:
    def __init__(self, path):
        self.engine = wasmtime.Engine()
        self.component = wc.Component.from_file(self.engine, path)
        self.wasi = "--wasi" in sys.argv
        self.fresh()

    def fresh(self):
        self.store = wasmtime.Store(self.engine)
        linker = wc.Linker(self.engine)

        def clock(_store):
            calls["clock-now-ms"] = calls.get("clock-now-ms", 0) + 1
            return float(int(time.time() * 1000))

        # A component built through the WASI p1->p2 adapter imports WASI 0.2
        # interfaces; Wasmtime's own implementation (nothing preopened,
        # nothing inherited) serves them.
        if self.wasi:
            self.store.set_wasi_p2(wasmtime.WasiConfig()) if hasattr(self.store, "set_wasi_p2") else self.store.set_wasi(wasmtime.WasiConfig())
            linker.add_wasip2()
        else:
            with linker.root() as root:
                root.add_func("clock-now-ms", clock)
        self.inst = linker.instantiate(self.store, self.component)
        iface = self.inst.get_export_index(self.store, IFACE)
        self.f = {}
        for n in ["[static]receipt-verifier.create", "[method]receipt-verifier.verify",
                  "[method]receipt-verifier.verify-base64", "[static]jws-verifier.create",
                  "[method]jws-verifier.verify-transaction", "[method]jws-verifier.verify-app-transaction",
                  "[method]jws-verifier.verify-raw", "[static]endpoint.create",
                  "[method]endpoint.verify-receipt-json"]:
            self.f[n] = self.inst.get_func(self.store, self.inst.get_export_index(self.store, n, iface))
        self.handles = {}

    def call(self, name, *args):
        return self.f[name](self.store, *args)

    def handle(self, r, opts):
        key = (r["kind"], r["options"])
        if key in self.handles:
            return self.handles[key]
        roots = None if opts.get("roots") is None else [base64.b64decode(x) for x in opts["roots"]]
        try:
            if r["kind"] == "receipt":
                h = None if opts.get("bundleId") is None else \
                    self.ok(self.call("[static]receipt-verifier.create", opts["bundleId"], roots))
            elif r["kind"] == "jws":
                envs = [ENV[n] for n in opts.get("acceptedEnvironments") or []]
                app = opts.get("appAppleId") or None
                h = self.ok(self.call("[static]jws-verifier.create",
                                      opts.get("bundleId") or "conformance.unset.bundle.id", envs, app, roots))
            else:
                env = ENV.get(opts.get("environment"))
                h = None if env is None else self.ok(self.call("[static]endpoint.create", env, roots, opts.get("nowMillis")))
        except (wasmtime.WasmtimeError, Refused):
            h = None
        self.handles[key] = h
        return h

    @staticmethod
    def ok(v):
        # wasmtime-py leaves a result untagged when its ok and err types
        # differ: a constructor answers the resource, or the error payload.
        if isinstance(v, wc.Variant):
            v = v.payload if v.tag == "ok" else None
        if isinstance(v, wc.ResourceAny):
            return v
        raise Refused(v)

    def row(self, r):
        opts = json.loads(r["options"])
        data = base64.b64decode(r["input"])
        rid = r["id"]
        h = self.handle(r, opts)
        if h is None:
            return {"id": rid, "code": "CTOR_REFUSED", "json": None}
        text = None
        if r["kind"] != "receipt" or r.get("base64"):
            if b"\0" in data:
                return {"id": rid, "code": "NUL_IN_BODY" if r["kind"] == "endpoint" else "NUL_IN_INPUT", "json": None}
            try:
                text = data.decode("utf-8")  # keeps a BOM, as the C ABI does
            except UnicodeDecodeError:
                return {"id": rid, "code": 101, "json": None}
        if r["kind"] == "endpoint":
            return {"id": rid, "code": None, "json": self.call("[method]endpoint.verify-receipt-json", h, text)}
        if r["kind"] == "jws":
            name = ["[method]jws-verifier.verify-transaction", "[method]jws-verifier.verify-app-transaction",
                    "[method]jws-verifier.verify-raw"][r["op"]]
            v = self.call(name, h, text)
        else:
            guid = bytes.fromhex(r["guidHex"]) if r.get("guidHex") is not None else None
            v = (self.call("[method]receipt-verifier.verify-base64", h, text, guid) if r.get("base64")
                 else self.call("[method]receipt-verifier.verify", h, data, guid))
        if isinstance(v, wc.Variant) and v.tag == "err":
            p = v.payload
            if isinstance(p, str):
                return {"id": rid, "code": int(p.split()[-1]) if p.startswith("status ") else "CONFIG", "json": None}
            return {"id": rid, "code": REASON[p.reason], "json": None}
        if isinstance(v, wc.Variant):
            v = v.payload
        return {"id": rid, "code": 0, "json": v}


class Refused(Exception):
    pass


def main():
    host = Host(sys.argv[1])
    traps = 0
    rows = [json.loads(l) for l in open(sys.argv[2], encoding="utf-8") if l.strip()]
    for r in rows:
        try:
            row = host.row(r)
        except wasmtime.Trap as e:
            traps += 1
            host.fresh()
            row = {"id": r["id"], "code": "TRAP", "json": None, "trap": str(e).splitlines()[0]}
        print(json.dumps(row))
    print(json.dumps({"host": "wasmtime-component", "calls": calls, "traps": traps, "rows": len(rows)}), file=sys.stderr)


if __name__ == "__main__":
    main()
