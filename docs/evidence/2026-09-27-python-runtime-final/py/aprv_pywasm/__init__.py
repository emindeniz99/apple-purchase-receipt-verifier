"""Spike only (2026-09-27, round 11): a minimal APRV facade over pywasm
2.2.3, the pure-Python WebAssembly interpreter (no native code at all).

    APRV_MODULE=aprv-abi1.wasm  python -c "import aprv_pywasm; ..."

It registers exactly aprv.clock_now_ms and aprv.random_get and runs the ABI
v1 call lifecycle. pywasm keeps one Machine (stack + store) per Runtime, so
every instance gets its own Runtime, which is also what makes "discard the
instance after a trap" clean: a trap leaves pywasm's stack mid-call.

Two pywasm behaviours shape it (read in pywasm/core.py 2.2.3):
- `data.drop` clears the parsed module's data-segment bytearray in place,
  so a parsed ModuleDesc cannot be instantiated twice as-is; each instance
  gets fresh copies of the segments.
- Traps are Python exceptions, most of them `assert` statements
  (`unreachable` is `assert 0`; bounds checks are asserts).
"""
import json
import os
import time

import pywasm

__all__ = ["Verifier", "AbiMismatchError", "WasmTrapError", "OP", "LOAD_INFO", "IMPORT_CALLS", "InProcHost"]

ABI_VERSION = 1
OP = {"VERIFY_RECEIPT": 1, "VERIFY_SIGNED_DATA": 2, "ENDPOINT_PRODUCTION": 3, "ENDPOINT_SANDBOX": 4}
IMPORT_CALLS = {"aprv.clock_now_ms": 0, "aprv.random_get": 0}
LOAD_INFO = {}
_desc = None
_segments = None
C = pywasm.core


class AbiMismatchError(RuntimeError):
    pass


class WasmTrapError(RuntimeError):
    pass


class _Trap(Exception):
    pass


def _module():
    """Parse the module once per process (pywasm has no separate validation step)."""
    global _desc, _segments
    if _desc is None:
        t = time.perf_counter()
        with open(os.environ["APRV_MODULE"], "rb") as f:
            _desc = C.ModuleDesc.from_reader(f)
        _segments = [bytes(d.init) for d in _desc.data]
        LOAD_INFO.update(init_ms=0.0, load_ms=round((time.perf_counter() - t) * 1000, 3))
    for d, seg in zip(_desc.data, _segments):
        d.init = bytearray(seg)  # data.drop clears it in place
    return _desc


class _Instance:
    def __init__(self):
        desc = _module()
        rt = C.Runtime()
        holder = {}

        def clock_now_ms(_machine, _args):
            IMPORT_CALLS["aprv.clock_now_ms"] += 1
            return [float(time.time_ns() // 1_000_000)]

        def random_get(_machine, args):
            IMPORT_CALLS["aprv.random_get"] += 1
            ptr, n = args
            mem = holder["mem"]
            if ptr < 0 or n < 0 or ptr + n > len(mem.data):
                raise _Trap("aprv.random_get out of bounds")
            if n:
                mem.data[ptr:ptr + n] = os.urandom(n)
            return [0]

        i32, f64 = C.ValType.i32(), C.ValType.f64()
        rt.imports["aprv"] = {
            "clock_now_ms": rt.allocate_func_host(C.FuncType([], [f64]), clock_now_ms),
            "random_get": rt.allocate_func_host(C.FuncType([i32, i32], [i32]), random_get),
        }
        self.rt = rt
        self.m = rt.instance(desc)
        self.mem = holder["mem"] = rt.exported_memory(self.m, "memory")
        self.raw("_initialize")
        self.module_version = self.raw("aprv_abi_version")
        if self.module_version != ABI_VERSION:
            raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={ABI_VERSION}")

    def raw(self, name, *args):
        try:
            r = self.rt.invocate(self.m, name, list(args))
        except _Trap:
            raise
        except Exception as e:  # noqa: BLE001  pywasm traps are plain exceptions and asserts
            raise _Trap(f"{type(e).__name__}: {e}".strip()) from None
        return r[0] if r else None

    def mem_len(self):
        return len(self.mem.data)

    def invoke(self, operation, data, abi_version=ABI_VERSION):
        n = len(data)
        p = self.raw("aprv_alloc", n)
        if p == 0:
            raise MemoryError(f"aprv_alloc({n}) failed")
        pu = p & 0xFFFFFFFF
        if n:
            if pu + n > len(self.mem.data):
                raise _Trap("input out of bounds")
            self.mem.data[pu:pu + n] = data
        try:
            h = self.raw("aprv_call", abi_version, operation, p, n)
        except _Trap:
            if abi_version != self.module_version:
                raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={abi_version}") from None
            raise
        rp = self.raw("aprv_result_ptr", h) & 0xFFFFFFFF
        rn = self.raw("aprv_result_len", h) & 0xFFFFFFFF
        if rp + rn > len(self.mem.data):
            raise _Trap("result out of bounds")
        out = bytes(self.mem.data[rp:rp + rn])
        self.raw("aprv_result_free", h)
        self.raw("aprv_dealloc", p, n)
        return out

    def close(self):
        self.rt = self.m = self.mem = None


class Verifier:
    def __init__(self):
        self._inst = _Instance()
        self.traps = 0

    def call(self, operation, data, abi_version=ABI_VERSION):
        if self._inst is None:
            self._inst = _Instance()
        try:
            return self._inst.invoke(operation, bytes(data), abi_version)
        except (_Trap, MemoryError) as e:
            self._inst = None
            self.traps += 1
            raise WasmTrapError(str(e)) from None
        except AbiMismatchError:
            self._inst = None
            raise

    def verify_receipt(self, receipt_data):
        data = receipt_data.encode() if isinstance(receipt_data, str) else bytes(receipt_data)
        return json.loads(self.call(OP["VERIFY_RECEIPT"], data))


class InProcHost:
    """The driver protocol's operations in process (py/driver.py)."""

    def __init__(self):
        self.insts, self.next = {}, 1

    def new(self):
        self.insts[self.next] = _Instance()
        self.next += 1
        return self.next - 1

    def drop(self, i):
        self.insts.pop(i).close()

    def raw(self, i, name, *args):
        return self.insts[i].raw(name, *args)

    def invoke(self, i, abi, op, data):
        return self.insts[i].invoke(op, data, abi)

    def mem_len(self, i):
        return self.insts[i].mem_len()

    def import_calls(self):
        return dict(IMPORT_CALLS)

    def label(self):
        return "python pywasm 2.2.3"

    def close(self):
        for i in list(self.insts):
            self.drop(i)
