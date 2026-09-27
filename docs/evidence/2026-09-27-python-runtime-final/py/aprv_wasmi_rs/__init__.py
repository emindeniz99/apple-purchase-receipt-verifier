"""Spike only (2026-09-27, round 11): a ctypes facade for aprv.wasm (ABI v1)
over ../wasmi-cdylib, an APRV-specific C ABI around Wasmi 2.0.0's safe Rust
API. The host imports run in Rust, so Python never re-enters during a call,
and ctypes releases the GIL for the whole aprv_call. Not a general binding.

Environment (read once per process):
  APRV_LIBAPRVWASMI  path to libaprv_wasmi.so built from ../wasmi-cdylib
  APRV_MODULE        path to aprv.wasm
  APRV_WASMI_MODE    lazy-translation (default) | lazy | eager
  APRV_WASMI_FUEL    per-call fuel budget, 0 = metering off (default 0)
  APRV_WASMI_MAXMEM  linear-memory cap in bytes, 0 = none (default 0)
"""
import ctypes as C
import json
import os
import threading
import time

__all__ = ["Verifier", "AbiMismatchError", "WasmTrapError", "OP", "LOAD_INFO", "InProcHost"]

ABI_VERSION = 1
OP = {"VERIFY_RECEIPT": 1, "VERIFY_SIGNED_DATA": 2, "ENDPOINT_PRODUCTION": 3, "ENDPOINT_SANDBOX": 4}
LOAD_INFO = {}
_MODES = {"eager": 0, "lazy-translation": 1, "lazy": 2}
_CAP = 512


class AbiMismatchError(RuntimeError):
    pass


class WasmTrapError(RuntimeError):
    pass


class _Trap(Exception):
    pass


_lib = _rt = None
_lock = threading.Lock()


def _runtime():
    global _lib, _rt
    with _lock:
        if _rt is None:
            t0 = time.perf_counter()
            lib = C.CDLL(os.environ["APRV_LIBAPRVWASMI"])
            P, S, E = C.c_void_p, C.c_size_t, C.c_char_p
            for name, args, res in [
                ("aprv_rt_new", [C.c_char_p, S, C.c_uint32, C.c_uint64, S, E, S], P),
                ("aprv_rt_free", [P], None),
                ("aprv_inst_new", [P, E, S], P),
                ("aprv_inst_free", [P], None),
                ("aprv_inst_invoke", [P, P, C.c_int32, C.c_int32, C.c_char_p, S, C.POINTER(C.c_void_p), C.POINTER(S), E, S], C.c_int32),
                ("aprv_buf_free", [P, S], None),
                ("aprv_inst_raw", [P, P, C.c_char_p, C.POINTER(C.c_int32), S, C.POINTER(C.c_int32), C.POINTER(C.c_uint32), E, S], C.c_int32),
                ("aprv_inst_memory_size", [P], S),
                ("aprv_inst_fuel_used", [P], C.c_uint64),
                ("aprv_import_counts", [C.POINTER(C.c_uint64), C.POINTER(C.c_uint64)], None),
            ]:
                f = getattr(lib, name)
                f.argtypes, f.restype = args, res
            t1 = time.perf_counter()
            data = open(os.environ["APRV_MODULE"], "rb").read()
            err = C.create_string_buffer(_CAP)
            rt = lib.aprv_rt_new(data, len(data), _MODES[os.environ.get("APRV_WASMI_MODE", "lazy-translation")],
                                 int(os.environ.get("APRV_WASMI_FUEL", "0")), int(os.environ.get("APRV_WASMI_MAXMEM", "0")), err, _CAP)
            if not rt:
                raise RuntimeError(err.value.decode("utf-8", "replace"))
            _lib, _rt = lib, rt
            LOAD_INFO.update(init_ms=round((t1 - t0) * 1000, 3), load_ms=round((time.perf_counter() - t1) * 1000, 3))
        return _lib


class _Instance:
    def __init__(self):
        self.lib = _runtime()
        self.err = C.create_string_buffer(_CAP)
        self.ptr = self.lib.aprv_inst_new(_rt, self.err, _CAP)
        if not self.ptr:
            text = self.err.value.decode("utf-8", "replace")
            raise (AbiMismatchError if "ABI mismatch" in text else RuntimeError)(text)
        self.module_version = ABI_VERSION

    def _fail(self, code):
        # 1 = trap, 3 = a Rust panic caught at the boundary: either way the
        # instance's state is suspect, so both discard it (as _Trap).
        text = self.err.value.decode("utf-8", "replace")
        raise (_Trap if code in (1, 3) else RuntimeError)(text)

    def raw(self, name, *args):
        a = (C.c_int32 * max(len(args), 1))(*args)
        r, n = C.c_int32(), C.c_uint32()
        code = self.lib.aprv_inst_raw(_rt, self.ptr, name.encode(), a, len(args), C.byref(r), C.byref(n), self.err, _CAP)
        if code:
            self._fail(code)
        return r.value if n.value else None

    def mem_len(self):
        return self.lib.aprv_inst_memory_size(self.ptr)

    def fuel_used(self):
        return self.lib.aprv_inst_fuel_used(self.ptr)

    def invoke(self, operation, data, abi_version=ABI_VERSION):
        out, n = C.c_void_p(), C.c_size_t()
        code = self.lib.aprv_inst_invoke(_rt, self.ptr, abi_version, operation, data, len(data), C.byref(out), C.byref(n), self.err, _CAP)
        if code:
            if code == 1 and abi_version != self.module_version:
                raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={abi_version}")
            if code == 2 and "aprv_alloc" in self.err.value.decode():
                raise MemoryError(self.err.value.decode())
            self._fail(code)
        try:
            return C.string_at(out.value, n.value) if n.value else b""
        finally:
            self.lib.aprv_buf_free(out, n)

    def close(self):
        if self.ptr:
            self.lib.aprv_inst_free(self.ptr)
            self.ptr = None


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
            self._inst.close()
            self._inst = None
            self.traps += 1
            raise WasmTrapError(str(e)) from None
        except AbiMismatchError:
            self._inst.close()
            self._inst = None
            raise

    def verify_receipt(self, receipt_data):
        data = receipt_data.encode() if isinstance(receipt_data, str) else bytes(receipt_data)
        return json.loads(self.call(OP["VERIFY_RECEIPT"], data))


class InProcHost:
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
        c, r = C.c_uint64(), C.c_uint64()
        _runtime().aprv_import_counts(C.byref(c), C.byref(r))
        return {"aprv.clock_now_ms": c.value, "aprv.random_get": r.value}

    def label(self):
        return (f"python ctypes aprv-wasmi (Rust cdylib) {os.environ.get('APRV_WASMI_MODE', 'lazy-translation')}"
                f" fuel={os.environ.get('APRV_WASMI_FUEL', '0')}")

    def close(self):
        for i in list(self.insts):
            self.drop(i)
