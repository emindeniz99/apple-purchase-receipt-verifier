"""Spike only (2026-09-26): a minimal Python facade over aprv.wasm (ABI v1)
on the official Bytecode Alliance wasmtime-py.

    from aprv_wasm import Verifier
    v = Verifier()                       # one per worker; never shared
    v.verify_receipt(receipt_data)       # -> dict: verified + payload, or verified=False + reason
    v.verify_signed_data(jws)            # -> dict: verified + payload + payloadJson, or failure
    v.verify_receipt_endpoint("Sandbox", body)   # -> str: the verifyReceipt answer, byte for byte

No business policy: the caller compares bundleId, environment and
appAppleId from the payload.

Errors, kept apart:
- a verification failure is a value (verified=False), never an exception;
- AbiMismatchError: the module speaks another ABI version;
- WasmTrapError: the instance trapped (an internal failure). The Verifier
  discards that instance and starts a fresh one on its next call.

Threading: the Engine, the compiled Module and a Linker that holds the two
host functions are process-wide and created once. Each Verifier owns its
Store and Instance and must be used by one thread at a time. The host
functions are defined once on the Linker, never per Store: wasmtime-py
49.0.0's handle table for Python callbacks is not safe when handles are
allocated and freed from several threads (fixed upstream after 49.0.0,
bytecodealliance/wasmtime-py#344); a Linker defined once allocates its two
handles at start-up and never frees them.
"""
import json
import os
import threading
import time
from importlib import resources

import wasmtime

__all__ = ["Verifier", "AbiMismatchError", "WasmTrapError", "ABI_VERSION", "OP"]

ABI_VERSION = 1
OP = {"VERIFY_RECEIPT": 1, "VERIFY_SIGNED_DATA": 2, "ENDPOINT_PRODUCTION": 3, "ENDPOINT_SANDBOX": 4}
_ENDPOINT = {"Production": 3, "Sandbox": 4}


class AbiMismatchError(RuntimeError):
    """The module and this facade disagree on the ABI version."""


class WasmTrapError(RuntimeError):
    """The instance trapped: an internal failure, not a verdict."""


# Calls into the two host functions, process-wide (for tests; not exact under threads).
IMPORT_CALLS = {"aprv.clock_now_ms": 0, "aprv.random_get": 0}


def _clock_now_ms():
    IMPORT_CALLS["aprv.clock_now_ms"] += 1
    return float(time.time_ns() // 1_000_000)


def _random_get(caller, ptr, length):
    IMPORT_CALLS["aprv.random_get"] += 1
    memory = caller["memory"]
    if ptr < 0 or length < 0 or ptr + length > memory.data_len(caller):
        raise wasmtime.WasmtimeError("aprv.random_get out of bounds")
    if length:
        memory.write(caller, os.urandom(length), ptr)
    return 0


_shared = None
_shared_lock = threading.Lock()


def _runtime():
    """(engine, module, linker), created once per process."""
    global _shared
    with _shared_lock:
        if _shared is None:
            engine = wasmtime.Engine()
            module = wasmtime.Module(engine, resources.files(__name__).joinpath("aprv.wasm").read_bytes())
            for imp in module.imports:
                if (imp.module, imp.name) not in {("aprv", "clock_now_ms"), ("aprv", "random_get")}:
                    raise AbiMismatchError(f"unexpected import {imp.module}.{imp.name}")
            linker = wasmtime.Linker(engine)
            f64, i32 = wasmtime.ValType.f64(), wasmtime.ValType.i32()
            linker.define_func("aprv", "clock_now_ms", wasmtime.FuncType([], [f64]), _clock_now_ms)
            linker.define_func("aprv", "random_get", wasmtime.FuncType([i32, i32], [i32]), _random_get, access_caller=True)
            _shared = (engine, module, linker)
        return _shared


class _Instance:
    def __init__(self):
        engine, module, linker = _runtime()
        self.store = wasmtime.Store(engine)
        inst = linker.instantiate(self.store, module)
        x = inst.exports(self.store)
        self.memory = x["memory"]
        self.alloc, self.dealloc, self.call = x["aprv_alloc"], x["aprv_dealloc"], x["aprv_call"]
        self.rptr, self.rlen, self.rfree = x["aprv_result_ptr"], x["aprv_result_len"], x["aprv_result_free"]
        self.version = x["aprv_abi_version"]
        self.exports = x
        x["_initialize"](self.store)
        self.module_version = self.version(self.store)
        if self.module_version != ABI_VERSION:
            raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={ABI_VERSION}")

    def invoke(self, operation, data, abi_version=ABI_VERSION):
        s = self.store
        n = len(data)
        p = self.alloc(s, n)
        if p == 0:
            raise MemoryError(f"aprv_alloc({n}) failed")
        if n:
            self.memory.write(s, data, p)
        try:
            h = self.call(s, abi_version, operation, p, n)
        except wasmtime.Trap:
            if abi_version != self.module_version:
                raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={abi_version}") from None
            raise
        rp = self.rptr(s, h) & 0xFFFFFFFF
        rn = self.rlen(s, h) & 0xFFFFFFFF
        if rp + rn > self.memory.data_len(s):
            raise WasmTrapError("result out of bounds")
        out = bytes(self.memory.read(s, rp, rp + rn))  # a copy owned by Python
        self.rfree(s, h)
        self.dealloc(s, p, n)
        return out


class Verifier:
    """One instance of aprv.wasm. Use from one thread at a time."""

    def __init__(self):
        self._inst = _Instance()
        self.traps = 0

    def call(self, operation, data, abi_version=ABI_VERSION):
        """The raw ABI call: bytes in, result bytes out. A trap discards the instance."""
        if self._inst is None:
            self._inst = _Instance()
        try:
            return self._inst.invoke(operation, bytes(data), abi_version)
        except (wasmtime.Trap, wasmtime.WasmtimeError, WasmTrapError) as e:
            self._inst = None  # trap => discard; the next call starts fresh
            self.traps += 1
            raise WasmTrapError(str(e)) from None
        except AbiMismatchError:
            self._inst = None
            raise

    @staticmethod
    def _text(value):
        return value.encode("utf-8") if isinstance(value, str) else bytes(value)

    def verify_receipt(self, receipt_data):
        """receipt_data: the base64 string a client sends (str or bytes)."""
        return json.loads(self.call(OP["VERIFY_RECEIPT"], self._text(receipt_data)))

    def verify_signed_data(self, jws):
        """jws: a compact JWS (str or bytes)."""
        return json.loads(self.call(OP["VERIFY_SIGNED_DATA"], self._text(jws)))

    def verify_receipt_endpoint(self, environment, body):
        """environment: "Production" or "Sandbox"; body: the request JSON. Returns the answer text."""
        return self.call(_ENDPOINT[environment], self._text(body)).decode("utf-8")
