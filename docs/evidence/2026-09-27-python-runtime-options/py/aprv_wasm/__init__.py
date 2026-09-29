"""Spike only (2026-09-27): round 7's facade (2026-09-26-python-wasmtime,
facade/src/aprv_wasm) with the engine and the module source made
selectable, so round 7's harness (run_calls.py, abi_tests.py,
concurrency.py) runs unchanged against every wasmtime-py option. The
Verifier, the call lifecycle and the error classes are round 7's.

Selected by environment variables, read once per process:

  APRV_ENGINE   cranelift (default: Cranelift, opt level "speed")
                cranelift-none (Cranelift, opt level "none")
                winch (Wasmtime's baseline compiler; wasmtime-py 49.0.0 has no
                  setter value for it, so this calls the C API's
                  wasmtime_config_strategy_set with WASMTIME_STRATEGY_WINCH)
                pulley (Config.target = "pulley64": Wasmtime's interpreter)
  APRV_BASELINE 1: Config.target = "x86_64-unknown-linux-gnu", which turns off
                the inference of the host's CPU features (what a module
                precompiled for a wheel must use)
  APRV_TARGET   a target triple, for cross-compiling with precompile.py only
  APRV_MODULE   path to aprv.wasm (compiled at start) or to a .cwasm made by
                Module.serialize with the same wasmtime and the same settings
                (loaded with Module.deserialize_file)
  APRV_PARALLEL 0: Config.parallel_compilation = False (compile on one thread)
  APRV_CACHE    path to a Wasmtime cache TOML: Config.cache (on-disk cache)
  APRV_FILECACHE  a directory: per-machine file cache written on first run
                (Module.serialize on a miss, Module.deserialize_file on a hit),
                keyed by module sha256, wasmtime version and settings

LOAD_INFO records what happened: {"source", "load_ms"}.
"""
import json
import os
import threading
import time

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
LOAD_INFO = {}
WASMTIME_STRATEGY_WINCH = 2  # wasmtime/config.h: AUTO 0, CRANELIFT 1, WINCH 2


def _config():
    engine = os.environ.get("APRV_ENGINE", "cranelift")
    cfg = wasmtime.Config()
    if engine == "cranelift-none":
        cfg.cranelift_opt_level = "none"
    elif engine == "winch":
        wasmtime._ffi.wasmtime_config_strategy_set(cfg.ptr(), WASMTIME_STRATEGY_WINCH)
    elif engine == "pulley":
        cfg.target = "pulley64"
    elif engine != "cranelift":
        raise ValueError(f"unknown APRV_ENGINE {engine}")
    if os.environ.get("APRV_BASELINE") == "1":
        if engine == "pulley":
            raise ValueError("APRV_BASELINE does not apply to pulley")
        cfg.target = "x86_64-unknown-linux-gnu"
    if os.environ.get("APRV_TARGET"):
        cfg.target = os.environ["APRV_TARGET"]  # precompile.py only: cross-compiling for another wheel
    if os.environ.get("APRV_PARALLEL") == "0":
        cfg.parallel_compilation = False
    if os.environ.get("APRV_CACHE"):
        cfg.cache = os.environ["APRV_CACHE"]
    return cfg, engine


def _load_module(engine_obj, engine_name):
    path = os.environ["APRV_MODULE"]
    t = time.perf_counter()
    if path.endswith(".cwasm"):
        module, source = wasmtime.Module.deserialize_file(engine_obj, path), "precompiled .cwasm, deserialized"
    elif os.environ.get("APRV_FILECACHE"):
        import hashlib
        from importlib import metadata
        wasm = open(path, "rb").read()
        key = hashlib.sha256(wasm + f"|{metadata.version('wasmtime')}|{engine_name}|{os.environ.get('APRV_BASELINE', '0')}".encode()).hexdigest()[:32]
        cached = os.path.join(os.environ["APRV_FILECACHE"], key + ".cwasm")
        try:
            module, source = wasmtime.Module.deserialize_file(engine_obj, cached), "file cache hit, deserialized"
        except Exception:  # noqa: BLE001  a miss, or a file this wasmtime refuses
            module, source = wasmtime.Module(engine_obj, wasm), "file cache miss, compiled and written"
            tmp = f"{cached}.{os.getpid()}.tmp"
            with open(tmp, "wb") as f:
                f.write(module.serialize())
            os.replace(tmp, cached)
    else:
        module, source = wasmtime.Module(engine_obj, open(path, "rb").read()), "compiled at start"
    LOAD_INFO.update(source=source, load_ms=round((time.perf_counter() - t) * 1000, 1), engine=engine_name)
    return module


def _runtime():
    """(engine, module, linker), created once per process."""
    global _shared
    with _shared_lock:
        if _shared is None:
            cfg, name = _config()
            engine = wasmtime.Engine(cfg)
            module = _load_module(engine, name)
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
