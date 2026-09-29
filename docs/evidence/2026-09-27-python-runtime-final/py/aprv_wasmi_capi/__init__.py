"""Spike only (2026-09-27, round 11): a minimal ctypes facade for aprv.wasm
(ABI v1) over Wasmi 2.0.0's official WebAssembly C API (wasm.h, plus the
wasmi.h config extensions), built as one shared library from the
wasmi_c_api_impl crate (../wasmi-capi). Not a general binding.

Environment (read once per process):
  APRV_LIBWASMI  path to the libwasmi.so built from ../wasmi-capi
  APRV_MODULE    path to aprv.wasm
  APRV_WASMI_MODE  lazy-translation (default) | lazy | eager
  APRV_WASMI_FUEL  1: wasmi_config_consume_fuel_set(true) (see the note: the
                   wasm.h store has no way to add fuel, so every call traps)

C API functions called: wasm_config_new, wasmi_config_compilation_mode_set,
wasmi_config_consume_fuel_set, wasm_engine_new_with_config, wasm_store_new,
wasm_store_delete, wasm_byte_vec_new, wasm_byte_vec_delete, wasm_module_new,
wasm_valtype_new, wasm_valtype_vec_new, wasm_valtype_vec_new_empty,
wasm_functype_new, wasm_functype_delete, wasm_func_new_with_env,
wasm_func_as_extern, wasm_instance_new, wasm_instance_delete,
wasm_instance_exports, wasm_module_exports, wasm_exporttype_name,
wasm_exporttype_vec_delete, wasm_extern_vec_delete, wasm_extern_as_func,
wasm_extern_as_memory, wasm_func_call, wasm_func_result_arity,
wasm_memory_data, wasm_memory_data_size, wasm_trap_new, wasm_trap_message,
wasm_trap_delete. Nothing from the unimplemented set (wasm_trap_origin,
wasm_trap_trace, wasm_frame_*, wasm_module_serialize/deserialize,
wasm_foreign_new, wasm_ref_*host_info*).

Host functions are Python callbacks (ctypes CFUNCTYPE): every aprv_call runs
aprv.clock_now_ms back in Python, which retakes the GIL.
"""
import ctypes as C
import json
import os
import threading
import time

__all__ = ["Verifier", "AbiMismatchError", "WasmTrapError", "OP", "LOAD_INFO", "IMPORT_CALLS", "InProcHost"]

ABI_VERSION = 1
OP = {"VERIFY_RECEIPT": 1, "VERIFY_SIGNED_DATA": 2, "ENDPOINT_PRODUCTION": 3, "ENDPOINT_SANDBOX": 4}
IMPORT_CALLS = {"aprv.clock_now_ms": 0, "aprv.random_get": 0}
LOAD_INFO = {}


class AbiMismatchError(RuntimeError):
    pass


class WasmTrapError(RuntimeError):
    pass


class _Trap(Exception):
    pass


class _ByteVec(C.Structure):
    _fields_ = [("size", C.c_size_t), ("data", C.c_void_p)]


class _PtrVec(C.Structure):  # wasm_valtype_vec_t, wasm_extern_vec_t, wasm_exporttype_vec_t
    _fields_ = [("size", C.c_size_t), ("data", C.POINTER(C.c_void_p))]


class _Val(C.Structure):
    _fields_ = [("kind", C.c_uint8), ("_pad", C.c_uint8 * 7), ("of", C.c_int64)]


class _ValVec(C.Structure):
    _fields_ = [("size", C.c_size_t), ("data", C.POINTER(_Val))]


assert C.sizeof(_Val) == 16
_CALLBACK = C.CFUNCTYPE(C.c_void_p, C.c_void_p, C.POINTER(_ValVec), C.POINTER(_ValVec))
_MODES = {"eager": 0, "lazy-translation": 1, "lazy": 2}
_I32, _F64 = 0, 3

_lib = _engine = _module = None
_export_names = []
_lock = threading.Lock()
_envs = {}          # env id -> {"store", "memory"} for the host callbacks
_next_env = [1]


def _bind(lib):
    P, S, B, U8 = C.c_void_p, C.c_size_t, C.c_bool, C.c_uint8
    sig = {
        "wasm_config_new": ([], P), "wasmi_config_compilation_mode_set": ([P, U8], None),
        "wasmi_config_consume_fuel_set": ([P, B], None), "wasm_engine_new_with_config": ([P], P),
        "wasm_store_new": ([P], P), "wasm_store_delete": ([P], None),
        "wasm_byte_vec_new": ([C.POINTER(_ByteVec), S, C.c_char_p], None), "wasm_byte_vec_delete": ([C.POINTER(_ByteVec)], None),
        "wasm_module_new": ([P, C.POINTER(_ByteVec)], P),
        "wasm_valtype_new": ([U8], P), "wasm_valtype_vec_new": ([C.POINTER(_PtrVec), S, C.POINTER(C.c_void_p)], None),
        "wasm_valtype_vec_new_empty": ([C.POINTER(_PtrVec)], None),
        "wasm_functype_new": ([C.POINTER(_PtrVec), C.POINTER(_PtrVec)], P), "wasm_functype_delete": ([P], None),
        "wasm_func_new_with_env": ([P, P, _CALLBACK, P, P], P), "wasm_func_as_extern": ([P], P),
        "wasm_instance_new": ([P, P, C.POINTER(_PtrVec), C.POINTER(C.c_void_p)], P), "wasm_instance_delete": ([P], None),
        "wasm_instance_exports": ([P, C.POINTER(_PtrVec)], None), "wasm_module_exports": ([P, C.POINTER(_PtrVec)], None),
        "wasm_exporttype_name": ([P], C.POINTER(_ByteVec)), "wasm_exporttype_vec_delete": ([C.POINTER(_PtrVec)], None),
        "wasm_extern_vec_delete": ([C.POINTER(_PtrVec)], None),
        "wasm_extern_as_func": ([P], P), "wasm_extern_as_memory": ([P], P),
        "wasm_func_call": ([P, C.POINTER(_ValVec), C.POINTER(_ValVec)], P), "wasm_func_result_arity": ([P], S),
        "wasm_memory_data": ([P], P), "wasm_memory_data_size": ([P], S),
        "wasm_trap_new": ([P, C.POINTER(_ByteVec)], P), "wasm_trap_message": ([P, C.POINTER(_ByteVec)], None),
        "wasm_trap_delete": ([P], None),
    }
    for name, (args, res) in sig.items():
        f = getattr(lib, name)
        f.argtypes, f.restype = args, res


def _trap(env_id, text):
    msg = _ByteVec()
    raw = text.encode() + b"\0"
    _lib.wasm_byte_vec_new(C.byref(msg), len(raw), raw)
    t = _lib.wasm_trap_new(_envs[env_id]["store"], C.byref(msg))
    _lib.wasm_byte_vec_delete(C.byref(msg))
    return t


@_CALLBACK
def _clock_now_ms(env, args, results):
    IMPORT_CALLS["aprv.clock_now_ms"] += 1
    r = results.contents.data[0]
    r.kind = _F64
    C.cast(C.byref(r, 8), C.POINTER(C.c_double))[0] = float(time.time_ns() // 1_000_000)
    return None


@_CALLBACK
def _random_get(env, args, results):
    IMPORT_CALLS["aprv.random_get"] += 1
    a = args.contents.data
    ptr, n = C.c_int32(a[0].of).value, C.c_int32(a[1].of).value
    mem = _envs[env]["memory"]
    size = _lib.wasm_memory_data_size(mem)
    if ptr < 0 or n < 0 or ptr + n > size:
        return _trap(env, "aprv.random_get out of bounds")
    if n:
        C.memmove(_lib.wasm_memory_data(mem) + ptr, os.urandom(n), n)
    r = results.contents.data[0]
    r.kind, r.of = _I32, 0
    return None


def _functype(params, results):
    def vec(kinds):
        v = _PtrVec()
        if not kinds:
            _lib.wasm_valtype_vec_new_empty(C.byref(v))
        else:
            arr = (C.c_void_p * len(kinds))(*[_lib.wasm_valtype_new(k) for k in kinds])
            _lib.wasm_valtype_vec_new(C.byref(v), len(kinds), arr)
        return v
    p, r = vec(params), vec(results)
    return _lib.wasm_functype_new(C.byref(p), C.byref(r))  # takes ownership of both vectors


def _runtime():
    global _lib, _engine, _module
    with _lock:
        if _module is None:
            t0 = time.perf_counter()
            lib = C.CDLL(os.environ["APRV_LIBWASMI"])
            _bind(lib)
            _lib = lib
            cfg = lib.wasm_config_new()
            lib.wasmi_config_compilation_mode_set(cfg, _MODES[os.environ.get("APRV_WASMI_MODE", "lazy-translation")])
            if os.environ.get("APRV_WASMI_FUEL") == "1":
                lib.wasmi_config_consume_fuel_set(cfg, True)
            _engine = lib.wasm_engine_new_with_config(cfg)
            t1 = time.perf_counter()
            data = open(os.environ["APRV_MODULE"], "rb").read()
            bv = _ByteVec()
            lib.wasm_byte_vec_new(C.byref(bv), len(data), data)
            store = lib.wasm_store_new(_engine)  # wasm_module_new takes a store; the module belongs to the engine
            _module = lib.wasm_module_new(store, C.byref(bv))
            lib.wasm_byte_vec_delete(C.byref(bv))
            if not _module:
                raise RuntimeError("wasm_module_new failed (the C API returns no reason)")
            ets = _PtrVec()
            lib.wasm_module_exports(_module, C.byref(ets))
            for i in range(ets.size):
                nm = lib.wasm_exporttype_name(ets.data[i]).contents
                _export_names.append(C.string_at(nm.data, nm.size).decode())
            lib.wasm_exporttype_vec_delete(C.byref(ets))
            lib.wasm_store_delete(store)
            LOAD_INFO.update(init_ms=round((t1 - t0) * 1000, 3), load_ms=round((time.perf_counter() - t1) * 1000, 3))
        return _lib


class _Instance:
    """One wasm_store_t per instance, so discarding an instance frees everything it made."""

    def __init__(self):
        lib = _runtime()
        self.lib = lib
        self.store = lib.wasm_store_new(_engine)
        self.env = _next_env[0]
        _next_env[0] += 1
        _envs[self.env] = {"store": self.store, "memory": None}
        ft_clock, ft_rand = _functype([], [_F64]), _functype([_I32, _I32], [_I32])
        f_clock = lib.wasm_func_new_with_env(self.store, ft_clock, _clock_now_ms, self.env, None)
        f_rand = lib.wasm_func_new_with_env(self.store, ft_rand, _random_get, self.env, None)
        lib.wasm_functype_delete(ft_clock)
        lib.wasm_functype_delete(ft_rand)
        imports = _PtrVec(2, (C.c_void_p * 2)(lib.wasm_func_as_extern(f_clock), lib.wasm_func_as_extern(f_rand)))
        trap = C.c_void_p()
        self.inst = lib.wasm_instance_new(self.store, _module, C.byref(imports), C.byref(trap))
        if not self.inst:
            raise RuntimeError(f"instantiate: {self._trap_text(trap.value) if trap.value else 'failed'}")
        self.exports = _PtrVec()
        lib.wasm_instance_exports(self.inst, C.byref(self.exports))
        ex = {n: self.exports.data[i] for i, n in enumerate(_export_names)}
        self.memory = lib.wasm_extern_as_memory(ex["memory"])
        _envs[self.env]["memory"] = self.memory
        self.f = {n: lib.wasm_extern_as_func(e) for n, e in ex.items() if n != "memory"}
        self.arity = {n: lib.wasm_func_result_arity(f) for n, f in self.f.items()}
        self._args, self._res = (_Val * 4)(), (_Val * 1)()
        self.raw("_initialize")
        self.module_version = self.raw("aprv_abi_version")
        if self.module_version != ABI_VERSION:
            raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={ABI_VERSION}")

    def _trap_text(self, t):
        m = _ByteVec()
        self.lib.wasm_trap_message(t, C.byref(m))
        text = C.string_at(m.data, m.size).rstrip(b"\0").decode("utf-8", "replace")
        self.lib.wasm_byte_vec_delete(C.byref(m))
        self.lib.wasm_trap_delete(t)
        return text

    def raw(self, name, *args):
        f = self.f.get(name)
        if not f:
            raise RuntimeError(f"no export {name}")
        for i, v in enumerate(args):
            self._args[i].kind, self._args[i].of = _I32, v
        nres = self.arity[name]
        t = self.lib.wasm_func_call(f, C.byref(_ValVec(len(args), self._args)), C.byref(_ValVec(nres, self._res)))
        if t:
            raise _Trap(self._trap_text(t))
        return C.c_int32(self._res[0].of).value if nres else None

    def mem(self):
        return self.lib.wasm_memory_data(self.memory), self.lib.wasm_memory_data_size(self.memory)

    def mem_len(self):
        return self.mem()[1]

    def invoke(self, operation, data, abi_version=ABI_VERSION):
        n = len(data)
        p = self.raw("aprv_alloc", n)
        if p == 0:
            raise MemoryError(f"aprv_alloc({n}) failed")
        pu = p & 0xFFFFFFFF
        if n:
            base, size = self.mem()
            if pu + n > size:
                raise _Trap("input out of bounds")
            C.memmove(base + pu, data, n)
        try:
            h = self.raw("aprv_call", abi_version, operation, p, n)
        except _Trap:
            if abi_version != self.module_version:
                raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={abi_version}") from None
            raise
        rp = self.raw("aprv_result_ptr", h) & 0xFFFFFFFF
        rn = self.raw("aprv_result_len", h) & 0xFFFFFFFF
        base, size = self.mem()
        if rp + rn > size:
            raise _Trap("result out of bounds")
        out = C.string_at(base + rp, rn)
        self.raw("aprv_result_free", h)
        self.raw("aprv_dealloc", p, n)
        return out

    def close(self):
        if self.store:
            self.lib.wasm_extern_vec_delete(C.byref(self.exports))
            self.lib.wasm_instance_delete(self.inst)
            self.lib.wasm_store_delete(self.store)
            _envs.pop(self.env, None)
            self.store = None


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
        return dict(IMPORT_CALLS)

    def label(self):
        return f"python ctypes wasmi-c-api {os.environ.get('APRV_WASMI_MODE', 'lazy-translation')}"

    def close(self):
        for i in list(self.insts):
            self.drop(i)
