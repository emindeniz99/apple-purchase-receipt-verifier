"""Spike only (2026-09-27, round 9): a minimal, APRV-specific ctypes facade
over WAMR's libiwasm.so (wasm_export.h), for aprv.wasm (ABI v1). It is not
a general WAMR binding: it registers exactly aprv.clock_now_ms and
aprv.random_get, and runs the ABI v1 call lifecycle.

    import aprv_wamr
    v = aprv_wamr.Verifier()               # one per thread; never shared
    v.verify_receipt(receipt_data)         # -> dict
    v.verify_signed_data(jws)              # -> dict
    v.verify_receipt_endpoint("Sandbox", body)  # -> str

Configuration (environment, read once per process):
  APRV_LIBIWASM   path to the libiwasm.so to load (one build per WAMR execution mode)
  APRV_MODULE     path to aprv.wasm
  APRV_RUNNING_MODE  optional: interp | fast-jit | llvm-jit | multi-tier

Errors, as in round 7's wasmtime-py facade: a verification failure is a
value; AbiMismatchError for another ABI version; WasmTrapError when the
instance trapped (the Verifier discards it and starts a fresh one).

Threading: WAMR needs wasm_runtime_init_thread_env() on every thread that
calls into Wasm other than the one that initialised the runtime; this
spike calls from one thread only.
"""
import ctypes as C
import json
import os
import threading
import time

__all__ = ["Verifier", "AbiMismatchError", "WasmTrapError", "ABI_VERSION", "OP", "LOAD_INFO", "IMPORT_CALLS"]

ABI_VERSION = 1
OP = {"VERIFY_RECEIPT": 1, "VERIFY_SIGNED_DATA": 2, "ENDPOINT_PRODUCTION": 3, "ENDPOINT_SANDBOX": 4}
_ENDPOINT = {"Production": 3, "Sandbox": 4}
IMPORT_CALLS = {"aprv.clock_now_ms": 0, "aprv.random_get": 0}
LOAD_INFO = {}
_STACK = 1024 * 1024  # exec env (Wasm operand) stack, as in ../wamr-host/host.c


class AbiMismatchError(RuntimeError):
    """The module and this facade disagree on the ABI version."""


class WasmTrapError(RuntimeError):
    """The instance trapped: an internal failure, not a verdict."""


class _Trap(Exception):
    pass


# ---- wasm_export.h layouts (x86-64; checked against sizeof in C: 232, 32, 16) ----
class _MemAllocOption(C.Union):
    _fields_ = [("pool", C.c_void_p * 2), ("allocator", C.c_void_p * 4)]


class _RuntimeInitArgs(C.Structure):
    _fields_ = [
        ("mem_alloc_type", C.c_int), ("mem_alloc_option", _MemAllocOption),
        ("native_module_name", C.c_char_p), ("native_symbols", C.c_void_p), ("n_native_symbols", C.c_uint32),
        ("max_thread_num", C.c_uint32), ("ip_addr", C.c_char * 128), ("unused", C.c_int), ("instance_port", C.c_int),
        ("fast_jit_code_cache_size", C.c_uint32), ("gc_heap_size", C.c_uint32), ("running_mode", C.c_int),
        ("llvm_jit_opt_level", C.c_uint32), ("llvm_jit_size_level", C.c_uint32), ("segue_flags", C.c_uint32),
        ("enable_linux_perf", C.c_bool),
    ]


class _NativeSymbol(C.Structure):
    _fields_ = [("symbol", C.c_char_p), ("func_ptr", C.c_void_p), ("signature", C.c_char_p), ("attachment", C.c_void_p)]


class _Val(C.Structure):
    _fields_ = [("kind", C.c_uint8), ("_pad", C.c_uint8 * 7), ("i32", C.c_int32), ("_hi", C.c_int32)]


assert C.sizeof(_RuntimeInitArgs) == 232 and C.sizeof(_NativeSymbol) == 32 and C.sizeof(_Val) == 16
_ALLOC_WITH_SYSTEM_ALLOCATOR = 2
_MODES = {"interp": 1, "fast-jit": 2, "llvm-jit": 3, "multi-tier": 4}
_MODE_NAMES = {v: k for k, v in _MODES.items()}

_lib = None
_module = None
_module_buf = None  # WAMR keeps pointers into the buffer until unload
_callbacks = []
_lock = threading.Lock()


def _clock_now_ms(_env):
    IMPORT_CALLS["aprv.clock_now_ms"] += 1
    return float(time.time_ns() // 1_000_000)


def _random_get(env, ptr, length):
    IMPORT_CALLS["aprv.random_get"] += 1
    inst = _lib.wasm_runtime_get_module_inst(env)
    if ptr < 0 or length < 0 or not _lib.wasm_runtime_validate_app_addr(inst, ptr & 0xFFFFFFFF, length & 0xFFFFFFFF):
        _lib.wasm_runtime_set_exception(inst, b"aprv.random_get out of bounds")
        return 0
    if length:
        C.memmove(_lib.wasm_runtime_addr_app_to_native(inst, ptr), os.urandom(length), length)
    return 0


def _bind(lib):
    P, U32, U64, B = C.c_void_p, C.c_uint32, C.c_uint64, C.c_bool
    sig = {
        "wasm_runtime_full_init": ([C.POINTER(_RuntimeInitArgs)], B),
        "wasm_runtime_is_running_mode_supported": ([C.c_int], B),
        "wasm_runtime_load": ([P, U32, C.c_char_p, U32], P),
        "wasm_runtime_instantiate": ([P, U32, U32, C.c_char_p, U32], P),
        "wasm_runtime_deinstantiate": ([P], None),
        "wasm_runtime_create_exec_env": ([P, U32], P),
        "wasm_runtime_destroy_exec_env": ([P], None),
        "wasm_runtime_lookup_function": ([P, C.c_char_p], P),
        "wasm_runtime_call_wasm_a": ([P, P, U32, C.POINTER(_Val), U32, C.POINTER(_Val)], B),
        "wasm_runtime_get_exception": ([P], C.c_char_p),
        "wasm_runtime_clear_exception": ([P], None),
        "wasm_runtime_set_exception": ([P, C.c_char_p], None),
        "wasm_runtime_get_module_inst": ([P], P),
        "wasm_runtime_validate_app_addr": ([P, U64, U64], B),
        "wasm_runtime_addr_app_to_native": ([P, U64], P),
        "wasm_runtime_get_default_memory": ([P], P),
        "wasm_memory_get_cur_page_count": ([P], U64),
        "wasm_memory_get_bytes_per_page": ([P], U64),
        "wasm_memory_get_base_address": ([P], P),
        "wasm_runtime_get_running_mode": ([P], C.c_int),
        "wasm_func_get_result_count": ([P, P], U32),
    }
    for name, (args, res) in sig.items():
        f = getattr(lib, name)
        f.argtypes, f.restype = args, res


def _runtime():
    """(lib, module), created once per process."""
    global _lib, _module, _module_buf
    with _lock:
        if _module is None:
            t0 = time.perf_counter()
            lib = C.CDLL(os.environ["APRV_LIBIWASM"])
            _bind(lib)
            _lib = lib
            clock_t = C.CFUNCTYPE(C.c_double, C.c_void_p)(_clock_now_ms)
            random_t = C.CFUNCTYPE(C.c_int32, C.c_void_p, C.c_int32, C.c_int32)(_random_get)
            _callbacks.extend([clock_t, random_t])
            natives = (_NativeSymbol * 2)(
                _NativeSymbol(b"clock_now_ms", C.cast(clock_t, C.c_void_p), b"()F", None),
                _NativeSymbol(b"random_get", C.cast(random_t, C.c_void_p), b"(ii)i", None))
            _callbacks.append(natives)  # WAMR keeps the symbol table
            args = _RuntimeInitArgs()
            args.mem_alloc_type = _ALLOC_WITH_SYSTEM_ALLOCATOR
            args.native_module_name = b"aprv"
            args.native_symbols = C.cast(natives, C.c_void_p)
            args.n_native_symbols = 2
            args.llvm_jit_opt_level = 3  # iwasm's defaults
            args.llvm_jit_size_level = 3
            mode = os.environ.get("APRV_RUNNING_MODE")
            if mode:
                args.running_mode = _MODES[mode]
                if not lib.wasm_runtime_is_running_mode_supported(args.running_mode):
                    raise RuntimeError(f"running mode {mode} not supported by this libiwasm")
            _callbacks.append(args)
            if not lib.wasm_runtime_full_init(C.byref(args)):
                raise RuntimeError("wasm_runtime_full_init failed")
            t1 = time.perf_counter()
            data = open(os.environ["APRV_MODULE"], "rb").read()
            _module_buf = C.create_string_buffer(data, len(data))
            err = C.create_string_buffer(256)
            _module = lib.wasm_runtime_load(_module_buf, len(data), err, 256)
            if not _module:
                raise RuntimeError(f"wasm_runtime_load: {err.value.decode()}")
            t2 = time.perf_counter()
            LOAD_INFO.update(init_ms=round((t1 - t0) * 1000, 3), load_ms=round((t2 - t1) * 1000, 3))
        return _lib, _module


class _Instance:
    def __init__(self):
        lib, module = _runtime()
        self.lib = lib
        err = C.create_string_buffer(256)
        self.inst = lib.wasm_runtime_instantiate(module, _STACK, 0, err, 256)
        if not self.inst:
            raise RuntimeError(f"instantiate: {err.value.decode()}")
        self.env = lib.wasm_runtime_create_exec_env(self.inst, _STACK)
        self.f = {n: lib.wasm_runtime_lookup_function(self.inst, n.encode()) for n in (
            "_initialize", "aprv_abi_version", "aprv_alloc", "aprv_dealloc", "aprv_call",
            "aprv_result_ptr", "aprv_result_len", "aprv_result_free")}
        if not all(self.f.values()):
            raise AbiMismatchError("missing export")
        self._args = (_Val * 4)()
        self._res = (_Val * 1)()
        self.raw("_initialize")
        self.module_version = self.raw("aprv_abi_version")
        if self.module_version != ABI_VERSION:
            raise AbiMismatchError(f"APRV Wasm ABI mismatch: module={self.module_version}, caller={ABI_VERSION}")

    @property
    def running_mode(self):
        return _MODE_NAMES.get(self.lib.wasm_runtime_get_running_mode(self.inst), "default")

    def raw(self, name, *args):
        """Calls an export with i32 arguments; returns its i32 result or None."""
        f = self.f.get(name) or self.lib.wasm_runtime_lookup_function(self.inst, name.encode())
        if not f:
            raise RuntimeError(f"no export {name}")
        a = self._args
        for i, v in enumerate(args):
            a[i].kind, a[i].i32 = 0, v
        nres = self.lib.wasm_func_get_result_count(f, self.inst)
        if not self.lib.wasm_runtime_call_wasm_a(self.env, f, nres, self._res, len(args), a):
            msg = (self.lib.wasm_runtime_get_exception(self.inst) or b"unknown failure").decode("utf-8", "replace")
            self.lib.wasm_runtime_clear_exception(self.inst)
            raise _Trap(msg)
        return self._res[0].i32 if nres else None

    def mem(self):
        m = self.lib.wasm_runtime_get_default_memory(self.inst)
        return self.lib.wasm_memory_get_base_address(m), self.lib.wasm_memory_get_cur_page_count(m) * self.lib.wasm_memory_get_bytes_per_page(m)

    def invoke(self, operation, data, abi_version=ABI_VERSION):
        n = len(data)
        p = self.raw("aprv_alloc", n)
        if p == 0:
            raise MemoryError(f"aprv_alloc({n}) failed")
        if n:
            base, size = self.mem()
            if (p & 0xFFFFFFFF) + n > size:
                raise _Trap("input out of bounds")
            C.memmove(base + (p & 0xFFFFFFFF), data, n)
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
        out = C.string_at(base + rp, rn)  # a copy owned by Python
        self.raw("aprv_result_free", h)
        self.raw("aprv_dealloc", p, n)
        return out

    def close(self):
        if self.env:
            self.lib.wasm_runtime_destroy_exec_env(self.env)
            self.lib.wasm_runtime_deinstantiate(self.inst)
            self.env = self.inst = None


class Verifier:
    """One WAMR module instance. Use from one thread at a time."""

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

    @staticmethod
    def _text(value):
        return value.encode("utf-8") if isinstance(value, str) else bytes(value)

    def verify_receipt(self, receipt_data):
        return json.loads(self.call(OP["VERIFY_RECEIPT"], self._text(receipt_data)))

    def verify_signed_data(self, jws):
        return json.loads(self.call(OP["VERIFY_SIGNED_DATA"], self._text(jws)))

    def verify_receipt_endpoint(self, environment, body):
        return self.call(_ENDPOINT[environment], self._text(body)).decode("utf-8")


class InProcHost:
    """The driver protocol's operations, in process (py/driver.py uses it for
    the facade's ABI tests and corpus parity)."""

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
        return self.insts[i].mem()[1]

    def import_calls(self):
        return dict(IMPORT_CALLS)

    def label(self):
        return f"python-ctypes-wamr {os.path.basename(os.path.dirname(os.environ['APRV_LIBIWASM']))}"

    def close(self):
        for i in list(self.insts):
            self.drop(i)

