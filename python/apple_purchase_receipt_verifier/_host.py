"""Runs ``aprv.wasm`` on wasmtime-py. This is the whole host: it compiles the
module, hands it its one import, moves bytes in and out through the
canonical ABI, and pools instances. It parses nothing, verifies nothing and
decides nothing (docs/rust-core/ARCHITECTURE.md sections 4, 5 and 7.2).

The canonical ABI is called by hand over the core module's exports with
``Memory.write``, never through wasmtime-py's typed component API: that API
lowers a ``list<u8>`` one element at a time in Python, about 1.1 microseconds
per input byte.

One compiled module, one ``Linker`` and one ``Engine`` per process. The host
function is defined once on that ``Linker``: wasmtime-py 49.0.0 keeps Python
callbacks in a handle table that is not safe when handles are created and
freed from several threads, and a ``Linker`` defined once allocates its
handle at start and never frees it.
"""

import hashlib
import secrets
import struct
import threading
from collections.abc import Callable
from importlib import resources
from typing import TypeVar

import wasmtime

from . import _cache

#: The ABI version this host binds. Export names carry it, so a module built
#: for another version has no export this host finds.
ABI_VERSION = "1.0.0"
_VERIFY = f"aprv:verifier/verify@{ABI_VERSION}#"
_HOST_MODULE = f"aprv:verifier/host@{ABI_VERSION}"

_I32, _I64 = "i32", "i64"
#: Export name -> (WIT parameters lowered to core types, in order). Every
#: export answers one ``i32``, the address of its return area, and has a
#: ``cabi_post_`` twin taking that address.
_EXPORTS = {
    "init": (_I32, _I32),
    "verify-receipt": (_I64, _I32, _I32),
    "verify-signed-data": (_I64, _I32, _I32),
    "verify-receipt-endpoint": (_I32, _I64, _I32, _I32),
}
_REALLOC = ("cabi_realloc", (_I32,) * 4, (_I32,))

#: Linear memory a store may grow to, and instances per store (THREAT-MODEL
#: section 2).
MEMORY_LIMIT = 256 * 1024 * 1024
#: An instance whose memory grew past this after a call is dropped instead
#: of pooled, so one hostile input cannot leave every pooled instance large.
_RETIRE_ABOVE = 64 * 1024 * 1024
#: The most that ``random-get`` may be asked for; OpenSSL asks for a few
#: dozen bytes, so anything near this is a guest gone wrong.
_RANDOM_LIMIT = 1024 * 1024


T = TypeVar("T")


class AbiMismatchError(RuntimeError):
    """The module is not one this package can run: it lacks an export of ABI
    version 1.0.0, or imports anything but ``random-get``."""


class Fault(Exception):
    """A verification could not be carried out: an instance trapped, or
    answered something the host cannot read, or the clock failed. The
    instance involved is discarded; ``__cause__`` names what happened."""


def _read_pinned_module() -> bytes:
    """The bundled module, checked against the SHA-256 recorded beside it,
    so a corrupted or swapped file stops the import instead of running."""
    package = resources.files(__package__)
    wasm = package.joinpath("aprv.wasm").read_bytes()
    recorded = package.joinpath("aprv.wasm.sha256").read_text(encoding="ascii").split()
    if not recorded or hashlib.sha256(wasm).hexdigest() != recorded[0]:
        raise RuntimeError("the bundled aprv.wasm does not match its recorded SHA-256")
    return wasm


_WASM = _read_pinned_module()


def _describe(
    module: "wasmtime.Module",
) -> "tuple[dict[str, tuple[list[str], list[str]]], list[str]]":
    functions, other = {}, []
    for export in module.exports:
        kind = export.type
        if isinstance(kind, wasmtime.FuncType):
            functions[export.name] = ([str(t) for t in kind.params], [str(t) for t in kind.results])
        else:
            other.append(export.name)
    return functions, other


def _check_abi(module: "wasmtime.Module") -> None:
    """Refuses a module that is not ABI 1.0.0: any import but ``random-get``,
    or a missing export or one of the wrong shape."""
    imports = [(i.module, i.name) for i in module.imports]
    if imports != [(_HOST_MODULE, "random-get")]:
        raise AbiMismatchError(
            f"aprv.wasm imports {imports}; this package binds ABI {ABI_VERSION} and "
            f"allows only {_HOST_MODULE} random-get"
        )
    functions, other = _describe(module)
    wanted = {_REALLOC[0]: (list(_REALLOC[1]), list(_REALLOC[2]))}
    for name, params in _EXPORTS.items():
        wanted[_VERIFY + name] = (list(params), [_I32])
        wanted["cabi_post_" + _VERIFY + name] = ([_I32], [])
    problems = [n for n, shape in wanted.items() if functions.get(n) != shape]
    if "memory" not in other:
        problems.append("memory")
    if problems:
        raise AbiMismatchError(
            f"aprv.wasm does not export ABI {ABI_VERSION}: missing or wrong {problems}; "
            f"it exports {sorted(functions) + sorted(other)}"
        )


def _memory(extern: object) -> "wasmtime.Memory":
    if not isinstance(extern, wasmtime.Memory):
        raise wasmtime.WasmtimeError("the module's memory export is not a memory")
    return extern


def _function(extern: object) -> "wasmtime.Func":
    if not isinstance(extern, wasmtime.Func):
        raise wasmtime.WasmtimeError("an export of the module is not a function")
    return extern


def _random_get(caller: "wasmtime.Caller", length: int, retptr: int) -> None:
    """``random-get: func(len: u32) -> list<u8>``, lowered as ``(len, retptr)``:
    the bytes are allocated in guest memory with the guest's ``cabi_realloc``
    and the return area gets their address and length. Anything wrong raises,
    which traps the guest."""
    length &= 0xFFFFFFFF
    retptr &= 0xFFFFFFFF
    if length > _RANDOM_LIMIT:
        raise wasmtime.WasmtimeError("random-get asked for too many bytes")
    memory = _memory(caller["memory"])
    pointer = _function(caller["cabi_realloc"])(caller, 0, 0, 1, length) & 0xFFFFFFFF
    if length:
        memory.write(caller, bytearray(secrets.token_bytes(length)), pointer)
    memory.write(caller, bytearray(struct.pack("<II", pointer, length)), retptr)


class Runtime:
    """One compiled module and the ``Linker`` that supplies its import."""

    def __init__(self, wasm: bytes) -> None:
        try:
            config = wasmtime.Config()
            _cache.enable(config)
            self.engine = wasmtime.Engine(config)
            self.module = wasmtime.Module(self.engine, wasm)
        except wasmtime.WasmtimeError as error:
            raise RuntimeError("aprv.wasm could not be compiled") from error
        _check_abi(self.module)
        i32 = wasmtime.ValType.i32()
        self.linker = wasmtime.Linker(self.engine)
        self.linker.define_func(
            _HOST_MODULE,
            "random-get",
            wasmtime.FuncType([i32, i32], []),
            _random_get,
            access_caller=True,
        )


_default: "Runtime | None" = None
_default_lock = threading.Lock()


def default_runtime() -> Runtime:
    """The process-wide runtime for the bundled module; compiled on first
    use (about 1 s on 4 CPUs, 3 s on one, or a cache hit)."""
    global _default
    with _default_lock:
        if _default is None:
            _default = Runtime(_WASM)
        return _default


class Instance:
    """One instance of the module in its own store. One call at a time; the
    pool enforces that. After any :class:`Fault` it must be dropped."""

    __slots__ = ("_functions", "_memory", "_posts", "_realloc", "_store")

    def __init__(self, runtime: Runtime) -> None:
        try:
            store = wasmtime.Store(runtime.engine)
            store.set_limits(memory_size=MEMORY_LIMIT, instances=1)
            exports = runtime.linker.instantiate(store, runtime.module).exports(store)
            _function(exports["_initialize"])(store)
            self._store = store
            self._memory = _memory(exports["memory"])
            self._realloc = _function(exports[_REALLOC[0]])
            self._functions = {n: _function(exports[_VERIFY + n]) for n in _EXPORTS}
            self._posts = {n: _function(exports["cabi_post_" + _VERIFY + n]) for n in _EXPORTS}
        except Exception as error:  # a trap in _initialize, a refused instantiation
            raise Fault(
                f"the Wasm instance could not be created: {type(error).__name__}"
            ) from error

    def memory_size(self) -> int:
        return int(self._memory.data_len(self._store))

    def call(self, export: str, scalars: "tuple[int, ...]", data: bytes) -> str:
        """One canonical-ABI call. ``scalars`` are the WIT arguments before
        the ``list<u8>`` (``env``, ``now-ms``), ``data`` is the list. Returns
        the string the module answered. Nothing the guest hands back leaves
        this method as a pointer."""
        store, memory = self._store, self._memory
        try:
            length = len(data)
            pointer = self._realloc(store, 0, 0, 1, length) & 0xFFFFFFFF
            if length:
                if pointer + length > memory.data_len(store):
                    raise Fault("cabi_realloc returned a buffer outside memory")
                memory.write(store, bytearray(data), pointer)  # the guest owns the buffer
            area = self._functions[export](store, *scalars, pointer, length) & 0xFFFFFFFF
            size = memory.data_len(store)
            if area + 8 > size:
                raise Fault("the return area is outside memory")
            address, count = struct.unpack("<II", memory.read(store, area, area + 8))
            if address + count > size:
                raise Fault("the result is outside memory")
            answer = bytes(memory.read(store, address, address + count))
            self._posts[export](store, area)  # frees the result; called once, never twice
            return answer.decode("utf-8")
        except Fault:
            raise
        except Exception as error:  # a trap, a runtime error, undecodable text
            raise Fault(f"the Wasm instance failed: {type(error).__name__}") from error


class Pool:
    """A small pool of initialised instances of one module. Each instance
    runs ``init`` once, with the configuration's roots, when it is created;
    one call runs on one instance at a time; an instance that faulted, or
    grew large, is dropped and the next call makes another."""

    def __init__(
        self,
        runtime: Runtime,
        config_json: bytes,
        size: int,
        accepts: Callable[[str], bool],
    ) -> None:
        """``accepts(answer)`` says whether an ``init`` answer means the
        roots were taken; it is what a later instance must answer as the
        first did."""
        self._runtime = runtime
        self._config_json = config_json
        self._accepts = accepts
        self._free: list[Instance] = []
        self._lock = threading.Lock()
        self._slots = threading.BoundedSemaphore(size)
        # Made now, so an ABI mismatch or a root the module refuses fails
        # where the caller builds the Verifier. Returns the module's answer.
        first, self.init_answer = self._create()
        self._free.append(first)

    def _create(self) -> "tuple[Instance, str]":
        instance = Instance(self._runtime)
        return instance, instance.call("init", (), self._config_json)

    def run(
        self, export: str, scalars: "tuple[int, ...]", data: bytes, parse: Callable[[str], T]
    ) -> T:
        """``parse(answer)`` runs inside the borrowed instance, so an answer
        it cannot read drops that instance like a trap does."""
        self._slots.acquire()
        instance: Instance | None = None
        keep = False
        try:
            with self._lock:
                instance = self._free.pop() if self._free else None
            if instance is None:
                instance, answer = self._create()
                if not self._accepts(answer):
                    raise Fault("init refused a configuration it accepted before")
            answer = instance.call(export, scalars, data)
            try:
                result = parse(answer)
            except Exception as error:
                raise Fault("the answer of the Wasm module could not be read") from error
            keep = instance.memory_size() <= _RETIRE_ABOVE
            return result
        except Fault:
            raise
        except Exception as error:
            raise Fault(f"the Wasm instance failed: {type(error).__name__}") from error
        finally:
            if keep and instance is not None:
                with self._lock:
                    self._free.append(instance)
            self._slots.release()
