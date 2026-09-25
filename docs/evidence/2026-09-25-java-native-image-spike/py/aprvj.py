"""ctypes binding for libapple_purchase_receipt_verifier_java.so (the spike's C ABI).

Only marshalling lives here: bytes in, (code, json text) out, every returned
string freed exactly once with aprvj_string_free.
"""

from __future__ import annotations

import ctypes
import threading

c_void_pp = ctypes.POINTER(ctypes.c_void_p)


class Library:
    def __init__(self, path: str):
        lib = ctypes.CDLL(path)
        vp = ctypes.c_void_p
        lib.aprvj_runtime_new.argtypes = []
        lib.aprvj_runtime_new.restype = vp
        lib.aprvj_runtime_isolate.argtypes = [vp]
        lib.aprvj_runtime_isolate.restype = vp
        lib.aprvj_thread_attach.argtypes = [vp]
        lib.aprvj_thread_attach.restype = vp
        lib.aprvj_thread_detach.argtypes = [vp]
        lib.aprvj_thread_detach.restype = ctypes.c_int
        lib.aprvj_runtime_free.argtypes = [vp]
        lib.aprvj_runtime_free.restype = ctypes.c_int
        for name in ("aprvj_receipt_verifier_new", "aprvj_jws_verifier_new", "aprvj_endpoint_new"):
            f = getattr(lib, name)
            f.argtypes = [vp, ctypes.c_char_p, c_void_pp]
            f.restype = vp
        lib.aprvj_handle_free.argtypes = [vp, vp]
        lib.aprvj_handle_free.restype = None
        lib.aprvj_verify_receipt.argtypes = [vp, vp, vp, ctypes.c_size_t, ctypes.c_int, vp, ctypes.c_size_t, c_void_pp]
        lib.aprvj_verify_receipt.restype = ctypes.c_int
        lib.aprvj_verify_jws.argtypes = [vp, vp, vp, ctypes.c_size_t, ctypes.c_int, c_void_pp]
        lib.aprvj_verify_jws.restype = ctypes.c_int
        lib.aprvj_verify_receipt_json.argtypes = [vp, vp, vp, ctypes.c_size_t, c_void_pp]
        lib.aprvj_verify_receipt_json.restype = ctypes.c_int
        lib.aprvj_self_check.argtypes = [vp, c_void_pp]
        lib.aprvj_self_check.restype = ctypes.c_int
        lib.aprvj_string_free.argtypes = [vp, vp]
        lib.aprvj_string_free.restype = None
        self.lib = lib
        self.thread = lib.aprvj_runtime_new()
        if not self.thread:
            raise RuntimeError("aprvj_runtime_new failed")
        self.isolate = lib.aprvj_runtime_isolate(self.thread)
        self._local = threading.local()
        self._local.thread = self.thread
        self._main = threading.get_ident()

    # Each OS thread uses its own isolate thread; the creating thread already has one.
    def attach(self):
        if getattr(self._local, "thread", None) is None:
            self._local.thread = self.lib.aprvj_thread_attach(self.isolate)
            if not self._local.thread:
                raise RuntimeError("aprvj_thread_attach failed")
        return self._local.thread

    def detach(self):
        t = getattr(self._local, "thread", None)
        if t is not None and threading.get_ident() != self._main:
            self.lib.aprvj_thread_detach(t)
            self._local.thread = None

    def close(self):
        rc = self.lib.aprvj_runtime_free(self.thread)
        self.thread = None
        return rc

    def take(self, pointer) -> str | None:
        if not pointer:
            return None
        text = ctypes.cast(pointer, ctypes.c_char_p).value
        self.lib.aprvj_string_free(self.attach(), pointer)
        return text.decode("utf-8")

    def new(self, kind: str, options: str):
        err = ctypes.c_void_p()
        f = {"receipt": self.lib.aprvj_receipt_verifier_new,
             "jws": self.lib.aprvj_jws_verifier_new,
             "endpoint": self.lib.aprvj_endpoint_new}[kind]
        handle = f(self.attach(), options.encode("utf-8"), ctypes.byref(err))
        return handle, self.take(err.value)

    def free(self, handle):
        self.lib.aprvj_handle_free(self.attach(), handle)

    def receipt(self, handle, data: bytes, base64: bool, guid: bytes | None):
        out = ctypes.c_void_p()
        buf = ctypes.create_string_buffer(data, len(data)) if data else None
        gbuf = ctypes.create_string_buffer(guid, len(guid)) if guid is not None else None
        code = self.lib.aprvj_verify_receipt(
            self.attach(), handle, buf, len(data), 1 if base64 else 0,
            gbuf if guid is not None else None, len(guid) if guid is not None else 0, ctypes.byref(out))
        return code, self.take(out.value)

    def jws(self, handle, data: bytes, op: int):
        out = ctypes.c_void_p()
        buf = ctypes.create_string_buffer(data, len(data)) if data else ctypes.create_string_buffer(1)
        code = self.lib.aprvj_verify_jws(self.attach(), handle, buf, len(data), op, ctypes.byref(out))
        return code, self.take(out.value)

    def endpoint(self, handle, data: bytes):
        out = ctypes.c_void_p()
        buf = ctypes.create_string_buffer(data, len(data)) if data else ctypes.create_string_buffer(1)
        code = self.lib.aprvj_verify_receipt_json(self.attach(), handle, buf, len(data), ctypes.byref(out))
        return code, self.take(out.value)

    def self_check(self):
        out = ctypes.c_void_p()
        code = self.lib.aprvj_self_check(self.attach(), ctypes.byref(out))
        return code, self.take(out.value)
