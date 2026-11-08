#!/usr/bin/env python3
"""The whole C ABI on one page, from Python, with nothing but the standard
library: a StoreKit 2 transaction verified against the fixture root that
signed it, the genuine sandbox receipt verified against the three bundled
Apple roots, and a verifier from init's JSON reporting what a host monitors
about revocation.

    cargo build --locked --release --manifest-path rust/ffi/Cargo.toml
    python3 rust/ffi/examples/python/example.py rust/target/release

The same two verifications examples/cpp/example.cpp and
examples/elixir/example.exs do, against the same three files, and the same
report examples/cpp/example.cpp prints. ctypes opens
the shared library at run time and calls the exported symbols by name, so
there is no compiler and no package in the loop; ../../tests/conformance.py
is the full harness built the same way.
"""

import ctypes
import json
import sys
from pathlib import Path

LIBRARY_NAMES = [
    "libapple_purchase_receipt_verifier_ffi.so",
    "libapple_purchase_receipt_verifier_ffi.dylib",
    "apple_purchase_receipt_verifier_ffi.dll",
]


class AprvResult(ctypes.Structure):
    # A void pointer, not c_char_p: ctypes would turn a c_char_p into bytes
    # and drop the pointer, and the pointer is what aprv_string_free needs.
    _fields_ = [("status", ctypes.c_int32), ("json", ctypes.c_void_p)]


def load(directory: Path) -> ctypes.CDLL:
    for name in LIBRARY_NAMES:
        if (directory / name).is_file():
            lib = ctypes.CDLL(str(directory / name))
            break
    else:
        raise SystemExit(f"no shared library in {directory}")
    u8p = ctypes.POINTER(ctypes.c_uint8)
    lib.aprv_version.restype = ctypes.c_char_p
    lib.aprv_verifier_new.argtypes = [
        ctypes.POINTER(u8p),
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int64),
    ]
    lib.aprv_verifier_new.restype = ctypes.c_void_p
    lib.aprv_verifier_new_config.argtypes = [
        ctypes.c_char_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_int64),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(AprvResult),
    ]
    lib.aprv_verifier_new_config.restype = ctypes.c_int32
    for name in ("aprv_verifier_revocation_urls", "aprv_verifier_revocation_valid_until_ms"):
        getattr(lib, name).argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
    for name in ("aprv_verify_receipt", "aprv_verify_signed_data"):
        getattr(lib, name).argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.POINTER(AprvResult),
        ]
    lib.aprv_verifier_free.argtypes = [ctypes.c_void_p]
    lib.aprv_string_free.argtypes = [ctypes.c_void_p]
    return lib


def show(lib: ctypes.CDLL, what: str, result: AprvResult) -> int:
    text = ctypes.cast(result.json, ctypes.c_char_p).value or b"{}"
    lib.aprv_string_free(result.json)  # every string the ABI hands out is freed
    print(f"{what}: status {result.status}")
    print(json.dumps(json.loads(text), indent=2), "\n")
    return 0 if result.status == 0 else 1


def reported(lib: ctypes.CDLL, getter, verifier) -> str:
    text = ctypes.c_void_p()
    getter(verifier, ctypes.byref(text))
    value = ctypes.cast(text, ctypes.c_char_p).value or b""
    lib.aprv_string_free(text)  # every string the ABI hands out is freed
    return value.decode()


def main(library_dir: str) -> int:
    lib = load(Path(library_dir))
    repository = Path(__file__).resolve().parents[4]
    generated = repository / "fixtures" / "generated"
    root = (generated / "jws-root.der").read_bytes()
    jws = (generated / "transaction.jws").read_bytes()
    receipt = (generated / "receipt-b64" / "01-genuine.txt").read_bytes()
    print("apple-purchase-receipt-verifier", lib.aprv_version().decode(), "\n")
    failures = 0

    root_buffer = (ctypes.c_uint8 * len(root)).from_buffer_copy(root)
    ders = (ctypes.POINTER(ctypes.c_uint8) * 1)(
        ctypes.cast(root_buffer, ctypes.POINTER(ctypes.c_uint8))
    )
    lens = (ctypes.c_size_t * 1)(len(root))
    # A verifier pinned to the fixture root, and one on the bundled Apple
    # roots. A NULL clock reads the system clock.
    fixture_verifier = lib.aprv_verifier_new(ders, lens, 1, None)
    transaction = AprvResult()
    lib.aprv_verify_signed_data(fixture_verifier, jws, ctypes.byref(transaction))
    failures += show(lib, "transaction", transaction)
    lib.aprv_verifier_free(fixture_verifier)

    apple_verifier = lib.aprv_verifier_new(None, None, 0, None)
    app_receipt = AprvResult()
    lib.aprv_verify_receipt(apple_verifier, receipt, ctypes.byref(app_receipt))
    failures += show(lib, "receipt", app_receipt)
    lib.aprv_verifier_free(apple_verifier)

    # Revocation settings arrive as the JSON aprv.wasm's init takes:
    # {"revocation_lists":[...],"revocation_issuers":[...],"distrust":[...]}.
    # `{}` is the bundled roots with no setting, which still reports Apple's lists.
    config = b"{}"
    configured = ctypes.c_void_p()
    refusal = AprvResult()
    status = lib.aprv_verifier_new_config(config, len(config), None, ctypes.byref(configured), ctypes.byref(refusal))
    if status != 0:
        show(lib, "configuration", refusal)
        return 1
    print("revocation urls:", reported(lib, lib.aprv_verifier_revocation_urls, configured))
    print("revocation valid until:", reported(lib, lib.aprv_verifier_revocation_valid_until_ms, configured))
    lib.aprv_verifier_free(configured)

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <directory holding the shared library>")
    sys.exit(main(sys.argv[1]))
