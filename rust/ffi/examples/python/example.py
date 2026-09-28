#!/usr/bin/env python3
"""The whole C ABI on one page, from Python, with nothing but the standard
library: a StoreKit 2 transaction verified against the fixture root that
signed it, and the genuine sandbox receipt verified against the three
bundled Apple roots.

    cargo build --locked --release --manifest-path rust/ffi/Cargo.toml
    python3 rust/ffi/examples/python/example.py rust/ffi/target/release

The same two verifications examples/cpp/example.cpp and
examples/elixir/example.exs do, against the same three files. ctypes opens
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

    return 0 if failures == 0 else 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit(f"usage: {sys.argv[0]} <directory holding the shared library>")
    sys.exit(main(sys.argv[1]))
