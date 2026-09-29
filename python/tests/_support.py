"""Helpers the test modules share: the fixtures and the WAT test double."""

import hashlib
import os
from collections.abc import Callable
from pathlib import Path

import wasmtime
from apple_purchase_receipt_verifier import Config, Verifier, _host

TESTS = Path(__file__).resolve().parent
FIXTURES = TESTS.parents[1] / "fixtures"
CERTS = TESTS.parents[1] / "certs"


def use_module_from_environment() -> bytes:
    """Test tooling, never the library: when ``APRV_WASM`` names a file, the
    process-wide runtime is built from it (through the internal loader, still
    checked against ``aprv.wasm.sha256``); otherwise from the bundled file. The
    package itself reads no such variable. Returns the module's bytes."""
    override = os.environ.get("APRV_WASM")
    if not override:
        return _host.read_pinned_module()
    wasm = _host.read_pinned_module(Path(override))
    _host._default = _host.Runtime(wasm)
    return wasm


WASM = use_module_from_environment()
MODULE_SHA256 = hashlib.sha256(WASM).hexdigest()


def fixture(*segments: str) -> bytes:
    return FIXTURES.joinpath(*segments).read_bytes()


def fixture_text(*segments: str) -> str:
    return fixture(*segments).decode("ascii").strip()


def apple_roots() -> "tuple[bytes, ...]":
    """Apple's three roots from the repository's ``certs/``, for a test that
    passes them explicitly. The package carries no copy: its defaults are the
    roots compiled into the module."""
    return tuple(path.read_bytes() for path in sorted(CERTS.glob("*.cer")))


_double: "_host.Runtime | None" = None


def double_runtime() -> "_host.Runtime":
    """The WAT test double (double.wat), compiled once per process."""
    global _double
    if _double is None:
        wat = (TESTS / "double.wat").read_text(encoding="utf-8")
        _double = _host.Runtime(bytes(wasmtime.wat2wasm(wat)))
    return _double


def double_verifier(
    clock: "Callable[[], int] | None" = None, roots: "tuple[bytes, ...]" = (b"\x30\x00",)
) -> Verifier:
    """A ``Verifier`` over the test double. Its roots only need to be bytes."""
    verifier = Verifier.__new__(Verifier)
    config = Config.create(roots=roots, clock=clock)
    verifier._setup(config, double_runtime)  # the seam the tests use
    return verifier
