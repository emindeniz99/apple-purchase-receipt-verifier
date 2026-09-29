"""Helpers the test modules share: the fixtures, the WAT test double, and
the record of what the stand-in module is known to answer differently."""

import hashlib
import unittest
from collections.abc import Callable
from importlib import resources
from pathlib import Path
from typing import Any, TypeVar

import wasmtime
from apple_purchase_receipt_verifier import Config, Verifier, _host

TESTS = Path(__file__).resolve().parent
FIXTURES = TESTS.parents[1] / "fixtures"

#: SHA-256 of the stand-in module the package carries until the integrator
#: overwrites it with the release build: the canonical-ABI core module of
#: round 13 (docs/evidence/2026-09-29-canonical-abi-final), built on the 0.6
#: core. It answers 0.6's JSON (camelCase payloads, 0.6 reason names), so
#: some of what these tests expect of 0.7's wire shape cannot hold yet.
STANDIN_SHA256 = "da786ac853464e7b837c5483f9b04a27a3a5c2ff0340fa526f60482fd80fdb68"

MODULE_SHA256 = hashlib.sha256(
    resources.files("apple_purchase_receipt_verifier").joinpath("aprv.wasm").read_bytes()
).hexdigest()
IS_STANDIN = MODULE_SHA256 == STANDIN_SHA256


def _differences() -> "frozenset[str]":
    lines = (TESTS / "standin_differences.txt").read_text(encoding="utf-8").splitlines()
    return frozenset(line for line in lines if line and not line.startswith("#"))


#: Case ids of fixtures/cases.json that fail on the stand-in module.
STANDIN_DIFFERENCES = _differences()

F = TypeVar("F", bound=Callable[..., Any])


def standin_differs(test: F) -> F:
    """Marks a test that asserts 0.7 behaviour the stand-in module (0.6 core)
    cannot show. On the stand-in it must fail; on any other module it runs
    as an ordinary test. A marked test that passes on the stand-in is
    reported, so the marker cannot go stale."""
    return unittest.expectedFailure(test) if IS_STANDIN else test


def fixture(*segments: str) -> bytes:
    return FIXTURES.joinpath(*segments).read_bytes()


def fixture_text(*segments: str) -> str:
    return fixture(*segments).decode("ascii").strip()


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
