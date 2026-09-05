"""Shared harness for the fuzz targets: the anchors they verify against, the
assertions every target repeats, and the instrumentation seam.

Two things happen here that a target must not repeat.

First, the library is imported inside ``atheris.instrument_imports()``. That
block rewrites the bytecode of everything imported under it, so it has to be
the *first* thing that pulls in ``apple_purchase_receipt_verifier`` — and with
it ``asn1crypto``, the pure-Python ASN.1 library the receipt path parses CMS
with. Instrumenting asn1crypto is the point: without it the fuzzer gets no
coverage signal from the CMS/SET walk that reads attacker-shaped input, and
degrades to random mutation. ``cryptography`` is a compiled extension and
yields no Python coverage either way. So a target imports the names it needs
**from this module**, never from the package directly; an import that sorted
above ``harness`` would load the package uninstrumented.

Second, the fixtures are read from the repository's shared ``fixtures/``
directory rather than copied here, so a regenerated fixture reseeds the
fuzzer with nothing to keep in step. Nothing under ``fixtures/`` is written.
"""

import sys
from pathlib import Path
from typing import Any, Callable, Optional

import atheris

_FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def _fixture(*segments: str) -> bytes:
    return _FIXTURES.joinpath(*segments).read_bytes()


with atheris.instrument_imports():
    from apple_purchase_receipt_verifier import (
        JwsVerifier,
        ReceiptVerifier,
        VerificationError,
        VerifyReceiptEndpoint,
        apple_jws_roots,
        apple_receipt_roots,
        verify_receipt_core,
    )
    from apple_purchase_receipt_verifier.receipt import _parse_payload
    from cryptography import x509

#: The receipt anchor set: the pinned Apple roots plus the generated fixture
#: root, so both the shared fixture receipts and the two public Apple receipts
#: get past the chain check and the fuzzer can explore what lies beyond it.
#: Parsed once — re-reading the DER on every execution would cost more than
#: the code under test.
RECEIPT_ANCHORS = [
    *apple_receipt_roots(),
    x509.load_der_x509_certificate(_fixture("generated", "receipt-root.der")),
]

#: The unrelated anchor set the accept-invariant re-runs against: the fixture
#: *JWS* root, which certified nothing in the receipt world.
UNRELATED_ANCHORS = [x509.load_der_x509_certificate(_fixture("generated", "jws-root.der"))]

#: The bundle id the generated receipt fixtures carry.
BUNDLE_ID = "com.example.app"

#: ``ReceiptVerifier.verify`` on a string — the form a client actually sends.
RECEIPT_VERIFIER = ReceiptVerifier(RECEIPT_ANCHORS, BUNDLE_ID)

#: Anchored on the fixture JWS root, so the generated ``.jws`` fixtures verify.
JWS_VERIFIER = JwsVerifier(UNRELATED_ANCHORS, BUNDLE_ID, ["Sandbox"])

#: The same verifier anchored on Apple's production roots — the unrelated set
#: for the JWS accept-invariant.
APPLE_JWS_VERIFIER = JwsVerifier(apple_jws_roots(), BUNDLE_ID, ["Sandbox"])

#: One environment's worth of verifyReceipt emulation.
ENDPOINT = VerifyReceiptEndpoint(RECEIPT_ANCHORS, "Sandbox")

#: The hand-written receipt-attribute reader, re-exported under a name that
#: says what it is. It walks the payload SET, decodes UTF8String/IA5String
#: values and parses the RFC 3339 dates, all on bytes that have not been
#: authenticated yet — so it gets a target of its own rather than only being
#: reached through the CMS path.
parse_receipt_payload = _parse_payload

#: What a target may import. ``verify_receipt_core`` is re-exported rather
#: than imported directly by the targets for the reason in the module
#: docstring: the package must be loaded under the instrumentation block.
__all__ = [
    "APPLE_JWS_VERIFIER",
    "BUNDLE_ID",
    "ENDPOINT",
    "JWS_VERIFIER",
    "RECEIPT_ANCHORS",
    "RECEIPT_VERIFIER",
    "UNRELATED_ANCHORS",
    "InvariantViolation",
    "as_text",
    "parse_receipt_payload",
    "require_verification_error",
    "run",
    "verify_receipt_core",
]


class InvariantViolation(AssertionError):
    """A target's invariant did not hold. Raised rather than returned so
    libFuzzer records the input that broke it as a crasher."""


def require_verification_error(error: BaseException, what: str) -> None:
    """Every failure a caller can see must be the library's own
    :class:`VerificationError`.

    A ``TypeError``, an ``OverflowError`` or an ``asn1crypto`` internal error
    escaping means hostile input reached a call site that was not expecting
    it, which is the class of bug these targets exist to find — so it is
    reported, not tolerated.
    """
    if isinstance(error, VerificationError):
        return
    raise InvariantViolation(f"{what} escaped as {type(error).__name__}: {error}") from error


def as_text(data: bytes) -> Optional[str]:
    """The string an API taking ``str`` would actually receive, or ``None``
    when the bytes are not UTF-8.

    Decoding leniently would map every invalid byte onto U+FFFD and hide the
    input the fuzzer built, so those runs are skipped instead — the same rule
    the Rust and Node targets use.
    """
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        return None


def run(one_input: "Callable[[bytes], Any]") -> None:
    """Hands the target to libFuzzer. ``sys.argv`` carries the corpus
    directories and libFuzzer's own flags, which ``run.sh`` assembles."""
    atheris.Setup(sys.argv, one_input)
    atheris.Fuzz()
