"""Smoke-tests the package as published to PyPI, imported by name from a
directory that is not the repository.

    python3 -m venv venv && venv/bin/pip install apple-purchase-receipt-verifier==0.7.0
    cp <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
    venv/bin/python <repo>/.github/smoke/pypi-smoke.py

Imports come from the installed distribution, so a wheel missing a module or
the bundled certs fails here rather than in a user's project.
"""

import base64

from apple_purchase_receipt_verifier import Config, Reason, Verifier

with open("receipt-sandbox-g5.b64", encoding="ascii") as handle:
    receipt_b64 = handle.read().strip()

# Apple's three roots are compiled into aprv.wasm, so the defaults name none
# of their own (None means the module's); a wheel that lost the module fails
# below, on the genuine receipt.
config = Config()
if config.roots is not None:
    raise SystemExit(f"expected the module's built-in roots (None), got {len(config.roots)}")
verifier = Verifier(config)

# A real Apple-signed receipt against the real pinned root: exercises the
# packaged module, the chain build and the signature check inside it.
result = verifier.verify_receipt(receipt_b64)
if not result.verified:
    raise SystemExit(f"verification failed: {result.failure.reason}: {result.failure.message}")
receipt = result.payload
if receipt.receipt_type != "ProductionSandbox":
    raise SystemExit(f"receipt_type was {receipt.receipt_type}, expected ProductionSandbox")
if receipt.bundle_id != "dev.bonzer.weeka.app":
    raise SystemExit(f"bundle_id was {receipt.bundle_id}")

# And the negative direction, so a verifier that accepted everything would fail
# here too: the same receipt with one bit flipped in its signature, the byte
# 128 from the end of the DER (BENCHMARKS.md).
der = bytearray(base64.b64decode(receipt_b64))
der[-128] ^= 0x01
tampered = verifier.verify_receipt(base64.b64encode(bytes(der)).decode("ascii"))
if tampered.verified or tampered.failure.reason != Reason.INVALID_SIGNATURE:
    outcome = "verified" if tampered.verified else tampered.failure.reason
    raise SystemExit(f"a tampered signature was not rejected as INVALID_SIGNATURE: {outcome}")

print(
    f"pypi: published package verified a genuine Apple receipt ({receipt.bundle_id}, "
    f"{len(receipt.in_app)} purchases) and rejected a tampered signature"
)
