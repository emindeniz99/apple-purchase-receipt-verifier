"""Smoke-tests the package as published to PyPI, imported by name from a
directory that is not the repository.

    python3 -m venv venv && venv/bin/pip install apple-purchase-receipt-verifier==0.2.1
    cp <repo>/fixtures/public-receipts/receipt-sandbox-g5.b64 .
    venv/bin/python <repo>/.github/smoke/pypi-smoke.py

Imports come from the installed distribution, so a wheel missing a module or
the bundled certs fails here rather than in a user's project.
"""

from apple_purchase_receipt_verifier import ReceiptVerifier, VerificationError
from apple_purchase_receipt_verifier.exceptions import Reason
from apple_purchase_receipt_verifier.roots import apple_receipt_roots

with open("receipt-sandbox-g5.b64", encoding="ascii") as handle:
    receipt_b64 = handle.read().strip()

# A real Apple-signed receipt against the real pinned root: exercises the
# packaged certs, the DER reader, the chain build and the signature check.
receipt = ReceiptVerifier(apple_receipt_roots(), "dev.bonzer.weeka.app").verify(receipt_b64)
if receipt.receipt_type != "ProductionSandbox":
    raise SystemExit(f"receipt_type was {receipt.receipt_type}, expected ProductionSandbox")
if receipt.bundle_id != "dev.bonzer.weeka.app":
    raise SystemExit(f"bundle_id was {receipt.bundle_id}")

# And the negative direction, so a verifier that accepted everything would fail
# here too.
try:
    ReceiptVerifier(apple_receipt_roots(), "com.other.app").verify(receipt_b64)
except VerificationError as error:
    if error.reason != Reason.WRONG_BUNDLE_ID:
        raise SystemExit(f"unexpected reason {error.reason}") from error
else:
    raise SystemExit("a receipt for another bundle id was not rejected")

print(
    f"pypi: published package verified a genuine Apple receipt ({receipt.bundle_id}, "
    f"{len(receipt.in_app_purchases)} purchases) and rejected a foreign bundle id"
)
