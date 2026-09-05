"""Verify Apple in-app purchases locally (StoreKit 2 JWS + legacy PKCS#7
receipts) with zero Apple server calls. See the project PLAN.md for the
normative algorithms; this package mirrors the Java implementation."""

from .exceptions import ENVIRONMENTS, Reason, VerificationError
from .jws import JwsVerifier, is_transaction_active_at
from .receipt import AppReceipt, InAppPurchase, ReceiptVerifier, verify_receipt_core
from .roots import apple_jws_roots, apple_receipt_roots
from .verify_receipt_endpoint import VerifyReceiptEndpoint

__all__ = [
    "ENVIRONMENTS",
    "AppReceipt",
    "InAppPurchase",
    "JwsVerifier",
    "Reason",
    "ReceiptVerifier",
    "VerificationError",
    "VerifyReceiptEndpoint",
    "apple_jws_roots",
    "apple_receipt_roots",
    "is_transaction_active_at",
    "verify_receipt_core",
]
