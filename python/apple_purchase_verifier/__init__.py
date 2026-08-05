"""Verify Apple in-app purchases locally (StoreKit 2 JWS + legacy PKCS#7
receipts) with zero Apple server calls. See the project PLAN.md for the
normative algorithms; this package mirrors the Java implementation."""

from .exceptions import ENVIRONMENTS, Reason, VerificationError
from .jws import JwsVerifier
from .receipt import AppReceipt, InAppPurchase, ReceiptVerifier, verify_receipt_core
from .verify_receipt_endpoint import VerifyReceiptEndpoint
from .roots import apple_jws_roots, apple_receipt_roots

__all__ = [
    "ENVIRONMENTS",
    "Reason",
    "VerificationError",
    "JwsVerifier",
    "ReceiptVerifier",
    "VerifyReceiptEndpoint",
    "verify_receipt_core",
    "AppReceipt",
    "InAppPurchase",
    "apple_jws_roots",
    "apple_receipt_roots",
]
