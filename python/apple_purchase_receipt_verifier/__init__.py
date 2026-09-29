"""Verify Apple in-app purchases locally (StoreKit 2 JWS + legacy PKCS#7
receipts) with zero Apple server calls. docs/design/0.7-api.md is the
normative spec this package mirrors."""

from . import apple_status
from .config import Config
from .environment import Environment
from .reason import Reason
from .receipt_payload import InAppPurchase, JsonPayload, ReceiptPayload
from .result import Failure, VerificationResult
from .verifier import Verifier
from .version import CURRENT as VERSION

__all__ = [
    "VERSION",
    "Config",
    "Environment",
    "Failure",
    "InAppPurchase",
    "JsonPayload",
    "Reason",
    "ReceiptPayload",
    "VerificationResult",
    "Verifier",
    "apple_status",
]
