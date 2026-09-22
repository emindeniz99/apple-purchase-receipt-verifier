"""Verification failure model — same reason codes as the Java/Node
implementations (PLAN.md §3)."""


class Reason:
    INVALID_JWS_FORMAT = "INVALID_JWS_FORMAT"
    INVALID_CERTIFICATE = "INVALID_CERTIFICATE"
    INVALID_CERTIFICATE_PURPOSE = "INVALID_CERTIFICATE_PURPOSE"
    INVALID_CHAIN = "INVALID_CHAIN"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    WRONG_BUNDLE_ID = "WRONG_BUNDLE_ID"
    WRONG_ENVIRONMENT = "WRONG_ENVIRONMENT"
    WRONG_APP_APPLE_ID = "WRONG_APP_APPLE_ID"
    INVALID_RECEIPT_FORMAT = "INVALID_RECEIPT_FORMAT"
    DEVICE_HASH_MISMATCH = "DEVICE_HASH_MISMATCH"
    STALE_PAYLOAD = "STALE_PAYLOAD"
    #: The verifyReceipt request envelope is unusable: the body is not a JSON
    #: object, or ``receipt-data`` is missing, empty or not a string. Only
    #: ever a ``VerifyReceiptResult.failure_reason``; never raised.
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    #: An unexpected exception inside the verifyReceipt endpoint, answered as
    #: status 21009. Only ever a ``VerifyReceiptResult.failure_reason``;
    #: never raised.
    INTERNAL_ERROR = "INTERNAL_ERROR"


class VerificationError(Exception):
    """Raised when a signed payload fails verification. ``reason`` is the
    machine-readable cause; a payload that raises must be treated as fully
    untrusted — there is no partial success."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason


ENVIRONMENTS = ("Production", "Sandbox", "Xcode", "LocalTesting")
