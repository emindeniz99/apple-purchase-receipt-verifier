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
    #: Not the client's fault, status 21009 at the endpoint. Raised when a
    #: trusted signer signed receipt content this library cannot read (found
    #: only after the chain and the signature passed; the parser's exception
    #: is the ``__cause__``), and reported by the endpoint for an unexpected
    #: exception inside it. Alert and retry or escalate; do not deny the user
    #: on it.
    INTERNAL_ERROR = "INTERNAL_ERROR"
    #: The verifyReceipt request envelope is unusable: the body is not a JSON
    #: object or nests deeper than 64, or ``receipt-data`` is missing, empty
    #: or not a string. Only ever a ``VerifyReceiptResult.failure_reason``;
    #: never raised.
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    #: The raw verifyReceipt request body is over
    #: ``VerifyReceiptEndpoint.MAX_REQUEST_BYTES`` (3,145,728 UTF-8 bytes),
    #: the size at which Apple's endpoint answers HTTP 413. Status 21002 in
    #: the response body; an HTTP layer can map it to 413 as Apple does. Only
    #: ever a ``VerifyReceiptResult.failure_reason``; never raised.
    REQUEST_TOO_LARGE = "REQUEST_TOO_LARGE"


class VerificationError(Exception):
    """Raised when a signed payload fails verification. ``reason`` is the
    machine-readable cause; a payload that raises must be treated as fully
    untrusted — there is no partial success."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(f"{reason}: {message}")
        self.reason = reason


ENVIRONMENTS = ("Production", "Sandbox", "Xcode", "LocalTesting")
