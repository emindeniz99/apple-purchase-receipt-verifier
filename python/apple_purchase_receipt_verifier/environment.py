"""Apple's two App Store environments: the two verifyReceipt URLs
:func:`~.verifier.Verifier.verify_receipt_endpoint` imitates, and the
environment a verified payload names (:attr:`.ReceiptPayload.environment`,
:attr:`.JsonPayload.environment`), as the module states it. Whether to
accept an environment is the caller's decision."""

import enum


class Environment(enum.Enum):
    PRODUCTION = "Production"
    SANDBOX = "Sandbox"
