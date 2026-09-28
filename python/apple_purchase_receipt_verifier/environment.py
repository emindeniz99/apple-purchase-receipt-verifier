"""Apple's two App Store environments, and the two verifyReceipt URLs
:func:`~.verifier.Verifier.verify_receipt_endpoint` imitates. The helpers
state what an Apple value means; whether to accept an environment is the
caller's decision."""

import enum


class Environment(enum.Enum):
    PRODUCTION = "Production"
    SANDBOX = "Sandbox"

    @staticmethod
    def from_receipt_type(receipt_type: "str | None") -> "Environment | None":
        """Maps a receipt's ``receipt_type`` (attribute 0): ``Production``
        and ``ProductionVPP`` to :attr:`PRODUCTION`, ``ProductionSandbox``
        and ``ProductionVPPSandbox`` to :attr:`SANDBOX`, anything else, a
        missing value included, to ``None``. The endpoint uses the same rule
        for status 21007 and 21008."""
        if receipt_type in ("Production", "ProductionVPP"):
            return Environment.PRODUCTION
        if receipt_type in ("ProductionSandbox", "ProductionVPPSandbox"):
            return Environment.SANDBOX
        return None

    @staticmethod
    def from_jws_environment(environment: "str | None") -> "Environment | None":
        """Maps a JWS ``environment`` claim: ``Production`` to
        :attr:`PRODUCTION`, ``Sandbox`` to :attr:`SANDBOX`, anything else
        (``Xcode``, ``LocalTesting``, a missing claim) to ``None``."""
        if environment == "Production":
            return Environment.PRODUCTION
        if environment == "Sandbox":
            return Environment.SANDBOX
        return None
