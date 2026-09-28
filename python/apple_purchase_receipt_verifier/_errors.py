"""Internal control-flow exception. Never reaches a caller: :mod:`verifier`
catches it at the boundary and turns it into a :class:`~.result.Failure`.

The message is log-safe by construction: anything quoted out of the input
goes through :mod:`_safe_text` before it is put here.
"""

from .reason import Reason


class VerificationError(Exception):
    """Raised internally when a check fails. ``reason`` is the
    :class:`~.reason.Reason`; the cause, when there is one, is set the usual
    way (``raise ... from cause``)."""

    def __init__(self, reason: Reason, message: str) -> None:
        super().__init__(message)
        self.reason = reason

    @property
    def message(self) -> str:
        return str(self)
