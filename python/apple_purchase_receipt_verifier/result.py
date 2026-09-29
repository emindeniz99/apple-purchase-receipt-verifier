"""The outcome of one verification (docs/design/0.7-api.md, "Result")."""

from dataclasses import dataclass
from typing import Generic, TypeVar

from .reason import Reason

T = TypeVar("T")


@dataclass(frozen=True)
class Failure:
    """Why a verification failed. ``message`` is safe to log as is, never
    embeds raw input and is not meant to be parsed; its wording may change
    between releases. ``cause`` is the inner exception behind an
    :attr:`~.reason.Reason.INTERNAL_ERROR` raised by this package (a trap of
    the Wasm module, a clock that failed); ``None`` for every other reason,
    :attr:`~.reason.Reason.UNREADABLE_PAYLOAD` included: the module's message
    says what did not parse.
    """

    reason: Reason
    message: str
    cause: "BaseException | None" = None

    def __eq__(self, other: object) -> bool:
        # Equal when reason and message are; the cause is not compared, as
        # the Java port's Failure.equals does.
        if not isinstance(other, Failure):
            return NotImplemented
        return self.reason == other.reason and self.message == other.message

    def __hash__(self) -> int:
        return hash((self.reason, self.message))


@dataclass(frozen=True)
class VerificationResult(Generic[T]):
    """Either the verified payload or the :class:`Failure`, never both.

    Construct directly to mock a verifier in a test: ``VerificationResult
    (payload=my_payload)`` or ``VerificationResult(failure=my_failure)``.
    """

    payload: "T | None" = None
    failure: "Failure | None" = None

    def __post_init__(self) -> None:
        if (self.payload is None) == (self.failure is None):
            raise ValueError("exactly one of payload and failure must be set")

    @property
    def verified(self) -> bool:
        """Whether the input verified; exactly when :attr:`payload` is set."""
        return self.payload is not None
