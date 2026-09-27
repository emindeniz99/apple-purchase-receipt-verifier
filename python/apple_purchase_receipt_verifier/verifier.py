"""The public entry point (docs/design/0.7-api.md, "Setup")."""

from . import endpoint as _endpoint
from . import jws as _jws
from . import receipt as _receipt
from ._errors import VerificationError
from .config import Config
from .environment import Environment
from .reason import Reason
from .receipt_payload import JsonPayload, ReceiptPayload
from .result import Failure, VerificationResult


def _to_failure(e: VerificationError) -> Failure:
    # The cause is kept only where it explains Apple-signed content or a
    # library fault: behind any other reason it is a parser or provider
    # exception about unverified input, whose message could quote raw
    # certificate text a logged stack trace would print.
    keep_cause = e.reason in (Reason.UNREADABLE_PAYLOAD, Reason.INTERNAL_ERROR)
    cause = e.__cause__ if keep_cause and isinstance(e.__cause__, BaseException) else None
    return Failure(e.reason, str(e), cause)


def _internal_error(e: Exception) -> Failure:
    return Failure(Reason.INTERNAL_ERROR, f"unexpected {type(e).__name__}", e)


class Verifier:
    """Immutable, thread-safe once constructed. The verify methods never
    raise for any input: an unexpected exception is caught and reported as
    :attr:`~.reason.Reason.INTERNAL_ERROR`.

    :raises ValueError: if ``config.roots`` is empty: a verifier with no
        roots would answer ``UNTRUSTED_CHAIN`` to everything and nobody
        would notice until production
    """

    __slots__ = ("_clock", "_roots")

    def __init__(self, config: Config) -> None:
        if not config.roots:
            raise ValueError("config.roots must not be empty")
        self._roots = config.roots
        self._clock = config.clock

    def verify_receipt(self, base64: "str | None") -> VerificationResult[ReceiptPayload]:
        try:
            return VerificationResult(
                payload=_receipt.verify_receipt(base64, self._roots, self._clock)
            )
        except VerificationError as e:
            return VerificationResult(failure=_to_failure(e))
        except Exception as e:
            return VerificationResult(failure=_internal_error(e))

    def verify_signed_data(self, jws: "str | None") -> VerificationResult[JsonPayload]:
        try:
            return VerificationResult(
                payload=_jws.verify_signed_data(jws, self._roots, self._clock)
            )
        except VerificationError as e:
            return VerificationResult(failure=_to_failure(e))
        except Exception as e:
            return VerificationResult(failure=_internal_error(e))

    def verify_receipt_endpoint(self, environment: Environment, request_json: "str | None") -> str:
        if not isinstance(environment, Environment):
            raise TypeError("environment must be an Environment")
        return _endpoint.verify_receipt_endpoint(
            environment, request_json, self._roots, self._clock
        )
