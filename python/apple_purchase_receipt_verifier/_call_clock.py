"""The configured clock for one call (docs/design/0.7-api.md, "Setup").

Read at most once, and only when a verdict needs it, so the chain instant of
a dateless receipt and the endpoint's ``request_date`` are the same reading.
A clock that raises is the host's fault, not the input's: it surfaces as
``INTERNAL_ERROR``, a :class:`~._errors.VerificationError` that the guards
turning unexpected exceptions on unverified input into ``MALFORMED`` pass
through unchanged.
"""

from collections.abc import Callable

from ._errors import VerificationError
from .reason import Reason


class CallClock:
    """One instance per call; the cached reading is not shared."""

    __slots__ = ("_clock", "_millis")

    def __init__(self, clock: Callable[[], int]) -> None:
        self._clock = clock
        self._millis: int | None = None

    def __call__(self) -> int:
        if self._millis is None:
            try:
                self._millis = self._clock()
            except Exception as e:
                raise VerificationError(Reason.INTERNAL_ERROR, "the configured clock failed") from e
        return self._millis
