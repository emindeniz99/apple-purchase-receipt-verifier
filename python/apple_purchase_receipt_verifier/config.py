"""What a :class:`~.verifier.Verifier` trusts and what time it thinks it is
(docs/design/0.7-api.md, "Setup")."""

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from cryptography import x509

from .roots import default_roots


def _system_clock_ms() -> int:
    return int(time.time() * 1000)


def _ordered_unique(roots: "Iterable[x509.Certificate]") -> "tuple[x509.Certificate, ...]":
    """``roots`` with later duplicates dropped, in first-seen order — the
    behaviour of Java's ``LinkedHashSet``, which the design's ``Config``
    mirrors. Kept in the caller's order (not a hash order) so the roots
    that reach the chain builder are, object for object, the ones the
    caller passed."""
    seen: list[x509.Certificate] = []
    for root in roots:
        if root not in seen:
            seen.append(root)
    return tuple(seen)


@dataclass(frozen=True)
class Config:
    """Immutable. ``Config()`` is Apple's three pinned roots plus the system
    clock, the same as :meth:`defaults`.

    **Roots** are the pinned trust anchors every chain must reach; leaving
    them unset uses the three Apple roots bundled with this library, and
    tests substitute their own. An empty collection is accepted here and
    refused by :class:`~.verifier.Verifier`.

    **The clock** answers "what time is it now?", as a zero-argument
    callable returning epoch milliseconds, and nothing else. It is read at
    most once per call, and only for one of two things: the chain-validity
    instant when a receipt or JWS states no signing date, and
    ``request_date`` in the endpoint response. It must be safe to call from
    several threads.

    :raises RuntimeError: from the ``roots`` default factory if the bundled
        roots are missing, do not parse, or do not match their pinned
        fingerprints (only when no explicit ``roots`` is given)
    """

    roots: "tuple[x509.Certificate, ...]" = field(default_factory=default_roots)
    clock: Callable[[], int] = _system_clock_ms

    def __post_init__(self) -> None:
        object.__setattr__(self, "roots", _ordered_unique(self.roots))

    @staticmethod
    def defaults() -> "Config":
        """Apple's three pinned roots and the system clock. Equivalent to
        ``Config()``; spelled out for parity with the other ports."""
        return Config()

    @staticmethod
    def create(
        roots: "Iterable[x509.Certificate] | None" = None,
        clock: "Callable[[], int] | None" = None,
    ) -> "Config":
        """Builds a ``Config``, replacing only what is given; unset values
        take :meth:`defaults`."""
        return Config(
            roots=tuple(roots) if roots is not None else default_roots(),
            clock=clock if clock is not None else _system_clock_ms,
        )
