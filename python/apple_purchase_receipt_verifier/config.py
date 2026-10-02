"""What a :class:`~.verifier.Verifier` trusts and what time it thinks it is
(docs/design/0.7-api.md, "Setup")."""

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass


def _system_clock_ms() -> int:
    return int(time.time() * 1000)


def _der(root: object) -> bytes:
    if isinstance(root, (bytes, bytearray, memoryview)):
        return bytes(root)
    raise TypeError(
        "roots must be certificates as DER or PEM bytes; for a cryptography "
        "Certificate pass cert.public_bytes(serialization.Encoding.DER)"
    )


def _ordered_unique(roots: "Iterable[object]") -> "tuple[bytes, ...]":
    """``roots`` as DER bytes with later duplicates dropped, in first-seen
    order (the behaviour of Java's ``LinkedHashSet``), which the design's
    ``Config`` mirrors."""
    seen: dict[bytes, None] = {}
    for root in roots:
        seen.setdefault(_der(root), None)
    return tuple(seen)


@dataclass(frozen=True)
class Config:
    """Immutable. ``Config()`` is Apple's three pinned roots plus the system
    clock, the same as :meth:`defaults`.

    **Roots** are the pinned trust anchors every chain must reach, as
    DER-encoded certificates (``bytes``). ``None``, the default, means the
    three Apple roots compiled into the verification module; this package
    carries no copy of them. Tests substitute their own. An empty collection
    is accepted here and refused by :class:`~.verifier.Verifier`. The module
    parses the roots, so a value that is not a certificate is refused when the
    ``Verifier`` is built.

    **The clock** answers "what time is it now?", as a zero-argument
    callable returning epoch milliseconds (an ``int``), and nothing else. It
    is read once per call, before the input is looked at, and the module
    uses the value for one of two things: the chain-validity instant when a
    receipt or JWS states no signing date, and ``request_date`` in the
    endpoint response. It must be safe to call from several threads.

    :raises TypeError: if a root is not ``bytes``
    """

    roots: "tuple[bytes, ...] | None" = None
    clock: Callable[[], int] = _system_clock_ms

    def __post_init__(self) -> None:
        if self.roots is not None:
            object.__setattr__(self, "roots", _ordered_unique(self.roots))

    @staticmethod
    def defaults() -> "Config":
        """Apple's three pinned roots and the system clock. Equivalent to
        ``Config()``; spelled out for parity with the other ports."""
        return Config()

    @staticmethod
    def create(
        roots: "Iterable[bytes | bytearray | memoryview] | None" = None,
        clock: "Callable[[], int] | None" = None,
    ) -> "Config":
        """Builds a ``Config``, replacing only what is given; unset values
        take :meth:`defaults`."""
        return Config(
            roots=tuple(_der(r) for r in roots) if roots is not None else None,
            clock=clock if clock is not None else _system_clock_ms,
        )
