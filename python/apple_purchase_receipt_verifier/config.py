"""What a :class:`~.verifier.Verifier` trusts, what it refuses, and what time
it thinks it is (docs/design/0.7-api.md, "Setup"; docs/design/revocation.md
section 4)."""

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import NamedTuple


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
    return tuple(dict.fromkeys(_der(root) for root in roots))


def _byte_strings(values: "Iterable[object]", name: str) -> "tuple[bytes, ...]":
    """``values`` as ``bytes``, in order, duplicates kept."""
    out = []
    for value in values:
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise TypeError(f"each of {name} must be bytes")
        out.append(bytes(value))
    return tuple(out)


class RevokedCertificate(NamedTuple):
    """A revocation key to refuse (docs/design/revocation.md section 2).

    ``issuer`` is the issuer id: 64 hex digits, the SHA-256 of the issuing
    certificate's subject Name followed by its subjectPublicKeyInfo, both as
    encoded in that certificate. ``serial`` is the revoked certificate's
    serial number in hex. Either letter case. The strings are kept as given;
    the module checks them when the :class:`~.verifier.Verifier` is built."""

    issuer: str
    serial: str


def _distrust(entries: "Iterable[object]") -> "tuple[RevokedCertificate, ...]":
    out = []
    for entry in entries:
        if not (
            isinstance(entry, tuple)
            and len(entry) == 2
            and isinstance(entry[0], str)
            and isinstance(entry[1], str)
        ):
            raise TypeError(
                "each distrust entry must be a RevokedCertificate(issuer, serial) "
                "or a tuple of two strings"
            )
        out.append(RevokedCertificate(entry[0], entry[1]))
    return tuple(out)


@dataclass(frozen=True, init=False)
class Config:
    """Immutable. ``Config()`` is Apple's three pinned roots plus the system
    clock, with no revocation setting beyond the list built into the module;
    pass keyword arguments to replace any of them, and leave out what stays
    the default.

    **Roots** are the pinned trust anchors every chain must reach, as
    DER-encoded certificates (``bytes``, ``bytearray`` or ``memoryview``),
    kept as ``bytes`` with later duplicates dropped. ``None``, the default,
    means the three Apple roots compiled into the verification module; this
    package carries no copy of them. Tests substitute their own. An empty
    collection is accepted here and refused by :class:`~.verifier.Verifier`.
    The module parses the roots, so a value that is not a certificate is
    refused when the ``Verifier`` is built.

    **The clock** answers "what time is it now?", as a zero-argument
    callable returning epoch milliseconds (an ``int``), and nothing else.
    ``None``, the default, is the system clock. It is read once per call,
    before the input is looked at, and the module uses the value for the
    chain-validity instant when a receipt or JWS states no signing date, for
    ``request_date`` in the endpoint response, and to judge whether a list
    holding a ``certificateHold`` entry is still fresh. It must be safe to
    call from several threads.

    **Revocation** (README, "Revocation"): ``revocation_lists`` are Apple's
    certificate revocation lists exactly as downloaded (DER bytes);
    ``revocation_issuers`` are CA certificates that sign lists, added to the
    built-in WWDR G5 and G6, in the same form as roots; ``distrust`` holds
    :class:`RevokedCertificate` entries (or tuples of two strings) to refuse
    whatever the lists say. Each is kept in order as a tuple, and each
    defaults to empty. The module judges them when the ``Verifier`` is
    built.

    :raises TypeError: if a root, list or issuer is not ``bytes``, or a
        distrust entry is not two strings
    """

    roots: "tuple[bytes, ...] | None"
    clock: Callable[[], int]
    revocation_lists: "tuple[bytes, ...]"
    revocation_issuers: "tuple[bytes, ...]"
    distrust: "tuple[RevokedCertificate, ...]"

    def __init__(
        self,
        roots: "Iterable[bytes | bytearray | memoryview] | None" = None,
        clock: "Callable[[], int] | None" = None,
        *,
        revocation_lists: "Iterable[bytes | bytearray | memoryview]" = (),
        revocation_issuers: "Iterable[bytes | bytearray | memoryview]" = (),
        distrust: "Iterable[RevokedCertificate | tuple[str, str]]" = (),
    ) -> None:
        object.__setattr__(self, "roots", None if roots is None else _ordered_unique(roots))
        object.__setattr__(self, "clock", _system_clock_ms if clock is None else clock)
        object.__setattr__(
            self, "revocation_lists", _byte_strings(revocation_lists, "revocation_lists")
        )
        object.__setattr__(
            self, "revocation_issuers", _byte_strings(revocation_issuers, "revocation_issuers")
        )
        object.__setattr__(self, "distrust", _distrust(distrust))
