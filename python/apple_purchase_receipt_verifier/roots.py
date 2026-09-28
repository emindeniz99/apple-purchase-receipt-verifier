"""Loads the Apple root certificates bundled with this package (copies of
the public roots from https://www.apple.com/certificateauthority/), used by
both verification paths. Production trust anchors; tests substitute their
own.

The anchors are fingerprint-pinned: :func:`default_roots` checks each
bundled DER file's SHA-256 digest against the value below before it is
trusted, so a corrupted or substituted resource fails loudly instead of
silently becoming a fourth root. Apple deliberately documents the JWS chain
as ending in "an Apple root certificate" (not a specific one) and its
guidance is to trust every root on the PKI page, so anchoring on a single
root would break silently if Apple re-anchored a path.
"""

import hashlib
from pathlib import Path

from cryptography import x509

_CERTS = Path(__file__).parent / "certs"

#: Apple's published root fingerprints, compile-time constants copied from
#: the certificateauthority page, checked against the bundled resources
#: rather than trusted by virtue of shipping in this package.
_PINNED_SHA256 = {
    "AppleIncRootCertificate.cer": (
        "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024"
    ),
    "AppleRootCA-G2.cer": "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",
    "AppleRootCA-G3.cer": "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",
}


def _load(name: str, expected_sha256: str) -> x509.Certificate:
    try:
        der = (_CERTS / name).read_bytes()
    except OSError as e:
        raise RuntimeError(f"bundled Apple root {name} is missing") from e
    actual = hashlib.sha256(der).hexdigest()
    if actual != expected_sha256:
        raise RuntimeError(
            f"bundled Apple root {name} has SHA-256 {actual}, expected "
            f"{expected_sha256}: the pinned Apple roots have been replaced"
        )
    try:
        return x509.load_der_x509_certificate(der)
    except ValueError as e:
        raise RuntimeError(f"bundled Apple root {name} does not parse") from e


def default_roots() -> "tuple[x509.Certificate, ...]":
    """Apple's three pinned production roots, in a fixed order.

    :raises RuntimeError: if a bundled root is missing, does not parse, or
        does not match its pinned fingerprint
    """
    return tuple(_load(name, digest) for name, digest in _PINNED_SHA256.items())
