"""Certificate chain validation against pinned trust anchors.

Hand-rolled because ``cryptography``'s verification API is TLS-oriented;
these are the PKIX-equivalent checks the Java implementation gets from
``CertPathValidator``: signature + name chaining at each step, validity
windows at signing time, and CA basic constraints on intermediates.
Anchors are trusted by fiat (their own expiry is not checked).
"""

from collections.abc import Sequence
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .exceptions import Reason, VerificationError

_MAX_PATH_LENGTH = 6


def _not_valid_before(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_before_utc  # cryptography >= 42
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def _not_valid_after(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _valid_at(cert: x509.Certificate, at: datetime) -> bool:
    return _not_valid_before(cert) <= at <= _not_valid_after(cert)


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (TypeError, InvalidSignature):
        return False
    except ValueError as e:
        if "Unsupported signature algorithm" not in str(e):
            return False
    # cryptography's helper refuses SHA-1 signature algorithms, but genuine
    # Apple legacy receipt chains are SHA-1 end-to-end; verify manually,
    # matching the Java (PKIX), Node and Swift implementations.
    if cert.issuer != issuer.subject:
        return False
    public_key = issuer.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    signature_hash = cert.signature_hash_algorithm
    if signature_hash is None:
        # No recognised signature hash (an EdDSA signature, or an OID
        # cryptography does not map). There is nothing to verify against, so
        # fail closed. Previously this reached verify() and came back as the
        # TypeError caught below — same verdict, now stated explicitly.
        return False
    try:
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            signature_hash,
        )
        return True
    except (InvalidSignature, TypeError, ValueError, UnsupportedAlgorithm):
        return False


def as_utc(millis: float) -> datetime:
    return datetime.fromtimestamp(millis / 1000.0, tz=timezone.utc)


def validate_pair(
    leaf: x509.Certificate,
    intermediate: x509.Certificate,
    anchors: Sequence[x509.Certificate],
    at: datetime,
) -> None:
    """Validates the fixed JWS path leaf → intermediate → (pinned anchor)."""
    if not _valid_at(leaf, at) or not _valid_at(intermediate, at):
        raise VerificationError(Reason.INVALID_CHAIN, "certificate not valid at signing time")
    if not _is_ca(intermediate):
        raise VerificationError(Reason.INVALID_CHAIN, "intermediate is not a CA")
    if not _issued_by(leaf, intermediate):
        raise VerificationError(Reason.INVALID_CHAIN, "leaf not issued by intermediate")
    if not any(_issued_by(intermediate, anchor) for anchor in anchors):
        raise VerificationError(Reason.INVALID_CHAIN, "intermediate not issued by a pinned root")


def build_and_validate_path(
    target: x509.Certificate,
    candidates: Sequence[x509.Certificate],
    anchors: Sequence[x509.Certificate],
    at: datetime,
) -> None:
    """Builds and validates a path from ``target`` through ``candidates``
    (certificates embedded in the CMS) to one of the pinned ``anchors``."""
    current = target
    for depth in range(_MAX_PATH_LENGTH):
        if not _valid_at(current, at):
            raise VerificationError(Reason.INVALID_CHAIN, "certificate not valid at signing time")
        if depth > 0 and not _is_ca(current):
            raise VerificationError(Reason.INVALID_CHAIN, "intermediate is not a CA")
        if any(_issued_by(current, anchor) for anchor in anchors):
            return
        issuer = next((c for c in candidates if c is not current and _issued_by(current, c)), None)
        if issuer is None:
            raise VerificationError(Reason.INVALID_CHAIN, "chain does not reach a pinned root")
        current = issuer
    raise VerificationError(Reason.INVALID_CHAIN, "chain exceeds maximum length")
