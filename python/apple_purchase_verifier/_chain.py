"""Certificate chain validation against pinned trust anchors.

Hand-rolled because ``cryptography``'s verification API is TLS-oriented;
these are the PKIX-equivalent checks the Java implementation gets from
``CertPathValidator``: signature + name chaining at each step, validity
windows at signing time, and CA basic constraints on intermediates.
Anchors are trusted by fiat (their own expiry is not checked).
"""

from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature

from .exceptions import Reason, VerificationError

_MAX_PATH_LENGTH = 6


def _not_valid_before(cert):
    try:
        return cert.not_valid_before_utc  # cryptography >= 42
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def _not_valid_after(cert):
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def _valid_at(cert, at):
    return _not_valid_before(cert) <= at <= _not_valid_after(cert)


def _is_ca(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        return False


def _issued_by(cert, issuer):
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (ValueError, TypeError, InvalidSignature):
        return False


def as_utc(millis):
    return datetime.fromtimestamp(millis / 1000.0, tz=timezone.utc)


def validate_pair(leaf, intermediate, anchors, at):
    """Validates the fixed JWS path leaf → intermediate → (pinned anchor)."""
    if not _valid_at(leaf, at) or not _valid_at(intermediate, at):
        raise VerificationError(Reason.INVALID_CHAIN, "certificate not valid at signing time")
    if not _is_ca(intermediate):
        raise VerificationError(Reason.INVALID_CHAIN, "intermediate is not a CA")
    if not _issued_by(leaf, intermediate):
        raise VerificationError(Reason.INVALID_CHAIN, "leaf not issued by intermediate")
    if not any(_issued_by(intermediate, anchor) for anchor in anchors):
        raise VerificationError(Reason.INVALID_CHAIN, "intermediate not issued by a pinned root")


def build_and_validate_path(target, candidates, anchors, at):
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
        issuer = next(
            (c for c in candidates if c is not current and _issued_by(current, c)), None)
        if issuer is None:
            raise VerificationError(Reason.INVALID_CHAIN, "chain does not reach a pinned root")
        current = issuer
    raise VerificationError(Reason.INVALID_CHAIN, "chain exceeds maximum length")
