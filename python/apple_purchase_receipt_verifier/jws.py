"""Offline verification of Apple-signed JWS payloads (StoreKit 2
``jwsRepresentation``, ``signedTransactionInfo`` / ``signedRenewalInfo``,
Server Notifications V2) against pinned Apple roots — PLAN.md §2.1,
mirroring the Java implementation check-for-check."""

import base64
import binascii
import json
import time
from collections.abc import Iterable
from typing import Any, Callable, Optional

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from ._chain import as_utc, validate_pair
from .exceptions import ENVIRONMENTS, Reason, VerificationError

#: Apple marker OID: leaf certificate used for App Store signing.
LEAF_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.11.1")
#: Apple marker OID: Worldwide Developer Relations intermediate CA.
INTERMEDIATE_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.2.1")


def _b64url(segment: str, what: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))
    except (binascii.Error, ValueError) as e:
        raise VerificationError(Reason.INVALID_JWS_FORMAT, f"{what} is not valid base64url") from e


def _json_segment(segment: str, what: str) -> "dict[str, Any]":
    try:
        parsed = json.loads(_b64url(segment, what))
    except (ValueError, UnicodeDecodeError) as e:
        raise VerificationError(Reason.INVALID_JWS_FORMAT, f"{what} is not valid JSON") from e
    if not isinstance(parsed, dict):
        raise VerificationError(Reason.INVALID_JWS_FORMAT, f"{what} is not a JSON object")
    return parsed


def _has_extension(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bool:
    try:
        cert.extensions.get_extension_for_oid(oid)
        return True
    except x509.ExtensionNotFound:
        return False


class JwsVerifier:
    """Thread-safe once constructed.

    :param trusted_roots: pinned root certificates
        (production: :func:`apple_purchase_receipt_verifier.apple_jws_roots`)
    :param bundle_id: the app's bundle id every payload must carry
    :param accepted_environments: e.g. ``["Production", "Sandbox"]`` —
        include Sandbox on endpoints App Review can hit (PLAN.md D3)
    :param app_apple_id: required to accept Production AppTransactions
    :param max_signed_age_millis: reject payloads signed longer ago than
        this (PLAN.md D5)
    :param clock: source of "now" for the max-signed-age rule, as a
        zero-argument callable returning epoch seconds. Optional; omitted,
        the system clock is used and behaviour is unchanged.

        A zero-argument callable is Python's idiomatic injectable time
        source, and ``time.time`` is itself exactly one — so the default is
        the stdlib function and an injected clock is any drop-in for it
        (``lambda: 1735689600.0``). Epoch seconds rather than a ``datetime``
        because the staleness arithmetic is in epoch milliseconds and the
        code already called ``time.time()``, so nothing is converted at the
        seam; a caller holding a ``datetime`` passes ``moment.timestamp``.
        The clock drives ONLY checks that genuinely depend on the current
        time. Certificate validity is not one: it is judged at the payload
        ``signedDate`` (PLAN.md §2.1 step 4) and never moves with the clock.
    """

    def __init__(
        self,
        trusted_roots: Iterable[Any],
        bundle_id: str,
        accepted_environments: Iterable[str],
        app_apple_id: Optional[int] = None,
        max_signed_age_millis: Optional[int] = None,
        clock: Optional[Callable[[], float]] = None,
    ):
        roots = list(trusted_roots)
        if not roots:
            raise ValueError("trusted_roots must not be empty")
        if not bundle_id:
            raise ValueError("bundle_id is required")
        environments = set(accepted_environments)
        if not environments or not environments.issubset(ENVIRONMENTS):
            raise ValueError(
                "accepted_environments must be a non-empty subset of known environments"
            )
        self._roots = roots
        self._bundle_id = bundle_id
        self._accepted_environments = environments
        self._app_apple_id = app_apple_id
        self._max_signed_age_millis = max_signed_age_millis
        self._clock = time.time if clock is None else clock

    def verify_transaction(self, jws: str) -> dict[str, Any]:
        """Verifies a signed transaction and checks bundle id + environment."""
        payload = self._verify_signature(jws)
        self._require_bundle_id(payload.get("bundleId"))
        self._require_accepted_environment(payload.get("environment"))
        return payload

    def verify_app_transaction(self, jws: str) -> dict[str, Any]:
        """Verifies a signed AppTransaction and checks bundle id, environment
        (``receiptType``), and — in Production — the app Apple id."""
        payload = self._verify_signature(jws)
        self._require_bundle_id(payload.get("bundleId"))
        environment = self._require_accepted_environment(payload.get("receiptType"))
        if environment == "Production" and (
            self._app_apple_id is None or self._app_apple_id != payload.get("appAppleId")
        ):
            raise VerificationError(
                Reason.WRONG_APP_APPLE_ID,
                f"expected {self._app_apple_id} but payload has {payload.get('appAppleId')}",
            )
        return payload

    def verify_raw(self, jws: str) -> dict[str, Any]:
        """Verifies the signature/chain only and returns the raw claims — for
        payload types without a dedicated model (renewal info, notification
        envelopes). The caller must check bundle id / environment /
        app Apple id in the returned claims itself."""
        return self._verify_signature(jws)

    def _verify_signature(self, jws: str) -> dict[str, Any]:
        if not isinstance(jws, str):
            raise VerificationError(Reason.INVALID_JWS_FORMAT, "jws must be a string")
        parts = jws.split(".")
        if len(parts) != 3:
            raise VerificationError(
                Reason.INVALID_JWS_FORMAT, f"expected 3 dot-separated segments, got {len(parts)}"
            )
        header = _json_segment(parts[0], "header")
        if header.get("alg") != "ES256":
            raise VerificationError(
                Reason.INVALID_JWS_FORMAT, f"alg must be ES256, got {header.get('alg')}"
            )
        x5c = header.get("x5c")
        if not isinstance(x5c, list) or len(x5c) != 3:
            raise VerificationError(
                Reason.INVALID_JWS_FORMAT, "x5c must contain exactly 3 certificates"
            )
        try:
            leaf = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
            intermediate = x509.load_der_x509_certificate(base64.b64decode(x5c[1]))
        except (ValueError, binascii.Error) as e:
            raise VerificationError(
                Reason.INVALID_CERTIFICATE, "x5c entry is not a valid certificate"
            ) from e
        if not _has_extension(leaf, LEAF_OID):
            raise VerificationError(
                Reason.INVALID_CERTIFICATE_PURPOSE,
                f"leaf certificate lacks Apple marker OID {LEAF_OID.dotted_string}",
            )
        if not _has_extension(intermediate, INTERMEDIATE_OID):
            raise VerificationError(
                Reason.INVALID_CERTIFICATE_PURPOSE,
                f"intermediate certificate lacks Apple marker OID {INTERMEDIATE_OID.dotted_string}",
            )

        payload = _json_segment(parts[1], "payload")
        # Chain validity is checked at signing time so payloads signed with
        # since-rotated certificates keep verifying (PLAN.md §2.1 step 4).
        signed_at = payload.get("signedDate")
        if not isinstance(signed_at, (int, float)):
            signed_at = payload.get("receiptCreationDate")
        if not isinstance(signed_at, (int, float)):
            signed_at = None
        # Deliberately the system clock, not self._clock: an injected clock
        # must not be able to move a certificate-validity verdict. This
        # fallback only fires for a payload carrying neither signedDate nor
        # receiptCreationDate, where PLAN.md's "else current time" leaves the
        # window anchored to real time.
        effective = as_utc(signed_at) if signed_at is not None else as_utc(time.time() * 1000)
        validate_pair(leaf, intermediate, self._roots, effective)

        public_key = leaf.public_key()
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            raise VerificationError(Reason.INVALID_SIGNATURE, "leaf key is not EC")
        signature = _b64url(parts[2], "signature")
        if len(signature) != 64:
            raise VerificationError(
                Reason.INVALID_SIGNATURE, f"ES256 signature must be 64 bytes, got {len(signature)}"
            )
        r = int.from_bytes(signature[:32], "big")
        s = int.from_bytes(signature[32:], "big")
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        try:
            public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
        except InvalidSignature as e:
            raise VerificationError(Reason.INVALID_SIGNATURE, "ES256 signature check failed") from e

        if (
            self._max_signed_age_millis is not None
            and signed_at is not None
            and self._clock() * 1000 - signed_at > self._max_signed_age_millis
        ):
            raise VerificationError(
                Reason.STALE_PAYLOAD,
                f"payload signed at {signed_at} exceeds max age {self._max_signed_age_millis}ms",
            )
        return payload

    def _require_bundle_id(self, actual: Any) -> None:
        if actual != self._bundle_id:
            raise VerificationError(
                Reason.WRONG_BUNDLE_ID, f"expected {self._bundle_id} but payload has {actual}"
            )

    def _require_accepted_environment(self, claim: Any) -> Any:
        if claim not in self._accepted_environments:
            raise VerificationError(
                Reason.WRONG_ENVIRONMENT, f"payload environment {claim} not in accepted set"
            )
        return claim


def is_transaction_active_at(payload: dict[str, Any], now_millis: int) -> bool:
    """Entitlement helper for a verified transaction payload: not revoked,
    and (for subscriptions) not expired at ``now_millis``. Point-in-time on
    the signed claims only — later refunds or renewals are invisible."""
    revocation = payload.get("revocationDate")
    if isinstance(revocation, (int, float)) and now_millis >= revocation:
        return False
    expires = payload.get("expiresDate")
    if isinstance(expires, (int, float)):
        return now_millis < expires
    return True
