"""Offline verification of Apple-signed JWS payloads (StoreKit 2
``jwsRepresentation``, ``signedTransactionInfo`` / ``signedRenewalInfo``,
Server Notifications V2) against pinned Apple roots — PLAN.md §2.1,
mirroring the Java implementation check-for-check."""

import base64
import binascii
import json
import re
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


#: RFC 7515 section 2 compact-JWS segments are unpadded canonical base64url:
#: this alphabet only, no "=" padding.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


def _b64url(segment: str, what: str) -> bytes:
    # Reject anything outside the base64url alphabet (incl. "=" padding) and
    # any length base64 cannot represent, before decoding at all — Python's
    # decoder silently discards non-alphabet characters otherwise, which
    # would recover the original bytes from a corrupted segment.
    if _B64URL_RE.match(segment) is None or len(segment) % 4 == 1:
        raise VerificationError(Reason.INVALID_JWS_FORMAT, f"{what} is not valid base64url")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as e:
        raise VerificationError(Reason.INVALID_JWS_FORMAT, f"{what} is not valid base64url") from e
    # Canonical check: the decoder ignores unused bits in the final
    # character, so a segment whose trailing bits are non-zero decodes to
    # the same bytes as its canonical spelling. Re-encoding must round-trip
    # to the original segment, or it isn't the canonical encoding of those
    # bytes.
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise VerificationError(Reason.INVALID_JWS_FORMAT, f"{what} is not valid base64url")
    return decoded


def _json_segment(segment: str, what: str) -> "dict[str, Any]":
    try:
        parsed = json.loads(_b64url(segment, what))
    except (ValueError, UnicodeDecodeError) as e:
        raise VerificationError(Reason.INVALID_JWS_FORMAT, f"{what} is not valid JSON") from e
    if not isinstance(parsed, dict):
        raise VerificationError(Reason.INVALID_JWS_FORMAT, f"{what} is not a JSON object")
    return parsed


def _has_extension(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bool:
    # `cert.extensions` parses the whole extension block lazily, so ONE
    # malformed extension anywhere in an x5c certificate makes every lookup
    # raise ValueError rather than ExtensionNotFound. Both mean the same
    # thing here — the certificate has not shown it carries the marker OID —
    # so both fail closed, as the Node port's safeHasExtension does.
    try:
        cert.extensions.get_extension_for_oid(oid)
        return True
    except (x509.ExtensionNotFound, ValueError):
        return False
    except x509.DuplicateExtension as e:
        # A certificate carrying one extension twice is the other way this
        # block refuses to be read, and it does not mean the same thing: RFC
        # 5280 4.2 forbids a second instance of any extension, so there is no
        # answer to "does it carry the marker OID" — a parser that allowed
        # one would have to pick a copy, and two ports could pick different
        # ones. It is the certificate that is unusable rather than its
        # purpose that is unproven, which is the verdict the ports whose
        # decoders refuse these outright reach (INVALID_CERTIFICATE), so this
        # is a rejection rather than a false return. Named rather than folded
        # into the tuple above because DuplicateExtension derives from
        # Exception, not ValueError, and so escaped this function, every
        # other `except` in the module and the caller — the fuzz finding
        # `transaction/reject-x5c-duplicate-extension` now pins.
        raise VerificationError(
            Reason.INVALID_CERTIFICATE, f"certificate carries a duplicate extension: {e}"
        ) from e


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
        # Every entry has to be a string as well as present: the header is
        # attacker-supplied JSON, so `"x5c": [1, 2, 3]` otherwise reaches
        # b64decode and comes back as a TypeError, which is not one of the
        # two exception types the decode below catches. The statically typed
        # ports get this from their JSON decoding; here it is a check.
        if (
            not isinstance(x5c, list)
            or len(x5c) != 3
            or not all(isinstance(entry, str) for entry in x5c)
        ):
            raise VerificationError(
                Reason.INVALID_JWS_FORMAT, "x5c must contain exactly 3 certificates"
            )
        try:
            leaf = x509.load_der_x509_certificate(base64.b64decode(x5c[0]))
            intermediate = x509.load_der_x509_certificate(base64.b64decode(x5c[1]))
            # cryptography decodes the SubjectPublicKeyInfo lazily, so a curve
            # it does not implement only surfaces later — as UnsupportedAlgorithm
            # out of the issuer check, where the chain gets blamed for a defect
            # of the certificate. Building both keys here settles it while the
            # verdict is still INVALID_CERTIFICATE, which is what java, swift
            # and go answer: their decoders refuse the certificate outright.
            leaf.public_key()
            intermediate.public_key()
        except Exception as e:
            # Broad by category, for the reason verify_receipt_core states at
            # length: which exception a malformed certificate produces is
            # neither documented nor stable. Naming (ValueError, binascii.Error)
            # here was tried first and missed InvalidVersion, which derives
            # from Exception directly and comes out of the loader itself.
            # Every one of them means the same thing to a caller, and it is
            # the verdict Node reaches with its own blanket catch.
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
        try:
            effective = as_utc(signed_at) if signed_at is not None else as_utc(time.time() * 1000)
        except (ValueError, OverflowError, OSError) as e:
            # signedDate is a JSON number an attacker picks, and datetime
            # covers years 1-9999: 1e300 raises OverflowError and NaN (which
            # json.loads accepts) raises ValueError, neither of which the
            # caller should ever see. An instant no calendar can express is
            # inside no certificate's validity window, which is the verdict
            # the other ports reach through their own date types — Node's
            # `new Date(1e300)` is an Invalid Date and every comparison
            # against it is false.
            raise VerificationError(
                Reason.INVALID_CHAIN, f"payload signing date {signed_at} is not a valid instant"
            ) from e
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
