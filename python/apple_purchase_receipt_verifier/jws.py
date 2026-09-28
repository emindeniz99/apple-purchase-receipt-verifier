"""Offline verification of Apple-signed compact JWS (StoreKit 2
``jwsRepresentation``, ``signedTransactionInfo`` / ``signedRenewalInfo``, app
transactions, Server Notifications V2) against pinned Apple roots
(docs/design/0.7-api.md §2).

Algorithm, in order: the compact JWS structure, ``alg`` equal to ``ES256``,
the ``x5c`` chain to a pinned root walked top-down (hardening parity #161),
certificate validity at the payload's ``signedDate`` (the clock when it is
missing or not a representable instant), Apple's marker OIDs on the leaf and
the intermediate, and last the signature. No payload is rejected for its
age.
"""

import base64
import binascii
import json
import math
import re
from collections.abc import Callable, Sequence

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import _asn1_depth, _bounded_json, _der, _safe_text
from ._chain import authenticate_pair_top_down, valid_at_ms
from ._errors import VerificationError
from ._receipt_base64 import decode_canonical_base64
from ._utf8 import utf8_exceeds
from .reason import Reason
from .receipt_payload import JsonPayload

#: Apple marker OID: leaf certificate used for App Store signing.
LEAF_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.11.1")
#: Apple marker OID: Worldwide Developer Relations intermediate CA.
INTERMEDIATE_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.2.1")

#: Ceiling on the compact JWS this verifier will look at, in UTF-8 bytes,
#: checked before the input is split or any segment is decoded. Real Apple
#: JWS payloads, Apple's own mock notification data included, are under
#: 2.5 KB, so 256 KiB is a hundredfold headroom over anything Apple has ever
#: signed.
MAX_JWS_BYTES = 262144

#: RFC 7515 section 2 compact-JWS segments are unpadded canonical base64url:
#: this alphabet only, no "=" padding.
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_TRAILING_WHITESPACE_RE = re.compile(r"[ \t\r\n]*")


def _has_extension(cert: x509.Certificate, oid: x509.ObjectIdentifier) -> bool:
    # `cert.extensions` parses the whole extension block lazily, so ONE
    # malformed extension anywhere in an x5c certificate makes every lookup
    # raise ValueError rather than ExtensionNotFound. Both mean the same
    # thing here: the certificate has not shown it carries the marker OID.
    try:
        cert.extensions.get_extension_for_oid(oid)
        return True
    except (x509.ExtensionNotFound, ValueError):
        return False
    except x509.DuplicateExtension as e:
        # RFC 5280 4.2 forbids a second instance of any extension: the
        # certificate is unusable, not merely lacking the marker.
        raise VerificationError(
            Reason.INVALID_CERTIFICATE,
            f"certificate carries a duplicate extension: {_safe_text.detail(str(e))}",
        ) from e


def _decode_base64url(segment: str, what: str) -> bytes:
    # Reject anything outside the base64url alphabet (incl. "=" padding) and
    # any length base64 cannot represent, before decoding at all.
    if _B64URL_RE.match(segment) is None or len(segment) % 4 == 1:
        raise VerificationError(Reason.MALFORMED, f"{what} is not valid base64url")
    padded = segment + "=" * (-len(segment) % 4)
    try:
        decoded = base64.urlsafe_b64decode(padded)
    except (binascii.Error, ValueError) as e:
        raise VerificationError(Reason.MALFORMED, f"{what} is not valid base64url") from e
    # Canonical check: the decoder ignores unused bits in the final
    # character, so re-encoding must round-trip to the original segment.
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != segment:
        raise VerificationError(Reason.MALFORMED, f"{what} is not valid base64url")
    return decoded


def _read_header(header_bytes: bytes) -> "tuple[str | None, list[str] | None]":
    """What verification reads from the header: the ``alg`` and ``x5c``
    members. Anything that stops the read is MALFORMED: bytes that are not
    strict UTF-8, and anything but whitespace after the object."""
    try:
        text = header_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise VerificationError(Reason.MALFORMED, "header is not UTF-8") from e
    if _bounded_json.exceeds_bounds(text):
        raise VerificationError(Reason.MALFORMED, "header is nested too deeply")
    try:
        obj, end = json.JSONDecoder().raw_decode(text)
    except ValueError as e:
        raise VerificationError(Reason.MALFORMED, "header is not valid JSON") from e
    if _TRAILING_WHITESPACE_RE.fullmatch(text[end:]) is None:
        raise VerificationError(Reason.MALFORMED, "content after the header object")
    if not isinstance(obj, dict):
        raise VerificationError(Reason.MALFORMED, "header is not a JSON object")
    alg = obj.get("alg")
    alg = alg if isinstance(alg, str) else None
    x5c = obj.get("x5c")
    if not (isinstance(x5c, list) and all(isinstance(e, str) for e in x5c)):
        x5c = None
    return alg, x5c


class _Payload:
    __slots__ = ("error", "json_text", "problem", "signed_date_ms")

    def __init__(
        self,
        json_text: "str | None",
        signed_date_ms: "int | None",
        problem: "str | None",
        error: "Exception | None",
    ) -> None:
        self.json_text = json_text
        self.signed_date_ms = signed_date_ms
        self.problem = problem
        self.error = error


def _signed_date_ms(raw: object) -> "int | None":
    """The claim as epoch milliseconds, or ``None`` when no signed 64-bit
    value holds it: absent, not a number, a bool, or out of range. A
    fraction or exponent is read as a float and truncated toward zero when
    it lies within range."""
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    if isinstance(raw, int):
        return raw if -(2**63) <= raw <= 2**63 - 1 else None
    if not math.isfinite(raw):
        return None
    if -(2.0**63) <= raw <= 2.0**63 - 1:
        return int(raw)
    return None


def _read_payload(payload_bytes: bytes) -> _Payload:
    """What verification reads from the payload: the text, if it is a JSON
    object in UTF-8 with nothing but whitespace after it, and its top-level
    ``signedDate``. Reading it never fails verification by itself; a
    payload that does not parse is carried to the signature check."""
    try:
        text = payload_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        return _Payload(None, None, "not UTF-8", e)
    if _bounded_json.exceeds_bounds(text):
        return _Payload(None, None, "nested too deeply", None)
    try:
        obj, end = json.JSONDecoder().raw_decode(text)
    except ValueError as e:
        return _Payload(None, None, "not valid JSON", e)
    if _TRAILING_WHITESPACE_RE.fullmatch(text[end:]) is None:
        return _Payload(None, None, "content after the object", None)
    if not isinstance(obj, dict):
        return _Payload(None, None, "not an object", None)
    return _Payload(text, _signed_date_ms(obj.get("signedDate")), None, None)


def _decode_chain(x5c: "list[str]") -> "list[x509.Certificate]":
    """Decodes the three ``x5c`` entries (RFC 7515 4.1.6: standard base64,
    canonical padding). Structural decode only: no certificate's public key
    is read here (the top-down walk decodes a key only once its certificate
    is vouched for)."""
    certs = []
    for index, entry in enumerate(x5c):
        try:
            der = decode_canonical_base64(entry)
            if _asn1_depth.exceeded(der):
                raise ValueError("nests ASN.1 too deeply")
            if not _der.certificate_signature_is_aligned(der):
                raise ValueError("signature BIT STRING is not byte-aligned")
            cert = x509.load_der_x509_certificate(der)
            # Forces the whole extension block to decode now, while the
            # verdict is still "not a valid certificate": a malformed
            # extension anywhere (not only the marker OIDs) is read lazily
            # by `cryptography` and would otherwise surface later as a
            # chain failure instead of what it is, a broken certificate.
            _ = cert.extensions
            certs.append(cert)
        except Exception as e:
            raise VerificationError(
                Reason.INVALID_CERTIFICATE, f"x5c[{index}] is not a valid certificate"
            ) from e
    return certs


def _verify_es256(leaf: x509.Certificate, signing_input: bytes, signature: bytes) -> None:
    if len(signature) != 64:
        raise VerificationError(
            Reason.INVALID_SIGNATURE, f"ES256 signature must be 64 bytes, got {len(signature)}"
        )
    try:
        public_key = leaf.public_key()
    except Exception as e:
        raise VerificationError(
            Reason.INVALID_CERTIFICATE, "leaf certificate key does not decode"
        ) from e
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise VerificationError(Reason.INVALID_SIGNATURE, "leaf key is not EC")
    r = int.from_bytes(signature[:32], "big")
    s = int.from_bytes(signature[32:], "big")
    try:
        public_key.verify(encode_dss_signature(r, s), signing_input, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as e:
        raise VerificationError(Reason.INVALID_SIGNATURE, "ES256 signature check failed") from e


def _require_marker(cert: x509.Certificate, oid: x509.ObjectIdentifier, what: str) -> None:
    if not _has_extension(cert, oid):
        raise VerificationError(
            Reason.INVALID_CERTIFICATE_PURPOSE,
            f"{what} certificate lacks Apple marker OID {oid.dotted_string}",
        )


def _require_valid(cert: x509.Certificate, at_ms: int, what: str) -> None:
    if not valid_at_ms(cert, at_ms):
        raise VerificationError(
            Reason.INVALID_CERTIFICATE, f"{what} certificate is not valid at the checked instant"
        )


def _verify_unguarded(
    jws: str, roots: "Sequence[x509.Certificate]", clock: Callable[[], int]
) -> JsonPayload:
    parts = jws.split(".")
    if len(parts) != 3:
        raise VerificationError(
            Reason.MALFORMED, f"expected 3 dot-separated segments, got {len(parts)}"
        )
    header_bytes = _decode_base64url(parts[0], "header")
    payload_bytes = _decode_base64url(parts[1], "payload")
    signature_bytes = _decode_base64url(parts[2], "signature")

    alg, x5c = _read_header(header_bytes)
    if alg != "ES256":
        raise VerificationError(Reason.MALFORMED, f"alg must be ES256, got {_safe_text.quote(alg)}")
    if x5c is None or len(x5c) != 3:
        raise VerificationError(Reason.MALFORMED, "x5c must contain exactly 3 certificates")
    # x5c[2] is decoded (structurally, above) and then dropped: it is the
    # JWS-supplied root, never compared to a pinned anchor and never
    # trusted, so a stranger's root changes nothing.
    chain = _decode_chain(x5c)
    leaf, intermediate = chain[0], chain[1]

    payload = _read_payload(payload_bytes)

    authenticate_pair_top_down(leaf, intermediate, roots)

    at_ms = payload.signed_date_ms if payload.signed_date_ms is not None else clock()
    _require_valid(leaf, at_ms, "leaf")
    _require_valid(intermediate, at_ms, "intermediate")

    _require_marker(leaf, LEAF_OID, "leaf")
    _require_marker(intermediate, INTERMEDIATE_OID, "intermediate")

    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    _verify_es256(leaf, signing_input, signature_bytes)

    if payload.json_text is None:
        raise VerificationError(
            Reason.UNREADABLE_PAYLOAD, f"signed payload is not a JSON object: {payload.problem}"
        ) from payload.error
    return JsonPayload(json=payload.json_text)


def verify_signed_data(
    jws: "str | None", roots: "Sequence[x509.Certificate]", clock: Callable[[], int]
) -> JsonPayload:
    """Verifies ``jws`` and returns its payload.

    :raises VerificationError: never for a caught, understood defect; see
        :mod:`.reason` for what each :class:`~.reason.Reason` means
    """
    if not jws:
        raise VerificationError(Reason.MALFORMED, "jws is empty")
    if utf8_exceeds(jws, MAX_JWS_BYTES):
        raise VerificationError(
            Reason.TOO_LARGE, f"jws exceeds the maximum accepted size of {MAX_JWS_BYTES} bytes"
        )
    try:
        return _verify_unguarded(jws, roots, clock)
    except VerificationError:
        raise
    except Exception as e:
        # Everything here runs on input nobody has vouched for yet, so an
        # exception this module did not anticipate is reported as a format
        # defect (MALFORMED), never INTERNAL_ERROR: answering an unknown
        # error with INTERNAL_ERROR ("alert and reconcile") would let anyone
        # raise that alert at will (hardening parity change #4).
        raise VerificationError(Reason.MALFORMED, f"unexpected {type(e).__name__}") from e
