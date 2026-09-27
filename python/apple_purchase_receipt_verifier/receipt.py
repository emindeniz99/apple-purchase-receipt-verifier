"""Offline verification of legacy PKCS#7 app receipts against pinned roots
(docs/design/0.7-api.md §1): the server-side port of Apple's "Validating
receipts on the device" procedure.

Algorithm, in order: strict base64, the CMS envelope, the chain to a pinned
root walked top-down (hardening parity #161), Apple's marker OIDs on both
the leaf (receipt signing) and the WWDR intermediate, certificate validity
at the receipt's creation date, and last the signature. Several SignerInfos
are tried in turn; when none passes, the first one's failure is reported.

CMS parsing uses ``asn1crypto`` (BER-capable: genuine Apple/Xcode receipts
use indefinite lengths); the receipt payload itself is parsed with a small
strict DER reader below.
"""

import hashlib
import hmac
from collections.abc import Callable, Sequence
from typing import Any

from asn1crypto import cms as asn1cms
from asn1crypto import core as asn1core
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from . import _asn1_depth, _der
from ._chain import build_path_top_down, valid_at_ms
from ._errors import VerificationError
from ._receipt_base64 import decode_receipt_base64
from ._utf8 import utf8_exceeds
from .jws import INTERMEDIATE_OID, LEAF_OID, _has_extension
from .reason import Reason
from .receipt_payload import InAppPurchase, ReceiptPayload

# Apple's receipt-signing marker, on the signer leaf; same OID the JWS path
# checks (the marker is per purpose, not per format).
_RECEIPT_SIGNER_OID = LEAF_OID

#: Ceiling on the base64 receipt string, in UTF-8 bytes.
MAX_RECEIPT_BYTES = 3145728
#: Ceiling on the certificates a receipt may embed.
MAX_EMBEDDED_CERTIFICATES = 10
#: Ceiling on the SignerInfos a receipt may carry.
MAX_SIGNER_INFOS = 4

#: The digests this library verifies a receipt signature under: the
#: guaranteed minimum set (docs/design/0.7-hardening-parity.md, "any
#: receipt signer algorithm").
_DIGESTS: "dict[str, Any]" = {
    "md5": hashes.MD5,
    "sha1": hashes.SHA1,
    "sha224": hashes.SHA224,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
}

# Receipt attribute types (see the Java port's ReceiptDecoder for the full
# provenance of the four community-established ones).
_ATTR_RECEIPT_TYPE = 0
_ATTR_APP_ITEM_ID = 1
_ATTR_BUNDLE_ID = 2
_ATTR_APP_VERSION = 3
_ATTR_OPAQUE_VALUE = 4
_ATTR_SHA1_HASH = 5
_ATTR_CREATION_DATE = 12
_ATTR_DOWNLOAD_ID = 15
_ATTR_VERSION_EXTERNAL_IDENTIFIER = 16
_ATTR_IN_APP = 17
_ATTR_ORIGINAL_APP_VERSION = 19
_ATTR_ORIGINAL_PURCHASE_DATE = 18
_ATTR_EXPIRATION_DATE = 21

_TOP_LEVEL_TYPES = {
    _ATTR_RECEIPT_TYPE, _ATTR_APP_ITEM_ID, _ATTR_BUNDLE_ID, _ATTR_APP_VERSION,
    _ATTR_OPAQUE_VALUE, _ATTR_SHA1_HASH, _ATTR_CREATION_DATE, _ATTR_DOWNLOAD_ID,
    _ATTR_VERSION_EXTERNAL_IDENTIFIER, _ATTR_ORIGINAL_PURCHASE_DATE,
    _ATTR_ORIGINAL_APP_VERSION, _ATTR_EXPIRATION_DATE,
}  # fmt: skip

_IAP_QUANTITY = 1701
_IAP_PRODUCT_ID = 1702
_IAP_TRANSACTION_ID = 1703
_IAP_PURCHASE_DATE = 1704
_IAP_ORIGINAL_TRANSACTION_ID = 1705
_IAP_ORIGINAL_PURCHASE_DATE = 1706
_IAP_EXPIRES_DATE = 1708
_IAP_WEB_ORDER_LINE_ITEM_ID = 1711
_IAP_CANCELLATION_DATE = 1712
_IAP_IS_TRIAL_PERIOD = 1713
_IAP_IS_IN_INTRO_OFFER_PERIOD = 1719

_IN_APP_TYPES = {
    _IAP_QUANTITY, _IAP_PRODUCT_ID, _IAP_TRANSACTION_ID, _IAP_PURCHASE_DATE,
    _IAP_ORIGINAL_TRANSACTION_ID, _IAP_ORIGINAL_PURCHASE_DATE, _IAP_EXPIRES_DATE,
    _IAP_WEB_ORDER_LINE_ITEM_ID, _IAP_CANCELLATION_DATE, _IAP_IS_TRIAL_PERIOD,
    _IAP_IS_IN_INTRO_OFFER_PERIOD,
}  # fmt: skip


def verify_receipt(
    base64_text: "str | None", roots: "Sequence[x509.Certificate]", clock: Callable[[], int]
) -> ReceiptPayload:
    """Verifies ``base64_text`` (the usual client transport form of a
    receipt) and decodes it.

    :raises VerificationError: never for a caught, understood defect; see
        :mod:`.reason` for what each :class:`~.reason.Reason` means
    """
    if not base64_text:
        raise VerificationError(Reason.MALFORMED, "receipt is empty")
    # Before the decode, which would otherwise allocate the bytes it
    # decodes to.
    if utf8_exceeds(base64_text, MAX_RECEIPT_BYTES):
        raise VerificationError(
            Reason.TOO_LARGE,
            f"receipt exceeds the maximum accepted size of {MAX_RECEIPT_BYTES} bytes",
        )
    der = decode_receipt_base64(base64_text)
    return verify_receipt_der(der, roots, clock)


def verify_receipt_der(
    der: bytes, roots: "Sequence[x509.Certificate]", clock: Callable[[], int]
) -> ReceiptPayload:
    """:func:`verify_receipt` after the base64 step. Module-internal (not
    re-exported from the package): the public API takes only the base64
    string a client sends; this is what the fuzz suite (python/fuzz) uses
    to exercise the DER path directly, without base64 diluting coverage."""
    if not der:
        raise VerificationError(Reason.MALFORMED, "receipt is empty")
    if len(der) > MAX_RECEIPT_BYTES:
        raise VerificationError(
            Reason.TOO_LARGE,
            f"receipt exceeds the maximum accepted size of {MAX_RECEIPT_BYTES} bytes",
        )
    try:
        payload = _verify_signature(der, roots, clock)
    except VerificationError:
        raise
    except Exception as e:
        # MALFORMED, not INTERNAL_ERROR: everything that can throw here runs
        # before a signature has verified, so it is attacker input
        # (hardening parity change #4). Signed content that cannot be read
        # is UNREADABLE_PAYLOAD, decided in _parse_signed_payload.
        raise VerificationError(Reason.MALFORMED, f"unexpected {type(e).__name__}") from e
    return _parse_signed_payload(payload)


def _verify_signature(
    der: bytes, roots: "Sequence[x509.Certificate]", clock: Callable[[], int]
) -> bytes:
    if _asn1_depth.exceeded(der):
        raise VerificationError(Reason.MALFORMED, "receipt nests ASN.1 too deeply")
    content, econtent_type, embedded_raw, signer_infos = _parse_cms(der)
    if len(embedded_raw) > MAX_EMBEDDED_CERTIFICATES:
        raise VerificationError(
            Reason.MALFORMED,
            f"receipt embeds {len(embedded_raw)} certificates, more than the "
            f"maximum of {MAX_EMBEDDED_CERTIFICATES}",
        )
    if len(signer_infos) == 0:
        raise VerificationError(Reason.MALFORMED, "no signer info")
    if len(signer_infos) > MAX_SIGNER_INFOS:
        raise VerificationError(
            Reason.MALFORMED,
            f"receipt carries {len(signer_infos)} SignerInfos, more than the "
            f"maximum of {MAX_SIGNER_INFOS}",
        )
    # Every SignerInfo's signedAttrs syntax is judged before any key is
    # used, regardless of position, so a malformed one is MALFORMED whether
    # it is the first signer or the last.
    for signer in signer_infos:
        _require_attribute_set_syntax(signer)

    readable, unreadable = _decode_embedded(embedded_raw)

    creation_date_ms = _read_creation_date(content)
    at_ms = creation_date_ms if creation_date_ms is not None else clock()

    first_failure: VerificationError | None = None
    for signer in signer_infos:
        try:
            signer_cert = _find_signer_cert(readable, unreadable, signer)
            path = build_path_top_down(signer_cert, [cert for _, cert in readable], roots)
            _require_markers(path)
            for cert in path:
                if not valid_at_ms(cert, at_ms):
                    raise VerificationError(
                        Reason.INVALID_CERTIFICATE,
                        "receipt certificate is not valid at the checked instant",
                    )
            # The chain and validity are checked BEFORE the signature on
            # purpose: checking the signature first would run the
            # attacker's own key (their choice of RSA size and exponent)
            # before anything about it is trusted.
            _verify_cms_signature(content, econtent_type, signer, signer_cert)
            return content
        except VerificationError as e:
            # Every SignerInfo signs the same content, so another one
            # passing proves the same bytes; only when none does is the
            # first one's failure the verdict.
            if first_failure is None:
                first_failure = e
    assert first_failure is not None
    raise first_failure


def _require_markers(path: "list[x509.Certificate]") -> None:
    signer_cert = path[0]
    if not _has_extension(signer_cert, _RECEIPT_SIGNER_OID):
        raise VerificationError(
            Reason.INVALID_CERTIFICATE_PURPOSE,
            f"receipt signer certificate lacks Apple receipt-signing marker OID "
            f"{_RECEIPT_SIGNER_OID.dotted_string}",
        )
    if len(path) < 2 or not _has_extension(path[1], INTERMEDIATE_OID):
        raise VerificationError(
            Reason.INVALID_CERTIFICATE_PURPOSE,
            f"receipt intermediate certificate lacks Apple WWDR marker OID "
            f"{INTERMEDIATE_OID.dotted_string}",
        )


def _parse_cms(der: bytes) -> "tuple[bytes, str, list[bytes], list[Any]]":
    try:
        info = asn1cms.ContentInfo.load(der, strict=True)  # rejects trailing bytes
        if info["content_type"].native != "signed_data":
            raise ValueError("not CMS SignedData")
        signed_data = info["content"]
        econtent_type = signed_data["encap_content_info"]["content_type"].native
        content = signed_data["encap_content_info"]["content"].native
        if not isinstance(content, bytes):
            raise ValueError("no encapsulated payload")
        embedded_raw = []
        certificate_choices = signed_data["certificates"]
        if certificate_choices:
            for choice in certificate_choices:
                embedded_raw.append(choice.chosen.dump())
        signer_infos = list(signed_data["signer_infos"])
        return content, econtent_type, embedded_raw, signer_infos
    except VerificationError:
        raise
    except Exception as e:  # asn1crypto raises broadly on malformed input
        raise VerificationError(Reason.MALFORMED, "not a parseable PKCS#7/CMS blob") from e


def _decode_embedded(
    embedded_raw: "list[bytes]",
) -> "tuple[list[tuple[bytes, x509.Certificate]], list[tuple[bytes, Exception]]]":
    readable = []
    unreadable = []
    for raw in embedded_raw:
        try:
            if _asn1_depth.exceeded(raw):
                raise ValueError("nests ASN.1 too deeply")
            if not _der.certificate_signature_is_aligned(raw):
                raise ValueError("signature BIT STRING is not byte-aligned")
            cert = x509.load_der_x509_certificate(raw)
            # Forces the whole extension block to decode now: a malformed
            # extension anywhere makes this entry unreadable the same way a
            # malformed certificate structure does, rather than surfacing
            # later as a chain failure (see jws._decode_chain).
            _ = cert.extensions
            readable.append((raw, cert))
        except Exception as e:
            unreadable.append((raw, e))
    return readable, unreadable


def _names_the_signer(raw: bytes, wanted_issuer: bytes, wanted_serial: int) -> bool:
    try:
        tbs = asn1x509.Certificate.load(raw)["tbs_certificate"]
        return bool(
            tbs["serial_number"].native == wanted_serial and tbs["issuer"].dump() == wanted_issuer
        )
    except Exception:
        return False


def _find_signer_cert(
    readable: "list[tuple[bytes, x509.Certificate]]",
    unreadable: "list[tuple[bytes, Exception]]",
    signer: Any,
) -> x509.Certificate:
    try:
        sid = signer["sid"].chosen
        wanted_serial = sid["serial_number"].native
        wanted_issuer = sid["issuer"].dump()
    except Exception as e:
        raise VerificationError(Reason.MALFORMED, "malformed signer id") from e
    # An unreadable entry naming the signer is a defect of a certificate; any
    # other unreadable entry is a defect of the (unsigned) certificate bag
    # itself, and a broken signer outranks a broken stranger.
    for raw, error in unreadable:
        if _names_the_signer(raw, wanted_issuer, wanted_serial):
            raise VerificationError(
                Reason.INVALID_CERTIFICATE, "receipt signer certificate is not a valid certificate"
            ) from error
    if unreadable:
        raise VerificationError(
            Reason.MALFORMED, "an embedded certificate is not a valid certificate"
        ) from unreadable[0][1]
    for raw, cert in readable:
        matches_issuer = (
            asn1x509.Certificate.load(raw)["tbs_certificate"]["issuer"].dump() == wanted_issuer
        )
        if cert.serial_number == wanted_serial and matches_issuer:
            return cert
    raise VerificationError(Reason.MALFORMED, "signer certificate not embedded")


def _require_attribute_set_syntax(signer: Any) -> None:
    """The syntax of one SignerInfo's signedAttrs, judged before any key is
    used: ``SEQUENCE { OID, SET OF value }`` with at least one value.
    A well-formed set lacking ``contentType`` or ``messageDigest`` is left
    to the signature check, as ``INVALID_SIGNATURE`` for that signer."""
    signed_attrs = signer["signed_attrs"]
    if isinstance(signed_attrs, asn1core.Void):
        return
    try:
        for attr in signed_attrs:
            if len(attr["values"]) == 0:
                raise ValueError("attribute carries no values")
    except VerificationError:
        raise
    except Exception as e:
        raise VerificationError(
            Reason.MALFORMED, "malformed signedAttrs: not an attribute set"
        ) from e


def _verify_cms_signature(
    content: bytes, econtent_type: str, signer: Any, signer_cert: x509.Certificate
) -> None:
    try:
        digest_name = signer["digest_algorithm"]["algorithm"].native
        signature = signer["signature"].native
        signature_algorithm = signer["signature_algorithm"]
    except Exception as e:  # attacker-chosen tags, decoded before the signature check
        raise VerificationError(Reason.MALFORMED, "malformed signer info") from e
    digest_cls = _DIGESTS.get(digest_name)
    if digest_cls is None:
        raise VerificationError(
            Reason.INVALID_SIGNATURE, f"unsupported digest algorithm {digest_name}"
        )
    try:
        family = signature_algorithm.signature_algo
    except Exception as e:
        raise VerificationError(Reason.INVALID_SIGNATURE, "unsupported signature algorithm") from e
    try:
        named_hash = signature_algorithm.hash_algo
    except ValueError:
        named_hash = None
    # A signatureAlgorithm that names a hash must name the one the
    # SignerInfo digested with (a relabelled field is not one signature
    # under two names); rsaEncryption / id-ecPublicKey name none and take
    # digestAlgorithm. No algorithm or key-type allowlist otherwise
    # (hardening parity change #3): the signer already chains to a pinned
    # root and carries Apple's marker, so whatever algorithm Apple signs
    # with is accepted.
    if named_hash is not None and named_hash != digest_name:
        raise VerificationError(
            Reason.INVALID_SIGNATURE, "signatureAlgorithm names another hash than digestAlgorithm"
        )
    hash_algorithm = digest_cls()

    signed_attrs = signer["signed_attrs"]
    data = (
        content
        if isinstance(signed_attrs, asn1core.Void)
        else _signed_attrs_to_sign(signed_attrs, digest_name, content, econtent_type)
    )
    try:
        # Safe to decode now: the signer is already vouched by the top-down
        # chain walk. A curve or key shape this build does not implement is
        # then a verdict about the certificate, not about the chain.
        public_key = signer_cert.public_key()
    except Exception as e:
        raise VerificationError(
            Reason.INVALID_CERTIFICATE, "receipt signer certificate key does not decode"
        ) from e
    try:
        if family == "rsassa_pkcs1v15":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise VerificationError(Reason.INVALID_SIGNATURE, "signer key is not RSA")
            public_key.verify(signature, data, padding.PKCS1v15(), hash_algorithm)
        elif family == "rsassa_pss":
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise VerificationError(Reason.INVALID_SIGNATURE, "signer key is not RSA")
            salt_length = _pss_salt_length(signature_algorithm, hash_algorithm)
            public_key.verify(
                signature,
                data,
                padding.PSS(mgf=padding.MGF1(hash_algorithm), salt_length=salt_length),
                hash_algorithm,
            )
        elif family == "ecdsa":
            if not isinstance(public_key, ec.EllipticCurvePublicKey):
                raise VerificationError(Reason.INVALID_SIGNATURE, "signer key is not EC")
            public_key.verify(signature, data, ec.ECDSA(hash_algorithm))
        else:
            raise VerificationError(
                Reason.INVALID_SIGNATURE, f"unsupported signer algorithm {family}"
            )
    except InvalidSignature as e:
        raise VerificationError(Reason.INVALID_SIGNATURE, "CMS signature check failed") from e


def _pss_salt_length(signature_algorithm: Any, hash_algorithm: Any) -> int:
    try:
        params = signature_algorithm["parameters"]
        if params.native is not None:
            return int(params["salt_length"].native)
    except Exception:
        pass
    return int(hash_algorithm.digest_size)


def _signed_attrs_to_sign(
    signed_attrs: Any, digest_name: str, content: bytes, econtent_type: str
) -> bytes:
    """The bytes the signature must cover when signedAttrs are present:
    their OIDs, types and nesting are attacker-chosen and decoded here,
    before the signature check that would reject them."""
    try:
        content_digest = hashlib.new(digest_name, content).digest()
    except ValueError as e:
        raise VerificationError(Reason.INTERNAL_ERROR, f"{digest_name} is not available") from e
    try:
        message_digest = None
        message_digest_seen = False
        for attr in signed_attrs:
            attr_type = attr["type"].native
            if attr_type == "message_digest":
                if message_digest_seen:  # RFC 5652 5.3: at most one instance
                    raise VerificationError(
                        Reason.INVALID_SIGNATURE,
                        "messageDigest attribute is present more than once",
                    )
                message_digest_seen = True
                values = attr["values"]
                if len(values) != 1:  # RFC 5652 5.3: exactly one value
                    raise VerificationError(
                        Reason.INVALID_SIGNATURE,
                        "messageDigest attribute must carry exactly one value",
                    )
                message_digest = values[0].native
            elif attr_type == "content_type":
                content_type = attr["values"][0].native
                if content_type != econtent_type:
                    raise VerificationError(
                        Reason.INVALID_SIGNATURE,
                        "contentType attribute does not match the encapsulated content type",
                    )
        if message_digest is None or not hmac.compare_digest(message_digest, content_digest):
            raise VerificationError(
                Reason.INVALID_SIGNATURE, "messageDigest attribute does not match content"
            )
        # Signature covers the signedAttrs re-encoded as an explicit SET
        # (RFC 5652 5.4): swap the IMPLICIT [0] tag for SET.
        raw: bytes = signed_attrs.dump()
        return b"\x31" + raw[1:]
    except VerificationError:
        raise
    except Exception as e:  # asn1crypto raises broadly on malformed input
        raise VerificationError(Reason.INVALID_SIGNATURE, "unparseable signed attributes") from e


# --- strict DER reader for the receipt payload ---------------------------

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_UTF8_STRING = 0x0C
_TAG_IA5_STRING = 0x16
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31

#: Attribute *types* are a 32-bit signed space; a wider type cannot be
#: represented and is refused for the whole payload rather than narrowed,
#: which would invent an attribute the receipt never carried.
_MAX_ATTRIBUTE_TYPE = 2147483647


class _PayloadFormatError(Exception):
    """Internal: a defect of the signed payload bytes themselves (as
    distinct from a per-attribute value that simply does not decode)."""


def _read_tlv(data: bytes, offset: int) -> "tuple[int, bytes, int]":
    if offset + 2 > len(data):
        raise _PayloadFormatError("truncated ASN.1 value")
    tag = data[offset]
    pos = offset + 1
    length = data[pos]
    pos += 1
    if length >= 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise _PayloadFormatError("unsupported ASN.1 length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise _PayloadFormatError("ASN.1 length exceeds input")
    return tag, data[pos:end], end


def _children(contents: bytes) -> "list[tuple[int, bytes]]":
    out = []
    pos = 0
    while pos < len(contents):
        tag, value, pos = _read_tlv(contents, pos)
        out.append((tag, value))
    return out


def _der_signed_int(contents: bytes) -> int:
    """The content octets of a DER INTEGER, as the signed two's-complement
    value they encode. DER forbids padding: no redundant leading 0x00 (when
    the next octet's high bit is already 0) and no redundant leading 0xFF
    (when the next octet's high bit is already 1)."""
    if len(contents) == 0:
        raise _PayloadFormatError("attribute integer is empty")
    if len(contents) >= 2 and (
        (contents[0] == 0x00 and contents[1] < 0x80)
        or (contents[0] == 0xFF and contents[1] >= 0x80)
    ):
        raise _PayloadFormatError("attribute integer is not minimally encoded")
    return int.from_bytes(contents, "big", signed=True)


def _attribute_type(contents: bytes) -> int:
    # Attribute *types* are non-negative; real receipts carry no negative
    # one, and 0.7 refuses one the same width every other integer gets
    # (docs/design/0.7-api.md: "types 0..2^31-1, wider -> whole payload
    # unreadable").
    if len(contents) > 8:
        raise _PayloadFormatError("attribute type out of range")
    value = _der_signed_int(contents)
    if value < 0 or value > _MAX_ATTRIBUTE_TYPE:
        raise _PayloadFormatError(f"receipt attribute type {value} exceeds the 32-bit signed range")
    return value


def _parse_attribute_set(der: bytes, what: str) -> "list[tuple[int, bytes]]":
    if _asn1_depth.exceeded(der):
        raise _PayloadFormatError(f"{what} nests ASN.1 too deeply")
    tag, contents, end = _read_tlv(der, 0)
    if tag == _TAG_OCTET_STRING and end == len(der):
        # Xcode receipts double-wrap the payload in an extra OCTET STRING.
        der = contents
        if _asn1_depth.exceeded(der):
            raise _PayloadFormatError(f"{what} double-wrap nests ASN.1 too deeply")
        tag, contents, end = _read_tlv(der, 0)
    if tag != _TAG_SET or end != len(der):
        raise _PayloadFormatError(f"{what} is not an ASN.1 SET")
    attributes = []
    for child_tag, child_value in _children(contents):
        if child_tag != _TAG_SEQUENCE:
            raise _PayloadFormatError("malformed receipt attribute")
        fields = _children(child_value)
        # Fields beyond type, version and value are tolerated, so a field
        # Apple appends later does not break parsing.
        if len(fields) < 3 or fields[0][0] != _TAG_INTEGER or fields[2][0] != _TAG_OCTET_STRING:
            raise _PayloadFormatError("malformed receipt attribute")
        attributes.append((_attribute_type(fields[0][1]), fields[2][1]))
    return attributes


def _decode_string(der: bytes) -> str:
    tag, contents, end = _read_tlv(der, 0)
    if tag not in (_TAG_UTF8_STRING, _TAG_IA5_STRING) or end != len(der):
        raise _PayloadFormatError("attribute value is not an ASN.1 string")
    if tag == _TAG_IA5_STRING:
        # IA5 is seven-bit: a byte at or above 0x80 is no IA5 character, and
        # is not read as Latin-1 either (owner, 2026-09-27).
        for octet in contents:
            if octet >= 0x80:
                raise _PayloadFormatError("IA5String attribute value is not seven-bit")
        return contents.decode("ascii")
    try:
        return contents.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _PayloadFormatError("attribute string is not valid UTF-8") from e


def _decode_integer(der: bytes) -> int:
    """An INTEGER that fits a signed 64-bit value, reported as it is,
    negative values included: the decoder reports what the receipt
    carries. Real receipts carry up to 7-byte integers; 8 bytes is the
    signed 64-bit range's own width, so nothing narrower than that range
    is ever refused here."""
    tag, contents, end = _read_tlv(der, 0)
    if tag != _TAG_INTEGER or end != len(der):
        raise _PayloadFormatError("attribute value is not an ASN.1 integer")
    if len(contents) > 8:
        raise _PayloadFormatError("attribute integer out of range")
    return _der_signed_int(contents)


def _digits(text: str, start: int, length: int) -> int:
    segment = text[start : start + length]
    if not segment.isdigit():
        return -1
    return int(segment)


_DAYS_IN_MONTH = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)


def _is_leap(year: int) -> bool:
    return year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)


def _epoch_day(year: int, month: int, day: int) -> int:
    # Days since 1970-01-01, proleptic Gregorian; matches java.time.LocalDate.
    days = 0
    if year >= 1970:
        for y in range(1970, year):
            days += 366 if _is_leap(y) else 365
    else:
        for y in range(year, 1970):
            days -= 366 if _is_leap(y) else 365
    for m in range(1, month):
        days += _DAYS_IN_MONTH[m - 1]
        if m == 2 and _is_leap(year):
            days += 1
    return days + (day - 1)


def _parse_receipt_date(text: str) -> "int | None":
    """Exactly ``YYYY-MM-DDTHH:MM:SSZ``: a four-digit year 0000-9999,
    uppercase ``T`` and ``Z``, a real calendar date, hours 00-23, minutes
    and seconds 00-59, no fraction, no offset. ``None`` when ``text`` is not
    in that form."""
    if (
        len(text) != 20
        or text[4] != "-"
        or text[7] != "-"
        or text[10] != "T"
        or text[13] != ":"
        or text[16] != ":"
        or text[19] != "Z"
    ):
        return None
    year = _digits(text, 0, 4)
    month = _digits(text, 5, 2)
    day = _digits(text, 8, 2)
    hour = _digits(text, 11, 2)
    minute = _digits(text, 14, 2)
    second = _digits(text, 17, 2)
    if year < 0 or month < 1 or month > 12 or day < 1 or hour > 23 or minute > 59 or second > 59:
        return None
    days_in_month = _DAYS_IN_MONTH[month - 1] + (1 if month == 2 and _is_leap(year) else 0)
    if day > days_in_month:
        return None
    days = _epoch_day(year, month, day)
    return ((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000


def _date(der: bytes) -> "int | None":
    """A date in an IA5String or UTF8String, as epoch milliseconds, or
    ``None`` when empty (Apple writes an unset date that way). Anything else
    that does not parse raises, and the caller keeps it raw."""
    text = _decode_string(der)
    if text == "":
        return None
    millis = _parse_receipt_date(text)
    if millis is None:
        raise _PayloadFormatError("attribute value is not a YYYY-MM-DDTHH:MM:SSZ date")
    return millis


def _decode_date_or_none(der: bytes) -> "int | None":
    try:
        return _date(der)
    except _PayloadFormatError:
        return None


def _read_creation_date(content: bytes) -> "int | None":
    """The receipt creation date (attribute 12), read the only way anything
    in a payload is read before its signer is trusted: the top-level
    attribute SET is walked shallowly, and only the value of the FIRST
    occurrence of type 12 is decoded, the same "first wins" rule the full
    parse applies to every known attribute (owner, 2026-09-27). ``None``
    means "judge the chain at the clock": no attribute 12, or a first one
    that is empty or does not decode. Never raises: nothing is trusted yet,
    so nothing here can blame anyone."""
    try:
        for attr_type, value in _parse_attribute_set(content, "receipt payload"):
            if attr_type == _ATTR_CREATION_DATE:
                return _decode_date_or_none(value)
        return None
    except Exception:
        return None


def _parse_signed_payload(content: bytes) -> ReceiptPayload:
    """The full payload parse, run only after the chain and a signature
    have passed. A trusted signer signed these bytes, so anything that
    stops the parse is the library's failure or a format Apple added, not
    the client's: UNREADABLE_PAYLOAD, never MALFORMED."""
    try:
        return _parse_payload(content)
    except Exception as e:
        raise VerificationError(
            Reason.UNREADABLE_PAYLOAD,
            f"signed receipt content could not be read: {type(e).__name__}",
        ) from e


def _parse_payload(content: bytes) -> ReceiptPayload:
    receipt_type = None
    app_item_id = None
    bundle_id = None
    bundle_id_bytes = None
    app_version = None
    opaque_value = None
    sha1_hash = None
    creation_date_ms = None
    original_purchase_date_ms = None
    original_app_version = None
    expiration_date_ms = None
    download_id = None
    version_external_identifier = None
    in_app: list[InAppPurchase] = []
    unknown: dict[int, list[bytes]] = {}
    seen: set[int] = set()

    for attr_type, value in _parse_attribute_set(content, "receipt payload"):
        if attr_type in _TOP_LEVEL_TYPES and attr_type in seen:
            unknown.setdefault(attr_type, []).append(value)
            continue
        seen.add(attr_type)
        try:
            if attr_type == _ATTR_RECEIPT_TYPE:
                receipt_type = _decode_string(value)
            elif attr_type == _ATTR_APP_ITEM_ID:
                app_item_id = _decode_integer(value)
            elif attr_type == _ATTR_ORIGINAL_PURCHASE_DATE:
                original_purchase_date_ms = _date(value)
            elif attr_type == _ATTR_BUNDLE_ID:
                bundle_id_bytes = value
                bundle_id = _decode_string(value)
            elif attr_type == _ATTR_APP_VERSION:
                app_version = _decode_string(value)
            elif attr_type == _ATTR_OPAQUE_VALUE:
                opaque_value = value
            elif attr_type == _ATTR_SHA1_HASH:
                sha1_hash = value
            elif attr_type == _ATTR_CREATION_DATE:
                creation_date_ms = _date(value)
            elif attr_type == _ATTR_DOWNLOAD_ID:
                download_id = _decode_integer(value)
            elif attr_type == _ATTR_VERSION_EXTERNAL_IDENTIFIER:
                version_external_identifier = _decode_integer(value)
            elif attr_type == _ATTR_IN_APP:
                in_app.append(_parse_in_app(value))
            elif attr_type == _ATTR_ORIGINAL_APP_VERSION:
                original_app_version = _decode_string(value)
            elif attr_type == _ATTR_EXPIRATION_DATE:
                expiration_date_ms = _date(value)
            else:
                unknown.setdefault(attr_type, []).append(value)
        except _PayloadFormatError:
            # A known attribute whose value does not decode: its typed
            # field stays null and the value is kept raw, so nothing Apple
            # signed is lost. Bundle id is the one exception: its octets
            # are already kept in bundle_id_bytes (a typed field of its
            # own, set above before the decode that failed), so the same
            # bytes are not duplicated into unknown_attributes.
            if attr_type == _ATTR_BUNDLE_ID:
                bundle_id = None
            else:
                unknown.setdefault(attr_type, []).append(value)

    return ReceiptPayload(
        receipt_type=receipt_type,
        app_item_id=app_item_id,
        bundle_id=bundle_id,
        bundle_id_bytes=bundle_id_bytes,
        application_version=app_version,
        opaque_value=opaque_value,
        sha1_hash=sha1_hash,
        receipt_creation_date_ms=creation_date_ms,
        download_id=download_id,
        version_external_identifier=version_external_identifier,
        in_app=in_app,
        original_purchase_date_ms=original_purchase_date_ms,
        original_application_version=original_app_version,
        expiration_date_ms=expiration_date_ms,
        unknown_attributes=unknown,
    )


_IAP_FIELDS: "dict[int, tuple[str, str]]" = {
    _IAP_QUANTITY: ("quantity", "int"),
    _IAP_PRODUCT_ID: ("product_id", "str"),
    _IAP_TRANSACTION_ID: ("transaction_id", "str"),
    _IAP_PURCHASE_DATE: ("purchase_date_ms", "date"),
    _IAP_ORIGINAL_TRANSACTION_ID: ("original_transaction_id", "str"),
    _IAP_ORIGINAL_PURCHASE_DATE: ("original_purchase_date_ms", "date"),
    _IAP_EXPIRES_DATE: ("expires_date_ms", "date"),
    _IAP_WEB_ORDER_LINE_ITEM_ID: ("web_order_line_item_id", "int"),
    _IAP_CANCELLATION_DATE: ("cancellation_date_ms", "date"),
    _IAP_IS_TRIAL_PERIOD: ("is_trial_period", "flag"),
    _IAP_IS_IN_INTRO_OFFER_PERIOD: ("is_in_intro_offer_period", "flag"),
}


def _parse_in_app(value: bytes) -> InAppPurchase:
    fields: dict[str, Any] = {}
    unknown: dict[int, list[bytes]] = {}
    seen: set[int] = set()
    for attr_type, attr_value in _parse_attribute_set(value, "in-app purchase attribute"):
        if attr_type in _IN_APP_TYPES and attr_type in seen:
            unknown.setdefault(attr_type, []).append(attr_value)
            continue
        seen.add(attr_type)
        spec = _IAP_FIELDS.get(attr_type)
        if spec is None:
            unknown.setdefault(attr_type, []).append(attr_value)
            continue
        name, kind = spec
        try:
            if kind == "str":
                fields[name] = _decode_string(attr_value)
            elif kind == "int":
                fields[name] = _decode_integer(attr_value)
            elif kind == "flag":
                fields[name] = _decode_integer(attr_value) != 0
            else:
                fields[name] = _date(attr_value)
        except _PayloadFormatError:
            unknown.setdefault(attr_type, []).append(attr_value)
    return InAppPurchase(unknown_attributes=unknown, **fields)


def device_hash(device_id: bytes, opaque_value: bytes, bundle_id_bytes: bytes) -> bytes:
    """SHA-1(``device_id`` + ``opaque_value`` + ``bundle_id_bytes``), the
    device-hash formula Apple's on-device check uses. Compare with
    :attr:`~.receipt_payload.ReceiptPayload.sha1_hash`. Not called by
    verification itself; the caller applies it (docs/design/0.7-api.md
    drops the built-in device-hash check)."""
    return hashlib.sha1(device_id + opaque_value + bundle_id_bytes).digest()
