"""Offline verification of legacy PKCS#7 app receipts against the pinned
Apple Inc. Root CA — the server-side port of Apple's "Validating receipts
on the device" procedure (PLAN.md §2.2), mirroring the Java implementation.

CMS parsing uses ``asn1crypto`` (BER-capable — genuine Apple/Xcode receipts
use indefinite lengths); the receipt payload itself is parsed with a small
strict DER reader below."""

import hashlib
import hmac
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Any, Optional

from asn1crypto import cms as asn1cms
from asn1crypto import core as asn1core
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._chain import as_utc, build_and_validate_path
from ._receipt_base64 import decode_receipt_base64
from .exceptions import Reason, VerificationError

# Apple marker OID on the receipt-signing leaf. The chain check alone does not
# distinguish signer purpose: developer certs chain through the same WWDR
# intermediate to the same pinned root, so this OID must be required too.
_RECEIPT_SIGNER_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.11.1")

# Every embedded certificate is loaded and offered to path building before
# anything about the receipt has been verified, and each one whose subject
# matches an issuer name in the chain costs a full RSA signature check there.
# Genuine receipts carry 1 to 3 (fixtures/public-receipts: 1, 3, 3), and
# _chain.py walks at most 6 of them, so 10 is well clear of any real receipt
# while bounding the flood: 56 decoy certificates in 44 KB measured at 4.4 ms
# and 224 in 163 KB at 21 ms, against 1.3 ms for the genuine receipt they were
# spliced into. A caller-side size limit cannot bound this on its own — the
# genuine legacy receipt under fixtures/public-receipts is 79,104 bytes, so any
# cap that admits it admits ~90 decoys too.
_MAX_EMBEDDED_CERTIFICATES = 10

# Only the digests Apple uses for receipts (SHA-1 / SHA-256), matching the
# other three implementations; anything else is rejected.
_DIGESTS = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
}

# Receipt attribute types — Apple, "Validating receipts on the device",
# plus two community-established ones (0: receipt type, 18: original
# purchase date) needed for verifyReceipt response compatibility.
_ATTR_RECEIPT_TYPE = 0
_ATTR_ORIGINAL_PURCHASE_DATE = 18
_ATTR_BUNDLE_ID = 2
_ATTR_APP_VERSION = 3
_ATTR_OPAQUE_VALUE = 4
_ATTR_SHA1_HASH = 5
_ATTR_CREATION_DATE = 12
_ATTR_IN_APP = 17
_ATTR_ORIGINAL_APP_VERSION = 19
_ATTR_EXPIRATION_DATE = 21

_IAP_FIELDS = {
    1701: ("quantity", "int"),
    1702: ("product_id", "str"),
    1703: ("transaction_id", "str"),
    1704: ("purchase_date", "date"),
    1705: ("original_transaction_id", "str"),
    1706: ("original_purchase_date", "date"),
    1708: ("expires_date", "date"),
    1711: ("web_order_line_item_id", "int"),
    1712: ("cancellation_date", "date"),
    1719: ("is_in_intro_offer_period", "int"),
}


class InAppPurchase:
    """One in-app purchase from the receipt (attribute 17)."""

    def __init__(self) -> None:
        #: Raw unmodeled attributes by type — forward compatibility (PLAN D10).
        self.unknown_attributes: dict[int, list[bytes]] = {}
        self.quantity: Optional[int] = None
        self.product_id: Optional[str] = None
        self.transaction_id: Optional[str] = None
        self.original_transaction_id: Optional[str] = None
        self.purchase_date: Optional[datetime] = None
        self.original_purchase_date: Optional[datetime] = None
        self.expires_date: Optional[datetime] = None
        self.cancellation_date: Optional[datetime] = None
        self.web_order_line_item_id: Optional[int] = None
        self.is_in_intro_offer_period: Optional[int] = None


class AppReceipt:
    """A verified legacy app receipt. Only receipts returned by
    :class:`ReceiptVerifier` should be trusted."""

    def __init__(self) -> None:
        #: Raw values of attribute types this library does not model, keyed
        #: by type — forward compatibility for fields Apple may add (PLAN
        #: D10). Values are raw octet-string contents, verified but undecoded.
        self.unknown_attributes: dict[int, list[bytes]] = {}
        self.receipt_type: Optional[str] = None
        self.original_purchase_date: Optional[datetime] = None
        self.bundle_id: Optional[str] = None
        self.bundle_id_bytes: Optional[bytes] = None
        self.app_version: Optional[str] = None
        self.opaque_value: Optional[bytes] = None
        self.sha1_hash: Optional[bytes] = None
        self.creation_date: Optional[datetime] = None
        self.original_app_version: Optional[str] = None
        self.expiration_date: Optional[datetime] = None
        self.in_app_purchases: list[InAppPurchase] = []


class ReceiptVerifier:
    """Thread-safe once constructed.

    :param trusted_roots: pinned roots
        (production: :func:`apple_purchase_receipt_verifier.apple_receipt_roots`)
    :param bundle_id: the app's bundle id the receipt must carry
    """

    def __init__(self, trusted_roots: "Iterable[x509.Certificate]", bundle_id: str) -> None:
        roots = list(trusted_roots)
        if not roots:
            raise ValueError("trusted_roots must not be empty")
        if not bundle_id:
            raise ValueError("bundle_id is required")
        self._roots = roots
        self._bundle_id = bundle_id

    def verify(self, receipt: "bytes | str", device_guid: "bytes | None" = None) -> "AppReceipt":
        """Verifies a receipt (DER ``bytes``, or its base64 string — the
        usual client transport form). Passing ``device_guid`` additionally
        enforces the device-hash binding: SHA1(guid ‖ opaqueValue ‖
        bundleIdBytes) must equal attribute 5 (optional — PLAN.md D4)."""
        der = decode_receipt_base64(receipt) if isinstance(receipt, str) else receipt
        fields = verify_receipt_core(der, self._roots)
        if fields.bundle_id != self._bundle_id:
            raise VerificationError(
                Reason.WRONG_BUNDLE_ID,
                f"expected {self._bundle_id} but receipt has {fields.bundle_id}",
            )
        if device_guid is not None:
            _verify_device_hash(fields, device_guid)
        return fields


def verify_receipt_core(der: bytes, trusted_roots: "Iterable[x509.Certificate]") -> "AppReceipt":
    """Chain + signature verification WITHOUT the bundle-id claim check —
    the primitive under both :class:`ReceiptVerifier` and the
    verifyReceipt-compat endpoint (which, like Apple's endpoint, accepts any
    bundle). Callers that unlock products must check ``bundle_id``
    themselves or use :class:`ReceiptVerifier`."""
    roots = list(trusted_roots)
    if not roots:
        raise ValueError("trusted_roots must not be empty")
    if not der:
        raise VerificationError(Reason.INVALID_RECEIPT_FORMAT, "receipt is empty")

    # asn1crypto and cryptography report malformed input with whatever the
    # failing layer happens to raise, and which exceptions those are is neither
    # documented nor stable, so hostile bytes are contained by category rather
    # than by type. Guarding individual call sites was tried first and missed
    # four of them: fuzzing a genuine receipt still leaked UnsupportedAlgorithm
    # and ValueError out of chain building and signer parsing.
    try:
        return _verify_receipt_core_unguarded(der, roots)
    except VerificationError:
        raise
    except Exception as e:
        raise VerificationError(Reason.INVALID_RECEIPT_FORMAT, f"malformed receipt: {e}") from e


def _verify_receipt_core_unguarded(der: bytes, roots: "list[x509.Certificate]") -> "AppReceipt":
    content, certificates, signer, unreadable = _parse_cms(der)

    # Parsed before signature verification only to learn the creation
    # date (chain validity anchors at signing time); nothing from it is
    # trusted until the chain + signature checks pass.
    fields = _parse_payload(content)
    # No clock seam here, deliberately: this path has no verdict that moves
    # with the current time. The chain window is anchored at the receipt
    # creation date, and the system-clock fallback below only fires for a
    # receipt carrying no creation date at all — a certificate-validity
    # judgement, which an injected clock must not be able to shift.
    at = fields.creation_date if fields.creation_date is not None else as_utc(time.time() * 1000)

    signer_cert = _find_signer_cert(certificates, signer, unreadable)
    # Everything cryptography's loader lets past that the checks below
    # assume, settled while the verdict is still "this is not a
    # certificate": the extension block, which is decoded lazily so one
    # malformed extension VALUE surfaces later as a chain failure, and the
    # public key, whose curve this build may not implement. Both are the
    # receipt-path twins of what the JWS path settles for an x5c entry.
    try:
        signer_cert.public_key()
        _ = signer_cert.extensions
    except Exception as e:
        raise VerificationError(
            Reason.INVALID_CERTIFICATE,
            f"receipt signer certificate is not a valid certificate: {e}",
        ) from e
    build_and_validate_path(signer_cert, [c for _, c in certificates], roots, at)
    try:
        signer_cert.extensions.get_extension_for_oid(_RECEIPT_SIGNER_OID)
    except x509.ExtensionNotFound as e:
        raise VerificationError(
            Reason.INVALID_CERTIFICATE_PURPOSE,
            "receipt signer certificate lacks Apple receipt-signing marker OID "
            f"{_RECEIPT_SIGNER_OID.dotted_string}",
        ) from e
    _verify_cms_signature(content, signer, signer_cert)
    return fields


def _parse_cms(
    der: bytes,
) -> "tuple[bytes, list[tuple[bytes, x509.Certificate]], Any, Optional[Exception]]":
    try:
        info = asn1cms.ContentInfo.load(der, strict=True)  # rejects trailing bytes (PLAN 2.3)
        if info["content_type"].native != "signed_data":
            raise ValueError("not CMS SignedData")
        signed_data = info["content"]
        content = signed_data["encap_content_info"]["content"].native
        if not isinstance(content, bytes):
            raise ValueError("no encapsulated payload")
        embedded = signed_data["certificates"] or []
        if len(embedded) > _MAX_EMBEDDED_CERTIFICATES:
            raise VerificationError(
                Reason.INVALID_CHAIN,
                f"receipt embeds {len(embedded)} certificates, more than the "
                f"{_MAX_EMBEDDED_CERTIFICATES} a chain can hold",
            )
        # An entry that will not load is held rather than raised, because
        # WHICH entry it is changes the verdict: a stranger the receipt
        # merely carries is a defect of the receipt, while the SIGNER being
        # unreadable is a defect of a certificate and gets the verdict an
        # unreadable x5c entry gets on the JWS path. Naming the signer needs
        # the readable entries matched against the SignerInfo first.
        certificates = []
        unreadable: Optional[Exception] = None
        for choice in embedded:
            raw = choice.chosen.dump()
            try:
                certificates.append((raw, x509.load_der_x509_certificate(raw)))
            except Exception as e:  # re-raised by _find_signer_cert
                if unreadable is None:
                    unreadable = e
        signer_infos = signed_data["signer_infos"]
        if len(signer_infos) == 0:
            raise ValueError("no signer info")
        return content, certificates, signer_infos[0], unreadable
    except VerificationError:
        raise
    except Exception as e:  # asn1crypto raises broadly on malformed input
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, f"not a parseable PKCS#7 receipt: {e}"
        ) from e


def _find_signer_cert(
    certificates: "list[tuple[bytes, x509.Certificate]]",
    signer: Any,
    unreadable: Optional[Exception] = None,
) -> x509.Certificate:
    sid = signer["sid"].chosen
    try:
        wanted_serial = sid["serial_number"].native
        wanted_issuer = sid["issuer"].dump()
    except Exception as e:
        raise VerificationError(Reason.INVALID_RECEIPT_FORMAT, "malformed signer id") from e
    for raw, cert in certificates:
        if cert.serial_number == wanted_serial:
            asn1_cert = asn1x509.Certificate.load(raw)
            if asn1_cert["tbs_certificate"]["issuer"].dump() == wanted_issuer:
                if unreadable is not None:
                    raise VerificationError(
                        Reason.INVALID_RECEIPT_FORMAT,
                        f"not a parseable PKCS#7 receipt: {unreadable}",
                    ) from unreadable
                return cert
    if unreadable is not None:
        raise VerificationError(
            Reason.INVALID_CERTIFICATE,
            "the receipt's signer certificate is not among the embedded "
            f"certificates that could be read: {unreadable}",
        ) from unreadable
    raise VerificationError(Reason.INVALID_RECEIPT_FORMAT, "signer certificate not embedded")


def _verify_cms_signature(content: bytes, signer: Any, signer_cert: x509.Certificate) -> None:
    try:
        digest_name = signer["digest_algorithm"]["algorithm"].native
        signature = signer["signature"].native
    except Exception as e:  # attacker-chosen tags, decoded before the signature check
        raise VerificationError(Reason.INVALID_RECEIPT_FORMAT, "malformed signer info") from e
    digest_cls = _DIGESTS.get(digest_name)
    if digest_cls is None:
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, f"unsupported digest algorithm {digest_name}"
        )
    public_key = signer_cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise VerificationError(Reason.INVALID_SIGNATURE, "signer key is not RSA")
    signed_attrs = signer["signed_attrs"]
    if isinstance(signed_attrs, asn1core.Void):
        data = content
    else:
        data = _signed_attrs_to_sign(signed_attrs, digest_name, content)
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), digest_cls())
    except InvalidSignature as e:
        raise VerificationError(Reason.INVALID_SIGNATURE, "CMS signature check failed") from e


def _signed_attrs_to_sign(signed_attrs: Any, digest_name: str, content: bytes) -> bytes:
    """The bytes the signature must cover when signedAttrs are present. Their
    OIDs, types and nesting are attacker-chosen and are decoded here, before
    the signature check that would reject them, so every decoding failure has
    to surface as a format error instead of escaping verify() raw."""
    try:
        content_digest = hashlib.new(digest_name, content).digest()
        message_digest = None
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                values = attr["values"]
                if len(values) != 1:  # RFC 5652 §5.3: exactly one value
                    raise VerificationError(
                        Reason.INVALID_RECEIPT_FORMAT,
                        "messageDigest attribute must carry exactly one value",
                    )
                message_digest = values[0].native
        if message_digest is None or not hmac.compare_digest(message_digest, content_digest):
            raise VerificationError(
                Reason.INVALID_SIGNATURE, "messageDigest attribute does not match content"
            )
        # Signature covers the signedAttrs re-encoded as an explicit SET
        # (RFC 5652 §5.4): swap the IMPLICIT [0] tag for SET.
        raw: bytes = signed_attrs.dump()
        return b"\x31" + raw[1:]
    except VerificationError:
        raise
    except Exception as e:  # asn1crypto raises broadly on malformed input
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, f"unparseable signed attributes: {e}"
        ) from e


def _verify_device_hash(fields: AppReceipt, device_guid: bytes) -> None:
    if fields.opaque_value is None or fields.sha1_hash is None or fields.bundle_id_bytes is None:
        raise VerificationError(
            Reason.DEVICE_HASH_MISMATCH,
            "receipt lacks the attributes needed for the device-hash check",
        )
    computed = hashlib.sha1(device_guid + fields.opaque_value + fields.bundle_id_bytes).digest()
    if not hmac.compare_digest(computed, fields.sha1_hash):
        raise VerificationError(
            Reason.DEVICE_HASH_MISMATCH, "computed device hash does not match attribute 5"
        )


# --- strict DER reader for the receipt payload ---------------------------

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_UTF8_STRING = 0x0C
_TAG_IA5_STRING = 0x16
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31


def _fmt_error(message: str) -> VerificationError:
    return VerificationError(Reason.INVALID_RECEIPT_FORMAT, message)


def _read_tlv(data: bytes, offset: int) -> "tuple[int, bytes, int]":
    if offset + 2 > len(data):
        raise _fmt_error("truncated ASN.1 value")
    tag = data[offset]
    pos = offset + 1
    length = data[pos]
    pos += 1
    if length >= 0x80:
        count = length & 0x7F
        if count == 0 or count > 4 or pos + count > len(data):
            raise _fmt_error("unsupported ASN.1 length")
        length = int.from_bytes(data[pos : pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise _fmt_error("ASN.1 length exceeds input")
    return tag, data[pos:end], end


def _children(contents: bytes) -> "list[tuple[int, bytes]]":
    out = []
    pos = 0
    while pos < len(contents):
        tag, value, pos = _read_tlv(contents, pos)
        out.append((tag, value))
    return out


def _parse_attribute_set(der: bytes, what: str) -> "list[tuple[int, bytes]]":
    tag, contents, end = _read_tlv(der, 0)
    if tag == _TAG_OCTET_STRING and end == len(der):
        # Xcode receipts double-wrap the payload in an extra OCTET STRING.
        der = contents
        tag, contents, end = _read_tlv(der, 0)
    if tag != _TAG_SET or end != len(der):
        raise _fmt_error(f"{what} is not an ASN.1 SET")
    attributes = []
    for child_tag, child_value in _children(contents):
        if child_tag != _TAG_SEQUENCE:
            raise _fmt_error("malformed receipt attribute")
        fields = _children(child_value)
        if len(fields) < 3 or fields[0][0] != _TAG_INTEGER or fields[2][0] != _TAG_OCTET_STRING:
            raise _fmt_error("malformed receipt attribute")
        attributes.append((_attribute_type(fields[0][1]), fields[2][1]))
    return attributes


# Attribute *types* are a 32-bit signed space: every type Apple has ever
# issued is a small number, and a value above 2^31-1 cannot be represented by
# ports whose attribute-type field is an int. Mapping such a type onto a
# sentinel (-1) and filing it under unknown_attributes would let two ports
# disagree about what the same receipt says, so an unrepresentable type is a
# malformed receipt in every port. Attribute *values* keep the wider range
# _int_value allows: web_order_line_item_id is genuinely a 7-byte integer.
_MAX_ATTRIBUTE_TYPE = 2147483647


def _attribute_type(contents: bytes) -> int:
    value = _int_value(contents)
    if value > _MAX_ATTRIBUTE_TYPE:
        raise _fmt_error(f"receipt attribute type {value} exceeds the 32-bit signed range")
    return value


def _int_value(contents: bytes) -> int:
    # 8-byte cap: real receipts carry 7-byte integers (web_order_line_item_id).
    if len(contents) > 8:
        raise _fmt_error("attribute integer out of range")
    if contents and contents[0] >= 0x80:
        raise _fmt_error("negative receipt integer")
    return int.from_bytes(contents, "big")


def _decode_string(der: bytes) -> str:
    tag, contents, end = _read_tlv(der, 0)
    if tag not in (_TAG_UTF8_STRING, _TAG_IA5_STRING) or end != len(der):
        raise _fmt_error("attribute value is not an ASN.1 string")
    try:
        return contents.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _fmt_error("attribute string is not valid UTF-8") from e


def _decode_integer(der: bytes) -> int:
    tag, contents, end = _read_tlv(der, 0)
    if tag != _TAG_INTEGER or end != len(der):
        raise _fmt_error("attribute value is not an ASN.1 integer")
    return _int_value(contents)


def _decode_date(der: bytes) -> Optional[datetime]:
    """RFC 3339 date in an IA5String; empty means absent (real receipts do this)."""
    text = _decode_string(der)
    if text == "":
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            # Assuming a zone would read the date as the server's local time,
            # so the same receipt would anchor chain validity up to 26 hours
            # apart on two hosts. Apple always emits a designator, and the
            # Java and Swift implementations reject a date without one.
            raise ValueError("no timezone designator")
        # astimezone() raises OverflowError — an ArithmeticError, not a
        # ValueError — for offsets that push the value past datetime.min/max.
        return parsed.astimezone(timezone.utc)
    except (ValueError, OverflowError) as e:
        raise _fmt_error(f"unparseable receipt date: {text}") from e


def _parse_payload(content: bytes) -> AppReceipt:
    receipt = AppReceipt()
    for attr_type, value in _parse_attribute_set(content, "receipt payload"):
        if attr_type == _ATTR_RECEIPT_TYPE:
            receipt.receipt_type = _decode_string(value)
        elif attr_type == _ATTR_ORIGINAL_PURCHASE_DATE:
            receipt.original_purchase_date = _decode_date(value)
        elif attr_type == _ATTR_BUNDLE_ID:
            receipt.bundle_id = _decode_string(value)
            receipt.bundle_id_bytes = value
        elif attr_type == _ATTR_APP_VERSION:
            receipt.app_version = _decode_string(value)
        elif attr_type == _ATTR_OPAQUE_VALUE:
            receipt.opaque_value = value
        elif attr_type == _ATTR_SHA1_HASH:
            receipt.sha1_hash = value
        elif attr_type == _ATTR_CREATION_DATE:
            receipt.creation_date = _decode_date(value)
        elif attr_type == _ATTR_IN_APP:
            receipt.in_app_purchases.append(_parse_in_app(value))
        elif attr_type == _ATTR_ORIGINAL_APP_VERSION:
            receipt.original_app_version = _decode_string(value)
        elif attr_type == _ATTR_EXPIRATION_DATE:
            receipt.expiration_date = _decode_date(value)
        else:
            receipt.unknown_attributes.setdefault(attr_type, []).append(value)
    return receipt


def _parse_in_app(value: bytes) -> InAppPurchase:
    purchase = InAppPurchase()
    for attr_type, attr_value in _parse_attribute_set(value, "in-app purchase attribute"):
        spec = _IAP_FIELDS.get(attr_type)
        if spec is None:
            purchase.unknown_attributes.setdefault(attr_type, []).append(attr_value)
            continue
        name, kind = spec
        if kind == "str":
            setattr(purchase, name, _decode_string(attr_value))
        elif kind == "int":
            setattr(purchase, name, _decode_integer(attr_value))
        else:
            setattr(purchase, name, _decode_date(attr_value))
    return purchase
