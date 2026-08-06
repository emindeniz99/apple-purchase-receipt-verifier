"""Offline verification of legacy PKCS#7 app receipts against the pinned
Apple Inc. Root CA — the server-side port of Apple's "Validating receipts
on the device" procedure (PLAN.md §2.2), mirroring the Java implementation.

CMS parsing uses ``asn1crypto`` (BER-capable — genuine Apple/Xcode receipts
use indefinite lengths); the receipt payload itself is parsed with a small
strict DER reader below."""

import base64
import binascii
import hashlib
import hmac
import time
from datetime import datetime, timezone

from asn1crypto import cms as asn1cms
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from ._chain import as_utc, build_and_validate_path
from .exceptions import Reason, VerificationError

# Apple marker OID on the receipt-signing leaf. The chain check alone does not
# distinguish signer purpose: developer certs chain through the same WWDR
# intermediate to the same pinned root, so this OID must be required too.
_RECEIPT_SIGNER_OID = x509.ObjectIdentifier("1.2.840.113635.100.6.11.1")

_DIGESTS = {
    "sha1": hashes.SHA1,
    "sha256": hashes.SHA256,
    "sha384": hashes.SHA384,
    "sha512": hashes.SHA512,
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

    def __init__(self):
        #: Raw unmodeled attributes by type — forward compatibility (PLAN D10).
        self.unknown_attributes = {}
        self.quantity = None
        self.product_id = None
        self.transaction_id = None
        self.original_transaction_id = None
        self.purchase_date = None
        self.original_purchase_date = None
        self.expires_date = None
        self.cancellation_date = None
        self.web_order_line_item_id = None
        self.is_in_intro_offer_period = None


class AppReceipt:
    """A verified legacy app receipt. Only receipts returned by
    :class:`ReceiptVerifier` should be trusted."""

    def __init__(self):
        #: Raw values of attribute types this library does not model, keyed
        #: by type — forward compatibility for fields Apple may add (PLAN
        #: D10). Values are raw octet-string contents, verified but undecoded.
        self.unknown_attributes = {}
        self.receipt_type = None
        self.original_purchase_date = None
        self.bundle_id = None
        self.bundle_id_bytes = None
        self.app_version = None
        self.opaque_value = None
        self.sha1_hash = None
        self.creation_date = None
        self.original_app_version = None
        self.expiration_date = None
        self.in_app_purchases = []


class ReceiptVerifier:
    """Thread-safe once constructed.

    :param trusted_roots: pinned roots
        (production: :func:`apple_purchase_verifier.apple_receipt_roots`)
    :param bundle_id: the app's bundle id the receipt must carry
    """

    def __init__(self, trusted_roots, bundle_id):
        roots = list(trusted_roots)
        if not roots:
            raise ValueError("trusted_roots must not be empty")
        if not bundle_id:
            raise ValueError("bundle_id is required")
        self._roots = roots
        self._bundle_id = bundle_id

    def verify(self, receipt: "bytes | str",
               device_guid: "bytes | None" = None) -> "AppReceipt":
        """Verifies a receipt (DER ``bytes``, or its base64 string — the
        usual client transport form). Passing ``device_guid`` additionally
        enforces the device-hash binding: SHA1(guid ‖ opaqueValue ‖
        bundleIdBytes) must equal attribute 5 (optional — PLAN.md D4)."""
        if isinstance(receipt, str):
            try:
                der = base64.b64decode(receipt)
            except (binascii.Error, ValueError) as e:
                raise VerificationError(
                    Reason.INVALID_RECEIPT_FORMAT, "receipt is not valid base64") from e
        else:
            der = receipt
        fields = verify_receipt_core(der, self._roots)
        if fields.bundle_id != self._bundle_id:
            raise VerificationError(
                Reason.WRONG_BUNDLE_ID,
                f"expected {self._bundle_id} but receipt has {fields.bundle_id}")
        if device_guid is not None:
            _verify_device_hash(fields, device_guid)
        return fields


def verify_receipt_core(der: bytes, trusted_roots) -> "AppReceipt":
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

    content, certificates, signer = _parse_cms(der)

    # Parsed before signature verification only to learn the creation
    # date (chain validity anchors at signing time); nothing from it is
    # trusted until the chain + signature checks pass.
    fields = _parse_payload(content)
    at = fields.creation_date if fields.creation_date is not None \
        else as_utc(time.time() * 1000)

    signer_cert = _find_signer_cert(certificates, signer)
    build_and_validate_path(signer_cert, [c for _, c in certificates], roots, at)
    try:
        signer_cert.extensions.get_extension_for_oid(_RECEIPT_SIGNER_OID)
    except x509.ExtensionNotFound:
        raise VerificationError(
            Reason.INVALID_CERTIFICATE_PURPOSE,
            "receipt signer certificate lacks Apple receipt-signing marker OID "
            f"{_RECEIPT_SIGNER_OID.dotted_string}")
    _verify_cms_signature(content, signer, signer_cert)
    return fields


def _parse_cms(der):
    try:
        info = asn1cms.ContentInfo.load(der, strict=True)  # rejects trailing bytes (PLAN 2.3)
        if info["content_type"].native != "signed_data":
            raise ValueError("not CMS SignedData")
        signed_data = info["content"]
        content = signed_data["encap_content_info"]["content"].native
        if not isinstance(content, bytes):
            raise ValueError("no encapsulated payload")
        certificates = []
        for choice in signed_data["certificates"] or []:
            raw = choice.chosen.dump()
            certificates.append((raw, x509.load_der_x509_certificate(raw)))
        signer_infos = signed_data["signer_infos"]
        if len(signer_infos) == 0:
            raise ValueError("no signer info")
        return content, certificates, signer_infos[0]
    except VerificationError:
        raise
    except Exception as e:  # asn1crypto raises broadly on malformed input
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, f"not a parseable PKCS#7 receipt: {e}") from e


def _find_signer_cert(certificates, signer):
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
                return cert
    raise VerificationError(Reason.INVALID_RECEIPT_FORMAT, "signer certificate not embedded")


def _verify_cms_signature(content, signer, signer_cert):
    digest_name = signer["digest_algorithm"]["algorithm"].native
    digest_cls = _DIGESTS.get(digest_name)
    if digest_cls is None:
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, f"unsupported digest algorithm {digest_name}")
    public_key = signer_cert.public_key()
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise VerificationError(Reason.INVALID_SIGNATURE, "signer key is not RSA")
    signature = signer["signature"].native
    signed_attrs = signer["signed_attrs"]
    if signed_attrs.native is not None:
        content_digest = hashlib.new(digest_name, content).digest()
        message_digest = None
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                message_digest = attr["values"][0].native
        if message_digest is None or not hmac.compare_digest(message_digest, content_digest):
            raise VerificationError(
                Reason.INVALID_SIGNATURE, "messageDigest attribute does not match content")
        # Signature covers the signedAttrs re-encoded as an explicit SET
        # (RFC 5652 §5.4): swap the IMPLICIT [0] tag for SET.
        raw = signed_attrs.dump()
        data = b"\x31" + raw[1:]
    else:
        data = content
    try:
        public_key.verify(signature, data, padding.PKCS1v15(), digest_cls())
    except InvalidSignature as e:
        raise VerificationError(Reason.INVALID_SIGNATURE, "CMS signature check failed") from e


def _verify_device_hash(fields, device_guid):
    if fields.opaque_value is None or fields.sha1_hash is None or fields.bundle_id_bytes is None:
        raise VerificationError(
            Reason.DEVICE_HASH_MISMATCH,
            "receipt lacks the attributes needed for the device-hash check")
    computed = hashlib.sha1(
        device_guid + fields.opaque_value + fields.bundle_id_bytes).digest()
    if not hmac.compare_digest(computed, fields.sha1_hash):
        raise VerificationError(
            Reason.DEVICE_HASH_MISMATCH, "computed device hash does not match attribute 5")


# --- strict DER reader for the receipt payload ---------------------------

_TAG_INTEGER = 0x02
_TAG_OCTET_STRING = 0x04
_TAG_UTF8_STRING = 0x0C
_TAG_IA5_STRING = 0x16
_TAG_SEQUENCE = 0x30
_TAG_SET = 0x31


def _fmt_error(message):
    return VerificationError(Reason.INVALID_RECEIPT_FORMAT, message)


def _read_tlv(data, offset):
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
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    end = pos + length
    if end > len(data):
        raise _fmt_error("ASN.1 length exceeds input")
    return tag, data[pos:end], end


def _children(contents):
    out = []
    pos = 0
    while pos < len(contents):
        tag, value, pos = _read_tlv(contents, pos)
        out.append((tag, value))
    return out


def _parse_attribute_set(der, what):
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
        attributes.append((_int_value(fields[0][1]), fields[2][1]))
    return attributes


def _int_value(contents):
    # 8-byte cap: real receipts carry 7-byte integers (web_order_line_item_id).
    if len(contents) > 8:
        raise _fmt_error("attribute integer out of range")
    if contents and contents[0] >= 0x80:
        raise _fmt_error("negative receipt integer")
    return int.from_bytes(contents, "big")


def _decode_string(der):
    tag, contents, end = _read_tlv(der, 0)
    if tag not in (_TAG_UTF8_STRING, _TAG_IA5_STRING) or end != len(der):
        raise _fmt_error("attribute value is not an ASN.1 string")
    try:
        return contents.decode("utf-8")
    except UnicodeDecodeError as e:
        raise _fmt_error("attribute string is not valid UTF-8") from e


def _decode_integer(der):
    tag, contents, end = _read_tlv(der, 0)
    if tag != _TAG_INTEGER or end != len(der):
        raise _fmt_error("attribute value is not an ASN.1 integer")
    return _int_value(contents)


def _decode_date(der):
    """RFC 3339 date in an IA5String; empty means absent (real receipts do this)."""
    text = _decode_string(der)
    if text == "":
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError as e:
        raise _fmt_error(f"unparseable receipt date: {text}") from e


def _parse_payload(content):
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


def _parse_in_app(value):
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
