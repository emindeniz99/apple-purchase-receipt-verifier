"""Strict decoder for the base64 *string* a client hands to the receipt
string entry points — :meth:`ReceiptVerifier.verify` and the verifyReceipt
endpoint's ``receipt-data`` — used by :mod:`receipt` and
:mod:`verify_receipt_endpoint`.

Rule, adjudicated from Apple's docs (fixtures/cases.json, the "Receipt
base64" paragraph of ``comment``): receipt-data is Base64 as defined in
RFC 4648, and Foundation's ``base64EncodedString(options:)`` can emit the
standard (``+``/``/``) or base64url (``-``/``_``) alphabet, with or without
padding, with CR/LF line endings at 64 or 76 columns. So this ACCEPTS
either alphabet (not mixed), padding present or omitted, and whitespace
(CR, LF, space, tab) anywhere — stripped before anything else is checked.
It REJECTS: any other character; both alphabets in one string; anything
but whitespace after the padding; a stripped length that is 1 mod 4
(impossible for base64); and an empty or whitespace-only string.

No canonical-trailing-bits check: unlike the JWS segment decoder
(:func:`apple_purchase_receipt_verifier.jws._b64url`), Apple's own encoder
is not the only source a receipt-data string can come from, and the rule
above does not ask for one."""

import base64
import binascii
import re

from .exceptions import Reason, VerificationError

#: CR, LF, space, tab — accepted anywhere in the input, stripped first.
_WHITESPACE_RE = re.compile(r"[ \t\r\n]+")
_STANDARD_CORE_RE = re.compile(r"^[A-Za-z0-9+/]*$")
_URLSAFE_CORE_RE = re.compile(r"^[A-Za-z0-9_-]*$")
_URLSAFE_TO_STANDARD = str.maketrans({"-": "+", "_": "/"})


def decode_receipt_base64(text: str) -> bytes:
    """Decodes a receipt-data string under the accept/reject rule above.

    Raises :class:`VerificationError` (``INVALID_RECEIPT_FORMAT``) rather
    than any ``binascii``/``ValueError`` — every rejection this function
    makes is a client-format problem, not a library bug."""
    body = _WHITESPACE_RE.sub("", text)
    if not body:
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, "receipt is empty or whitespace-only"
        )
    if len(body) % 4 == 1:
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, "receipt has a base64-impossible length"
        )

    pad_at = body.find("=")
    core, tail = (body, "") if pad_at == -1 else (body[:pad_at], body[pad_at:])
    if any(ch != "=" for ch in tail):
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, "receipt has data after its base64 padding"
        )

    has_standard = "+" in core or "/" in core
    has_urlsafe = "-" in core or "_" in core
    if has_standard and has_urlsafe:
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT,
            "receipt mixes the standard and base64url alphabets",
        )
    core_re = _URLSAFE_CORE_RE if has_urlsafe else _STANDARD_CORE_RE
    if core_re.match(core) is None:
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, "receipt contains a character outside base64"
        )

    standard_core = core.translate(_URLSAFE_TO_STANDARD)
    padded = standard_core + "=" * (-len(standard_core) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError) as e:
        raise VerificationError(Reason.INVALID_RECEIPT_FORMAT, "receipt is not valid base64") from e
