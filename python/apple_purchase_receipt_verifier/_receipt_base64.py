"""Decoder for the base64 *string* a client hands to the receipt string entry
points — :meth:`ReceiptVerifier.verify` and the verifyReceipt endpoint's
``receipt-data`` — used by :mod:`receipt` and :mod:`verify_receipt_endpoint`.

The rule is the one Apple's verifyReceipt applies, measured on 2026-09-23
against production and sandbox with genuine receipts
(``docs/evidence/2026-09-23-verifyreceipt-base64.md``): non-empty standard
base64 (``[A-Za-z0-9+/]``) with exactly the canonical ``=`` padding for its
length, and nothing else. Whitespace anywhere, base64url, omitted or extra
padding and anything after the padding are ``INVALID_RECEIPT_FORMAT``. Unused
low bits in the last data character are accepted, as Apple accepts them."""

import base64
import re

from .exceptions import Reason, VerificationError

_SHAPE = re.compile(r"[A-Za-z0-9+/]*={0,2}")


def decode_receipt_base64(text: str) -> bytes:
    """Decodes a receipt-data string under the rule above, or raises
    :class:`VerificationError` (``INVALID_RECEIPT_FORMAT``)."""
    try:
        return decode_canonical_base64(text)
    except ValueError as e:
        raise VerificationError(
            Reason.INVALID_RECEIPT_FORMAT, "receipt is not canonically padded standard base64"
        ) from e


def decode_canonical_base64(text: str) -> bytes:
    """The rule above as a plain decoder, raising ``ValueError``. An x5c entry
    is held to it too (:mod:`jws`), with its own verdict.

    ``b64decode(validate=True)`` checks the alphabet but not the padding
    count on every supported Python. Measured on 3.10 to 3.13: 3.10 accepts
    ``==``, ``AAA==``, ``AAAA=`` and ``AAAA==``; 3.11 and 3.12 accept
    ``AAAA=`` and ``AAAA==``; all of them decode ``""`` to nothing. So the
    shape and a length that is a non-zero multiple of four are checked
    first; together they leave only the canonical padding, and the stdlib
    decoder does the rest."""
    if not text or len(text) % 4 != 0 or _SHAPE.fullmatch(text) is None:
        raise ValueError("not canonically padded standard base64")
    return base64.b64decode(text, validate=True)
