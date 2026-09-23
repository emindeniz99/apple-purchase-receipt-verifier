"""The receipt-data base64 rule, spelling by spelling.

``decode_receipt_base64`` must answer what Apple's verifyReceipt answered on
2026-09-23 for the same spellings of genuine receipts
(docs/evidence/2026-09-23-verifyreceipt-base64.md). A spelling Apple decodes
must decode here to the same bytes; a spelling Apple answers 21002 must be
INVALID_RECEIPT_FORMAT here, or a receipt verifies in this library that Apple
itself refuses. The conformance cases pin the rule on a real receipt; this
pins each shape on its own, including the ones ``b64decode(validate=True)``
alone would have accepted.
"""

import base64
import binascii
import sys
import unittest

from apple_purchase_receipt_verifier._receipt_base64 import decode_receipt_base64
from apple_purchase_receipt_verifier.exceptions import Reason, VerificationError

ACCEPTED = {
    "QUJD": b"ABC",
    "QUI=": b"AB",
    "QQ==": b"A",
    "+/8=": b"\xfb\xff",
    # Unused low bits set in the last data character: Apple accepts them.
    "QR==": b"A",
    "Qf==": b"A",
    "QUJ=": b"AB",
}

#: Every spelling here got 21002 from Apple, or is one of the shapes the
#: padding and length rule excludes.
REFUSED = [
    "",
    "QQ",  # padding omitted
    "QUI",
    "QQ=",  # under-padded
    "QQ===",  # extra padding
    "QQ====",
    "QUJD=",  # padding after a full group
    "QUJD==",
    "QUJD====",
    "==",
    "====",
    "Q===",  # impossible length, padded
    "QUJDR",  # impossible length, unpadded
    "QQ==QUJD",  # data after the padding
    "QQ==!!!!",  # junk after the padding
    "QU!D",  # junk inside
    "QUJD\n",  # a single trailing line feed
    "QUJD\r\n",  # a trailing CRLF
    "QUJD\nQUJD",  # a line break inside
    " QUJD",  # a leading space
    "QU JD",  # a space inside
    "QU\tJD",  # a tab inside
    "  QUJD  ",  # leading and trailing whitespace
    "-_8=",  # base64url
    "-_8",  # base64url, unpadded
    "+_8=",  # both alphabets
    "QUJé",  # outside ASCII
]


class ReceiptBase64RuleTest(unittest.TestCase):
    def test_canonical_spellings_and_trailing_bits_decode(self) -> None:
        for text, expected in ACCEPTED.items():
            with self.subTest(text=text):
                self.assertEqual(expected, decode_receipt_base64(text))

    def test_every_other_spelling_is_invalid_receipt_format(self) -> None:
        for text in REFUSED:
            with self.subTest(text=text):
                with self.assertRaises(VerificationError) as caught:
                    decode_receipt_base64(text)
                self.assertEqual(Reason.INVALID_RECEIPT_FORMAT, caught.exception.reason)

    def test_the_stdlib_decoder_alone_is_not_the_rule(self) -> None:
        # Why the shape and length check exists: b64decode(validate=True)
        # decodes "" everywhere, and before 3.13 it also accepts surplus
        # padding after a full group.
        def unguarded(text: str) -> bool:
            try:
                base64.b64decode(text, validate=True)
                return True
            except (binascii.Error, ValueError):
                return False

        self.assertTrue(unguarded(""))
        self.assertEqual(sys.version_info < (3, 13), unguarded("QUJD="))


if __name__ == "__main__":
    unittest.main()
