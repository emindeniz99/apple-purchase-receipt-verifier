"""Why the receipt-data decoder checks the shape itself.

The spellings ``decode_receipt_base64`` must accept and refuse are the
decodeBase64 groups of fixtures/cases.json, which test_conformance.py runs
against both the receipt-data and the x5c decoder. What stays here is the one
thing a shared vector cannot say: that ``b64decode(validate=True)`` alone is
not the rule on the Pythons this package supports.
"""

import base64
import binascii
import sys
import unittest


class ReceiptBase64RuleTest(unittest.TestCase):
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
