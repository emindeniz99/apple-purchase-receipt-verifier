"""The receipt-attribute reader this port hand-writes, on its own.

``receipt.py`` parses the CMS envelope with ``asn1crypto`` but reads the
receipt payload inside it with a small strict DER reader of its own:
``_read_tlv`` (tag, multi-byte length, bounds), ``_children``, the attribute
SET walk with its Xcode double-OCTET-STRING unwrap, the 32-bit attribute-type
rule, the 8-byte integer cap, UTF8String/IA5String decoding, and the RFC 3339
date parse. The attribute SET walk and the date parse run on bytes that are
still unauthenticated, because the creation date is what anchors the
certificate validity window; the rest runs only under a trusted signature,
where a failure is INTERNAL_ERROR. Either way the reader must hold up.

``receipt_der.py`` reaches this code only through a CMS envelope the fuzzer
has to keep well-formed. Here it gets the payload bytes directly, so a length
or offset bug shows up without a signature structure around it.

Invariant: one parsed receipt or a ``VerificationError``, never an
``IndexError``, a ``UnicodeDecodeError``, an ``OverflowError`` from a date, or
anything else raw.
"""

from harness import parse_receipt_payload, require_verification_error, run


def one_input(data: bytes) -> None:
    try:
        parse_receipt_payload(data)
    except Exception as error:
        require_verification_error(error, "the receipt attribute reader")


if __name__ == "__main__":
    run(one_input)
