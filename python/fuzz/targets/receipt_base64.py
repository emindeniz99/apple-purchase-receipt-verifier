"""``ReceiptVerifier.verify`` on a string — the form a client actually sends —
through ``decode_receipt_base64``'s accept/reject rule and then the whole DER
path behind it.

Seeded from the ``receipt-b64`` fixtures and the public receipts, so the
fuzzer starts from strings that decode rather than from noise it has to grow
into base64 by itself.

Bytes that are not UTF-8 are skipped: the API takes a ``str``, so they could
not reach it.
"""

from harness import RECEIPT_VERIFIER, as_text, require_verification_error, run


def one_input(data: bytes) -> None:
    text = as_text(data)
    if text is None:
        return
    try:
        RECEIPT_VERIFIER.verify(text)
    except Exception as error:
        require_verification_error(error, "ReceiptVerifier.verify")


if __name__ == "__main__":
    run(one_input)
