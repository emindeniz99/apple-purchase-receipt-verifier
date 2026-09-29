"""``Verifier.verify_receipt`` on a string (the form a client actually sends):
the whole path behind the boundary, the module's receipt-data rule and its
parser, reached through the wrapper.

Two invariants beyond "nothing crashes": it never raises, and a receipt
accepted under the fixture anchors is refused under an unrelated anchor set.
Without the second, a fuzz target can only find crashes, never "accepts what
it should not".

Seeded from the ``receipt-b64`` fixtures and the public receipts, so the
fuzzer starts from strings that decode rather than from noise it has to grow
into base64 by itself.

Bytes that are not UTF-8 are skipped: the API takes a ``str``, so they could
not reach it.
"""

from harness import (
    RECEIPT_VERIFIER,
    UNRELATED_RECEIPT_VERIFIER,
    InvariantViolation,
    as_text,
    require_no_exception,
    run,
)


def one_input(data: bytes) -> None:
    text = as_text(data)
    if text is None:
        return
    result = require_no_exception(lambda: RECEIPT_VERIFIER.verify_receipt(text), "verify_receipt")
    if not result.verified:
        return
    unrelated = require_no_exception(
        lambda: UNRELATED_RECEIPT_VERIFIER.verify_receipt(text),
        "verify_receipt against an unrelated anchor",
    )
    if unrelated.verified:
        raise InvariantViolation(
            "this receipt verifies under an unrelated anchor too, so the anchors are not enforced"
        )


if __name__ == "__main__":
    run(one_input)
