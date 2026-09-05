"""The whole legacy-receipt path on DER bytes: the ``asn1crypto`` CMS walk,
the receipt payload parse, chain building and the RSA signature check.

This is the target that reaches ``asn1crypto``'s ``ContentInfo`` /
``SignedData`` / SET decoding through the entry point a consumer calls, which
is the only way that parser is reachable at all — the port has no public
ASN.1 surface of its own.

Three invariants, the same ones the Go, Rust and Node ports state:

  * nothing crashes the interpreter;
  * a failure is a ``VerificationError``, never a foreign error type;
  * a receipt that verifies was accepted *because of* the anchors, proven by
    re-running it against an unrelated anchor set and requiring failure.
    Without that third one a fuzz target can only find crashes, never
    "accepts what it should not".
"""

from harness import (
    RECEIPT_ANCHORS,
    UNRELATED_ANCHORS,
    InvariantViolation,
    require_verification_error,
    run,
    verify_receipt_core,
)


def one_input(data: bytes) -> None:
    try:
        verify_receipt_core(data, RECEIPT_ANCHORS)
    except Exception as error:
        require_verification_error(error, "verify_receipt_core")
        return
    try:
        verify_receipt_core(data, UNRELATED_ANCHORS)
    except Exception as error:
        require_verification_error(error, "verify_receipt_core against the unrelated anchors")
        return
    raise InvariantViolation(
        "this input verifies against an unrelated anchor set too, "
        "so the anchors are not being enforced"
    )


if __name__ == "__main__":
    run(one_input)
