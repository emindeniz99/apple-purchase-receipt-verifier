"""``VerifyReceiptEndpoint.verify_receipt_json``, the one entry point that
takes a request body rather than a receipt: JSON parse, ``receipt-data``
extraction, the receipt-base64 rule, then the whole DER path.

Its documented contract is stronger than the other targets' — it never raises
at all — so that is what is asserted: any body, any bytes, gets a JSON object
with a numeric ``status`` back.
"""

import json

from harness import ENDPOINT, InvariantViolation, as_text, run


def one_input(data: bytes) -> None:
    body = as_text(data)
    if body is None:
        return
    try:
        response = ENDPOINT.verify_receipt_json(body)
    except Exception as error:
        raise InvariantViolation(
            f"the endpoint raised {type(error).__name__}: {error}, "
            "but it documents that it never raises"
        ) from error
    try:
        parsed = json.loads(response)
    except ValueError as error:
        raise InvariantViolation(
            f"the endpoint answered with something that is not JSON: {response!r}"
        ) from error
    status = parsed.get("status") if isinstance(parsed, dict) else None
    if not isinstance(status, int) or isinstance(status, bool):
        raise InvariantViolation(f"the endpoint answered without a numeric status: {response!r}")


if __name__ == "__main__":
    run(one_input)
