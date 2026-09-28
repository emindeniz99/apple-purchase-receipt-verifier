"""The StoreKit 2 path: compact-JWS split, strict canonical base64url, the
JSON header and payload, the ``x5c`` certificates, the chain, the ES256
signature.

Same invariants as the Go port's ``FuzzVerifySignedData``: nothing escapes
as an exception at all (0.7's ``Verifier`` never raises), and a JWS that
verifies under the fixture root must be refused under Apple's roots, or the
anchors are not what decided it.

The header and payload are attacker-supplied JSON, so this target is the one
that reaches the library's claim reads with values of the wrong *type* and
the wrong *magnitude* — the two shapes a hand-written `.get()` chain tends to
miss.
"""

from harness import (
    APPLE_JWS_VERIFIER,
    JWS_VERIFIER,
    InvariantViolation,
    as_text,
    require_no_exception,
    run,
)


def one_input(data: bytes) -> None:
    jws = as_text(data)
    if jws is None:
        return
    result = require_no_exception(
        lambda: JWS_VERIFIER.verify_signed_data(jws), "Verifier.verify_signed_data"
    )
    if not result.verified:
        return
    apple_result = require_no_exception(
        lambda: APPLE_JWS_VERIFIER.verify_signed_data(jws),
        "Verifier.verify_signed_data against Apple's roots",
    )
    if apple_result.verified:
        raise InvariantViolation(
            "this input verifies against Apple's roots too, so the anchors are not being enforced"
        )


if __name__ == "__main__":
    run(one_input)
