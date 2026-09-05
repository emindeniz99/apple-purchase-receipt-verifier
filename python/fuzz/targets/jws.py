"""The StoreKit 2 path: compact-JWS split, strict canonical base64url, the
JSON header and payload, the ``x5c`` certificates, the chain, the ES256
signature, then each entry point's claim checks.

Same invariants as the Go port's ``FuzzVerifyTransaction``: nothing escapes
but a ``VerificationError``, and a JWS that ``verify_raw`` accepts under the
fixture root must be refused under Apple's roots, or the anchors are not what
decided it.

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
    require_verification_error,
    run,
)

_CALLS = (
    ("verify_transaction", JWS_VERIFIER.verify_transaction),
    ("verify_app_transaction", JWS_VERIFIER.verify_app_transaction),
    ("verify_raw", JWS_VERIFIER.verify_raw),
)


def one_input(data: bytes) -> None:
    jws = as_text(data)
    if jws is None:
        return
    accepted_by_fixture_root = False
    for name, call in _CALLS:
        try:
            call(jws)
            accepted_by_fixture_root = accepted_by_fixture_root or name == "verify_raw"
        except Exception as error:
            require_verification_error(error, name)
    if not accepted_by_fixture_root:
        return
    try:
        APPLE_JWS_VERIFIER.verify_raw(jws)
    except Exception as error:
        require_verification_error(error, "verify_raw against Apple's roots")
        return
    raise InvariantViolation(
        "this input verifies against Apple's roots too, so the anchors are not being enforced"
    )


if __name__ == "__main__":
    run(one_input)
