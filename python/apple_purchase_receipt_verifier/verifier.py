"""The public entry point (docs/design/0.7-api.md, "Setup").

A ``Verifier`` holds no verification logic. It reads the ``Config`` clock,
moves the input's bytes into ``aprv.wasm``, and maps the JSON the module
answers with to the 0.7 types (docs/rust-core/ARCHITECTURE.md section 4).
"""

import os
from collections.abc import Callable

from . import _host, _wire
from .config import Config
from .environment import Environment
from .reason import Reason
from .receipt_payload import JsonPayload, ReceiptPayload
from .result import Failure, VerificationResult

#: What ``verify_receipt_endpoint`` answers when the module could not: Apple's
#: 21009, "internal data access error".
_ENDPOINT_INTERNAL_ERROR = '{"status":21009}'
_INT64_MAX = 2**63 - 1
_ENVIRONMENT_CODE = {Environment.PRODUCTION: 0, Environment.SANDBOX: 1}


def _pool_size() -> int:
    return max(2, min(8, os.cpu_count() or 1))


def _bytes(text: "str | None") -> bytes:
    """The bytes the module receives. Anything but a string is empty input,
    which the module answers as it answers any empty input. A lone surrogate
    survives as bytes that are not UTF-8, so the module, not this wrapper,
    decides what it is."""
    return text.encode("utf-8", "surrogatepass") if isinstance(text, str) else b""


def _internal_error(fault: _host.Fault) -> Failure:
    cause = fault.__cause__ if isinstance(fault.__cause__, BaseException) else fault
    return Failure(Reason.INTERNAL_ERROR, str(fault), cause)


class Verifier:
    """Thread-safe once constructed: each call borrows one instance of the
    Wasm module from a small pool, so calls from several threads run on
    separate instances. The verify methods never raise for any input. A clock
    that raises, a trap and an answer the wrapper cannot read are all
    :attr:`~.reason.Reason.INTERNAL_ERROR` (status 21009 at the endpoint),
    and the instance involved is discarded. A verdict comes only from the
    module.

    The first ``Verifier`` in a process compiles ``aprv.wasm`` (about 1 s on
    4 CPUs, 3 s on one, or a cache hit, see the README); later ones take
    under a millisecond.

    :raises TypeError: if ``config`` is not a :class:`~.config.Config`
    :raises ValueError: if ``config.roots`` is empty (a verifier with no roots
        would answer ``UNTRUSTED_CHAIN`` to everything and nobody would notice
        until production), or if the module refuses a root, for example one
        that is not a certificate
    :raises RuntimeError: if the bundled module cannot be started; an ABI
        mismatch is a ``RuntimeError`` naming the ABI version expected
    """

    __slots__ = ("_clock", "_pool")

    def __init__(self, config: Config) -> None:
        self._setup(config, _host.default_runtime)

    def _setup(self, config: Config, runtime: "Callable[[], _host.Runtime]") -> None:
        if not isinstance(config, Config):
            raise TypeError("config must be a Config")
        if not config.roots:
            raise ValueError("config.roots must not be empty")
        self._clock = config.clock
        try:
            self._pool = _host.Pool(
                runtime(), _wire.init_config(config.roots), _pool_size(), _wire.init_accepted
            )
            refusal = _wire.check_init(self._pool.init_answer)
        except _host.AbiMismatchError:
            raise
        except (_host.Fault, _wire.ResultShapeError) as error:
            raise RuntimeError("the verification module could not be started") from error
        if refusal is not None:
            raise ValueError(f"the module refused config.roots: {refusal}")

    def _now(self) -> int:
        """The clock, read once per call, before the input is looked at."""
        try:
            now = self._clock()
        except Exception as error:
            raise _host.Fault("the configured clock failed") from error
        if not isinstance(now, int) or isinstance(now, bool) or not 0 <= now <= _INT64_MAX:
            raise _host.Fault("the configured clock did not answer epoch milliseconds")
        return now

    def verify_receipt(self, base64: "str | None") -> VerificationResult[ReceiptPayload]:
        try:
            now = self._now()
            return self._pool.run("verify-receipt", (now,), _bytes(base64), _wire.receipt_result)
        except _host.Fault as fault:
            return VerificationResult(failure=_internal_error(fault))

    def verify_signed_data(self, jws: "str | None") -> VerificationResult[JsonPayload]:
        try:
            now = self._now()
            return self._pool.run(
                "verify-signed-data", (now,), _bytes(jws), _wire.signed_data_result
            )
        except _host.Fault as fault:
            return VerificationResult(failure=_internal_error(fault))

    def verify_receipt_endpoint(self, environment: Environment, request_json: "str | None") -> str:
        if not isinstance(environment, Environment):
            raise TypeError("environment must be an Environment")
        try:
            now = self._now()
            return self._pool.run(
                "verify-receipt-endpoint",
                (_ENVIRONMENT_CODE[environment], now),
                _bytes(request_json),
                _wire.endpoint_answer,
            )
        except _host.Fault:
            return _ENDPOINT_INTERNAL_ERROR
