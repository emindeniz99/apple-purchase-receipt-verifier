"""The canonical-ABI contract, called by hand over the bundled module's core
exports (the round-13 ABI tests, docs/evidence/2026-09-29-canonical-abi-final):
what ``init`` answers, what traps, that a trap in one instance leaves another
verifying, that memory does not grow with the calls. These hold for any
``aprv.wasm`` of ABI 1.0.0, so they run on whichever module is in place. The wrapper's own
bounds checks are tested over the WAT double in test_facade.py.
"""

import json
import secrets
import time
import unittest
from typing import Any
from unittest import mock

from apple_purchase_receipt_verifier import Config, Environment, Verifier, _host, _wire

from _support import fixture, fixture_text

G5 = fixture_text("public-receipts", "receipt-sandbox-g5.b64").encode("ascii")
JWS = fixture_text("generated", "transaction.jws").encode("ascii")
JWS_ROOT = fixture("generated", "jws-root.der")
OK = '{"ok":true}'


def now() -> int:
    return time.time_ns() // 1_000_000


def fresh(config: bytes = b"", *, init: bool = True) -> _host.Instance:
    instance = _host.Instance(_host.default_runtime())
    if init:
        assert instance.call("init", (), config) == OK
    return instance


def request(receipt: bytes = G5) -> bytes:
    return b'{"receipt-data":"' + receipt + b'"}'


class ContractTest(unittest.TestCase):
    def test_init_with_no_roots_uses_the_built_in_ones_and_answers_ok(self) -> None:
        self.assertEqual(OK, _host.Instance(_host.default_runtime()).call("init", (), b""))

    def test_init_takes_roots_as_base64_der_and_answers_ok(self) -> None:
        self.assertEqual(
            OK,
            _host.Instance(_host.default_runtime()).call("init", (), _wire.init_config([JWS_ROOT])),
        )

    def test_a_configuration_init_refuses_is_ok_false_and_init_can_be_retried(self) -> None:
        instance = fresh(init=False)
        for config in (b"{not json", b"{\xff}", _wire.init_config([b"not a certificate"])):
            with self.subTest(config=config):
                answer = instance.call("init", (), config)
                refusal = json.loads(answer)
                self.assertIs(False, refusal["ok"], answer)
                self.assertIsInstance(refusal["message"], str)
        self.assertEqual(OK, instance.call("init", (), b""))
        self.assertIn('"verified"', instance.call("verify-receipt", (now(),), G5))

    def test_a_genuine_receipt_verifies_and_the_endpoint_takes_the_environment(self) -> None:
        instance = fresh()
        self.assertIn('"verified":true', instance.call("verify-receipt", (now(),), G5))
        sandbox = instance.call("verify-receipt-endpoint", (1, now()), request())
        self.assertIn('"status":0', sandbox)
        production = instance.call("verify-receipt-endpoint", (0, now()), request())
        self.assertIn('"status":21007', production)

    def test_a_jws_verifies_under_the_roots_init_was_given(self) -> None:
        instance = fresh(_wire.init_config([JWS_ROOT]))
        self.assertIn('"verified":true', instance.call("verify-signed-data", (now(),), JWS))

    def test_input_that_is_not_utf8_reaches_the_module_and_is_a_value(self) -> None:
        instance = fresh()
        for export, data in (
            ("verify-receipt", b"\xc3\x28"),
            ("verify-receipt", b""),
            ("verify-signed-data", b"ey\xff\xfe.x"),
            ("verify-signed-data", b""),
            ("verify-receipt-endpoint", b"\xff\xfe"),
        ):
            with self.subTest(export=export, data=data):
                scalars = (1, now()) if export.endswith("endpoint") else (now(),)
                answer = instance.call(export, scalars, data)
                self.assertTrue(answer.startswith("{"), answer)
                self.assertNotIn('"verified":true', answer)
        self.assertIn('"verified":true', instance.call("verify-receipt", (now(),), G5))


class MisuseTest(unittest.TestCase):
    """Each of these traps in the module, and the instance is not used again."""

    def assert_traps(
        self, instance: _host.Instance, export: str, scalars: "tuple[int, ...]", data: bytes
    ) -> None:
        with self.assertRaises(_host.Fault) as caught:
            instance.call(export, scalars, data)
        self.assertIsNotNone(caught.exception.__cause__, "the trap is the cause")

    def test_an_environment_other_than_0_or_1_traps(self) -> None:
        for env in (2, 255, 2**32 - 1):
            with self.subTest(env=env):
                instance = fresh()
                self.assert_traps(instance, "verify-receipt-endpoint", (env, now()), request())

    def test_a_verify_before_init_traps(self) -> None:
        for export, scalars in (
            ("verify-receipt", (now(),)),
            ("verify-signed-data", (now(),)),
            ("verify-receipt-endpoint", (1, now())),
        ):
            with self.subTest(export=export):
                instance = fresh(init=False)
                self.assert_traps(instance, export, scalars, G5)

    def test_a_second_init_after_ok_traps(self) -> None:
        instance = fresh()
        self.assert_traps(instance, "init", (), b"")

    def test_a_trap_in_one_instance_leaves_another_verifying(self) -> None:
        one, other = fresh(), fresh()
        self.assert_traps(one, "verify-receipt-endpoint", (2, now()), request())
        self.assertIn('"verified":true', other.call("verify-receipt", (now(),), G5))
        self.assertIn('"verified":true', fresh().call("verify-receipt", (now(),), G5))

    def test_a_public_call_that_traps_is_internal_error_and_the_next_call_verifies(self) -> None:
        # Environment 2 is unreachable through the public type, so it is forced.
        from apple_purchase_receipt_verifier import verifier as module

        verifier = Verifier(Config.defaults())
        with mock.patch.dict(module._ENVIRONMENT_CODE, {Environment.SANDBOX: 2}):
            answer = verifier.verify_receipt_endpoint(Environment.SANDBOX, request().decode())
        self.assertEqual('{"status":21009}', answer)
        again = verifier.verify_receipt_endpoint(Environment.SANDBOX, request().decode())
        self.assertIn('"status":0', again)


class InputCapTest(unittest.TestCase):
    """Never more than 3,145,729 bytes of an input enter linear memory: one
    over the core's cap, so the core itself answers TOO_LARGE (21002 at the
    endpoint) and a huge input costs no memory."""

    CAP = 3_145_728

    @staticmethod
    def recording(instance: _host.Instance) -> "list[int]":
        """The sizes ``cabi_realloc`` was asked for, one per call."""
        sizes: list[int] = []
        real = instance._realloc

        def spy(store: Any, old: int, old_size: int, align: int, size: int) -> Any:
            sizes.append(size)
            return real(store, old, old_size, align, size)

        instance._realloc = spy  # type: ignore[assignment]
        return sizes

    def test_a_4_mib_input_is_answered_by_the_core_and_only_the_cap_plus_one_is_copied(
        self,
    ) -> None:
        big = b"A" * (4 << 20)
        instance = fresh()
        sizes = self.recording(instance)
        answer = instance.call("verify-receipt", (now(),), big)
        self.assertEqual("TOO_LARGE", json.loads(answer)["reason"], answer)  # the core's own answer
        self.assertEqual([self.CAP + 1], sizes)
        # byte for byte what the core says when the whole input is copied
        with mock.patch.object(_host, "MAX_INPUT_COPY", 1 << 40):
            whole = fresh().call("verify-receipt", (now(),), big)
        self.assertEqual(whole, answer)

    def test_a_huge_input_does_not_grow_linear_memory(self) -> None:
        instance = fresh()
        instance.call("verify-receipt", (now(),), b"A" * (64 << 20))
        self.assertLess(instance.memory_size(), 16 << 20)

    def test_the_endpoint_answers_21002_for_a_4_mib_body(self) -> None:
        body = b'{"receipt-data":"' + b"A" * (4 << 20) + b'"}'
        answer = fresh().call("verify-receipt-endpoint", (0, now()), body)
        self.assertEqual({"status": 21002}, json.loads(answer))

    def test_an_input_of_exactly_the_cap_is_passed_whole(self) -> None:
        instance = fresh()
        sizes = self.recording(instance)
        answer = instance.call("verify-receipt", (now(),), b"A" * self.CAP)
        self.assertEqual([self.CAP], sizes)
        self.assertNotEqual("TOO_LARGE", json.loads(answer)["reason"], answer)  # it was read

    def test_the_public_api_reports_too_large_for_a_4_mib_receipt(self) -> None:
        result = Verifier(Config.defaults()).verify_receipt("A" * (4 << 20))
        self.assertFalse(result.verified)
        self.assertEqual("TOO_LARGE", result.failure.reason.name)  # type: ignore[union-attr]

    def test_init_is_never_truncated(self) -> None:
        config = _wire.init_config([JWS_ROOT])
        instance = fresh(init=False)
        sizes = self.recording(instance)
        instance.call("init", (), config + b" " * (4 << 20))
        self.assertEqual([len(config) + (4 << 20)], sizes)


class MemoryTest(unittest.TestCase):
    def test_two_thousand_calls_leave_memory_the_same_size(self) -> None:
        instance = fresh()
        instance.call("verify-receipt", (now(),), G5)  # the first call sizes the heap
        before = instance.memory_size()
        for _ in range(2000):
            instance.call("verify-receipt", (now(),), G5)
        self.assertEqual(before, instance.memory_size())

    def test_the_store_refuses_memory_beyond_its_limit(self) -> None:
        instance = fresh()
        self.assertEqual(256 * 1024 * 1024, _host.MEMORY_LIMIT)
        self.assertLessEqual(instance.memory_size(), _host.MEMORY_LIMIT)


class RandomGetTest(unittest.TestCase):
    def test_an_ecdsa_verification_draws_its_randomness_from_secrets(self) -> None:
        calls: list[int] = []
        real = secrets.token_bytes

        def counting(length: int) -> bytes:
            calls.append(length)
            return real(length)

        instance = fresh(_wire.init_config([JWS_ROOT]))
        with mock.patch.object(secrets, "token_bytes", counting):
            self.assertIn('"verified":true', instance.call("verify-signed-data", (now(),), JWS))
        self.assertGreater(len(calls), 0, "the module never asked the host for randomness")
        self.assertTrue(all(0 < n <= 1024 for n in calls), calls)


if __name__ == "__main__":
    unittest.main()
