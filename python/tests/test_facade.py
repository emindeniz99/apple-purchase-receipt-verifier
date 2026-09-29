"""The wrapper's own behaviour, over the WAT test double (``double.wat``): the
six outcomes kept apart, trap recovery, the clock and the environment, the
pool. The double speaks ABI 1.0.0 and verifies nothing, so these tests hold
whatever module the package carries: they exercise the host code, and the
verdicts are the module's own business (test_conformance.py, test_abi.py)."""

import contextlib
import gc
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
import weakref
from pathlib import Path
from typing import Any
from unittest import mock

import wasmtime
from apple_purchase_receipt_verifier import (
    Config,
    Environment,
    InAppPurchase,
    JsonPayload,
    Reason,
    ReceiptPayload,
    Verifier,
    _host,
    _wire,
)

import _support
from _support import TESTS, double_runtime, double_verifier

ROOT = b"\x30\x00"


def echo(answer: str) -> str:
    """Input that makes the double answer ``answer`` (an ``E`` prefix)."""
    return "E" + answer


def failure_of(result: Any) -> Any:
    assert result.failure is not None, result
    return result.failure


class VerifiedTest(unittest.TestCase):
    def test_a_receipt_payload_reads_back_as_the_value_the_wire_carries(self) -> None:
        purchase = InAppPurchase(
            quantity=3,
            product_id="p.coins",
            transaction_id="2000000000000001",
            purchase_date_ms=1_722_945_600_000,
            original_transaction_id="2000000000000000",
            original_purchase_date_ms=1_722_945_600_000,
            expires_date_ms=1_725_945_600_000,
            web_order_line_item_id=2**53 + 1,  # above what a JSON number keeps exactly
            cancellation_date_ms=None,
            is_trial_period=False,
            is_in_intro_offer_period=True,
            unknown_attributes={1799: (b"\x00\xff",), 1801: (b"a", b"b")},
        )
        payload = ReceiptPayload(
            receipt_type="ProductionSandbox",
            app_item_id=2**63 - 1,
            bundle_id="com.example.app",
            bundle_id_bytes=b"\x0c\x0fcom.example.app",
            application_version="1.2",
            opaque_value=bytes(range(16)),
            sha1_hash=bytes(20),
            receipt_creation_date_ms=1_722_945_600_000,
            download_id=-5,  # a hostile INTEGER can be negative
            version_external_identifier=0,
            in_app=(purchase, InAppPurchase()),
            original_purchase_date_ms=None,
            original_application_version="1.0",
            expiration_date_ms=None,
            unknown_attributes={99: (b"x",)},
        )
        answer = '{"verified":true,"payload":' + payload.to_json() + "}"
        result = double_verifier().verify_receipt(echo(answer))
        self.assertTrue(result.verified, result.failure)
        self.assertEqual(payload, result.payload)
        self.assertEqual(payload.to_json(), result.payload.to_json() if result.payload else None)

    def test_an_absent_optional_field_is_none_and_an_empty_payload_is_all_none(self) -> None:
        result = double_verifier().verify_receipt(echo('{"verified":true,"payload":{}}'))
        self.assertEqual(ReceiptPayload(), result.payload)

    def test_a_signed_payload_is_the_exact_text_the_module_returned(self) -> None:
        signed = '{"bundleId": "com.example.app",  "n": 1e2, "big": 12345678901234567890}'
        answer = json.dumps({"verified": True, "payload": signed})
        result = double_verifier().verify_signed_data(echo(answer))
        self.assertEqual(JsonPayload(json=signed), result.payload)
        self.assertIs(type(result.payload.json), str)  # type: ignore[union-attr]


class VerificationFailureTest(unittest.TestCase):
    def test_every_reason_of_0_7_reaches_the_caller_with_its_message(self) -> None:
        verifier = double_verifier()
        for reason in Reason:
            with self.subTest(reason=reason.name):
                answer = json.dumps({"verified": False, "reason": reason.value, "message": "why"})
                for result in (
                    verifier.verify_receipt(echo(answer)),
                    verifier.verify_signed_data(echo(answer)),
                ):
                    failure = failure_of(result)
                    self.assertEqual(reason, failure.reason)
                    self.assertEqual("why", failure.message)
                    self.assertIsNone(failure.cause)
                    self.assertFalse(result.verified)

    def test_a_failure_is_a_value_the_endpoint_answer_is_the_modules_text(self) -> None:
        text = '{"status":21003}'
        self.assertEqual(
            text, double_verifier().verify_receipt_endpoint(Environment.SANDBOX, echo(text))
        )
        odd = '{ "status" : 0 ,\n"unicode":"é\U0001f600" }'
        self.assertEqual(
            odd, double_verifier().verify_receipt_endpoint(Environment.SANDBOX, echo(odd))
        )


class CallerMisuseTest(unittest.TestCase):
    def test_no_roots_is_a_value_error_before_any_instance_exists(self) -> None:
        with mock.patch.object(_host, "Instance") as instance, self.assertRaises(ValueError):
            Verifier(Config.create(roots=[]))
        instance.assert_not_called()

    def test_a_config_that_is_not_a_config_is_a_type_error(self) -> None:
        for bad in (None, object(), {"roots": []}):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                Verifier(bad)  # type: ignore[arg-type]

    def test_a_root_the_module_refuses_is_a_value_error_naming_its_message(self) -> None:
        # The double refuses a first root whose base64 starts with "R".
        with self.assertRaises(ValueError) as caught:
            double_verifier(roots=(b"D" * 30,))
        self.assertIn("the double refuses this root", str(caught.exception))

    def test_a_root_that_is_not_bytes_is_a_type_error_at_config(self) -> None:
        for bad in ("MIIB", None, 5, object()):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                Config.create(roots=[bad])  # type: ignore[list-item]

    def test_bytes_like_roots_are_accepted_and_deduplicated_in_first_seen_order(self) -> None:
        config = Config.create(roots=[b"b", bytearray(b"a"), memoryview(b"b"), b"a"])
        self.assertEqual((b"b", b"a"), config.roots)

    def test_an_environment_that_is_not_an_environment_is_a_type_error(self) -> None:
        reads: list[int] = []

        def clock() -> int:
            reads.append(1)
            return 1

        verifier = double_verifier(clock=clock)
        for bad in ("PRODUCTION", 0, None, Environment):
            with self.subTest(bad=bad), self.assertRaises(TypeError):
                verifier.verify_receipt_endpoint(bad, "{}")  # type: ignore[arg-type]
        self.assertEqual([], reads, "a misuse is refused before the clock is read")


def double_wat(replacements: "dict[str, str]") -> bytes:
    text = (TESTS / "double.wat").read_text(encoding="utf-8")
    for old, new in replacements.items():
        assert old in text, old
        text = text.replace(old, new)
    return bytes(wasmtime.wat2wasm(text))


class AbiMismatchTest(unittest.TestCase):
    """A module of another ABI version, or one that wants more than
    ``random-get``, is a hard failure at ``create`` naming what was expected;
    it is never a verdict."""

    def create(self, wasm: bytes) -> None:
        runtime = _host.Runtime(wasm)
        Verifier.__new__(Verifier)._setup(Config.create(roots=[ROOT]), lambda: runtime)

    def test_a_module_of_another_abi_version_is_refused(self) -> None:
        wasm = double_wat({"verify@1.0.0#init": "verify@2.0.0#init"})
        with self.assertRaises(RuntimeError) as caught:
            self.create(wasm)
        self.assertIsInstance(caught.exception, _host.AbiMismatchError)
        message = str(caught.exception)
        self.assertIn("ABI 1.0.0", message)
        self.assertIn("aprv:verifier/verify@2.0.0#init", message, "names the exports it has")

    def test_a_module_that_imports_anything_else_is_refused(self) -> None:
        wasm = double_wat(
            {"(memory (export": '(import "env" "clock" (func (result i64)))\n  (memory (export'}
        )
        with self.assertRaises(_host.AbiMismatchError) as caught:
            self.create(wasm)
        self.assertIn("allows only", str(caught.exception))
        self.assertIn("clock", str(caught.exception))

    def test_a_module_with_an_export_of_the_wrong_shape_is_refused(self) -> None:
        wasm = double_wat(
            {
                '(func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32)': (
                    '(func (export "cabi_realloc") (param i32 i32 i32) (result i32)'
                ),
                "(local.get 3)))": "(i32.const 8)))",
            }
        )
        with self.assertRaises(_host.AbiMismatchError):
            self.create(wasm)

    def test_a_module_that_does_not_compile_is_a_runtime_error(self) -> None:
        with self.assertRaises(RuntimeError) as caught:
            _host.Runtime(b"\x00asm\x01\x00\x00\x00garbage")
        self.assertNotIsInstance(caught.exception, _host.AbiMismatchError)

    def test_a_module_whose_initialize_traps_is_a_runtime_error_at_create(self) -> None:
        wasm = double_wat(
            {'(func (export "_initialize"))': '(func (export "_initialize") unreachable)'}
        )
        with self.assertRaises(RuntimeError) as caught:
            self.create(wasm)
        self.assertIn("could not be started", str(caught.exception))

    def test_the_bundled_module_is_accepted(self) -> None:
        _host.default_runtime()  # compiles and checks the bundled module


class ModuleFileTest(unittest.TestCase):
    """The module is not committed. The library loads only the ``aprv.wasm``
    bundled in the package, checked against ``aprv.wasm.sha256``; it reads no
    environment variable to pick another file. Test and build tooling may pass
    an explicit path to the internal loader."""

    PACKAGE = Path(__file__).resolve().parents[1] / "apple_purchase_receipt_verifier"

    def run_in_copy(
        self, script: str, wasm: "bytes | None", env: "dict[str, str] | None" = None
    ) -> "subprocess.CompletedProcess[str]":
        """Runs ``script`` against a copy of the package whose ``aprv.wasm`` is
        ``wasm`` (absent when None)."""
        with tempfile.TemporaryDirectory() as directory:
            copy = Path(directory) / "apple_purchase_receipt_verifier"
            shutil.copytree(
                self.PACKAGE, copy, ignore=shutil.ignore_patterns("__pycache__", "aprv.wasm")
            )
            if wasm is not None:
                (copy / "aprv.wasm").write_bytes(wasm)
            environment = {k: v for k, v in os.environ.items() if k != "APRV_WASM"}
            environment.update(env or {})
            environment["PYTHONPATH"] = directory
            # The working directory leads sys.path for ``-c``: make it the copy.
            check = (
                "import apple_purchase_receipt_verifier as p;"
                f"assert p.__file__.startswith({directory!r}), p.__file__;"
            )
            return subprocess.run(
                [sys.executable, "-c", check + script],
                env=environment,
                cwd=directory,
                capture_output=True,
                text=True,
                timeout=300,
                check=False,
            )

    LOAD = "from apple_purchase_receipt_verifier import _host; _host.read_pinned_module()"
    START = (
        "from apple_purchase_receipt_verifier import Config, Verifier, default_roots;"
        "Verifier(Config.create(roots=default_roots()))"
    )

    def test_a_missing_module_is_a_clear_error(self) -> None:
        done = self.run_in_copy(self.LOAD, None)
        self.assertNotEqual(0, done.returncode)
        self.assertIn("not found", done.stderr)
        self.assertIn("copy the module into the package directory", done.stderr)

    def test_a_module_that_does_not_match_the_recorded_hash_is_refused(self) -> None:
        done = self.run_in_copy(self.LOAD, _support.WASM + b"\x00")
        self.assertNotEqual(0, done.returncode)
        self.assertIn("SHA-256", done.stderr)

    def test_the_variable_does_not_swap_the_module_in_the_library(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            other = Path(directory) / "other.wasm"
            other.write_bytes(_support.WASM + b"\x00")
            for value in (str(other), "/nonexistent/aprv.wasm"):
                done = self.run_in_copy(self.START, _support.WASM, {"APRV_WASM": value})
                self.assertEqual(0, done.returncode, done.stderr)

    def test_the_variable_does_not_supply_a_missing_module(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            elsewhere = Path(directory) / "elsewhere.wasm"
            elsewhere.write_bytes(_support.WASM)
            done = self.run_in_copy(self.START, None, {"APRV_WASM": str(elsewhere)})
        self.assertNotEqual(0, done.returncode)
        self.assertIn("not found", done.stderr)

    def test_the_internal_loader_takes_an_explicit_path_and_checks_its_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            good = Path(directory) / "good.wasm"
            good.write_bytes(_support.WASM)
            bad = Path(directory) / "bad.wasm"
            bad.write_bytes(_support.WASM + b"\x00")
            self.assertEqual(_support.WASM, _host.read_pinned_module(good))
            with self.assertRaisesRegex(RuntimeError, "SHA-256"):
                _host.read_pinned_module(bad)
            with self.assertRaisesRegex(RuntimeError, "not found"):
                _host.read_pinned_module(Path(directory) / "missing.wasm")

    def test_the_package_sources_name_no_module_variable(self) -> None:
        """Only test and build tooling may read ``APRV_WASM``; the package may
        name ``APRV_WASM_CACHE_DIR`` and nothing else that begins with it, and
        only ``_cache.py`` reads variables about the cache or the platform."""
        pattern = re.compile(r"APRV_WASM(?!_CACHE_DIR\b)")
        sources = sorted(self.PACKAGE.glob("*.py"))
        self.assertGreater(len(sources), 10)
        for source in sources:
            text = source.read_text(encoding="utf-8")
            self.assertIsNone(pattern.search(text), f"{source.name} names APRV_WASM")
            if source.name != "_cache.py":
                self.assertNotRegex(text, r"os\.environ|getenv", source.name)


class TrapAndInternalFailureTest(unittest.TestCase):
    def test_a_trap_is_internal_error_with_the_trap_as_its_cause(self) -> None:
        verifier = double_verifier()
        for result in (verifier.verify_receipt("T"), verifier.verify_signed_data("T")):
            failure = failure_of(result)
            self.assertEqual(Reason.INTERNAL_ERROR, failure.reason)
            self.assertIsInstance(failure.cause, (wasmtime.Trap, wasmtime.WasmtimeError))

    def test_a_trap_at_the_endpoint_is_apples_21009(self) -> None:
        answer = double_verifier().verify_receipt_endpoint(Environment.PRODUCTION, "T")
        self.assertEqual('{"status":21009}', answer)

    def test_answers_the_wrapper_cannot_read_are_internal_errors(self) -> None:
        verifier = double_verifier()
        answers = {
            "not JSON": "N",
            "a return area outside memory": "B",
            "a result outside memory": "L",
            "a JSON array": echo("[]"),
            "no verdict": echo("{}"),
            "verified with no payload": echo('{"verified":true}'),
            "an unknown reason": echo('{"verified":false,"reason":"INVALID_CHAIN","message":"m"}'),
            "a failure without a message": echo('{"verified":false,"reason":"MALFORMED"}'),
            "a payload that is not an object": echo('{"verified":true,"payload":[]}'),
            "a string where a number goes": echo('{"verified":true,"payload":{"download_id":"x"}}'),
            "a number where a string goes": echo('{"verified":true,"payload":{"bundle_id":1}}'),
            "a bad base64 field": echo('{"verified":true,"payload":{"sha1_hash":"@@@@"}}'),
            "a bad in-app": echo('{"verified":true,"payload":{"in_app":[1]}}'),
            "bad unknown attributes": echo(
                '{"verified":true,"payload":{"unknown_attributes":{"x":[]}}}'
            ),
        }
        for name, text in answers.items():
            with self.subTest(name):
                failure = failure_of(verifier.verify_receipt(text))
                self.assertEqual(Reason.INTERNAL_ERROR, failure.reason)
                self.assertIsNotNone(failure.cause)
        self.assertEqual(
            Reason.INTERNAL_ERROR,
            failure_of(verifier.verify_signed_data(echo('{"verified":true,"payload":{}}'))).reason,
            "the signed payload crosses as a JSON string, not an object",
        )
        for name, text in {
            "not JSON": "N",
            "a return area outside memory": "B",
            "a result outside memory": "L",
            "a JSON array": echo("[]"),
            "no status": echo("{}"),
            "a status that is not a number": echo('{"status":"0"}'),
        }.items():
            with self.subTest(f"endpoint, {name}"):
                answer = verifier.verify_receipt_endpoint(Environment.SANDBOX, text)
                self.assertEqual('{"status":21009}', answer)

    def test_a_result_larger_than_the_store_allows_is_a_trap_not_a_crash(self) -> None:
        failure = failure_of(double_verifier().verify_receipt("H"))
        self.assertEqual(Reason.INTERNAL_ERROR, failure.reason)

    def test_an_input_that_does_not_fit_the_module_is_internal_error(self) -> None:
        # The double's memory is 1 MiB and its allocator does not grow it.
        failure = failure_of(double_verifier().verify_receipt("A" * (2 << 20)))
        self.assertEqual(Reason.INTERNAL_ERROR, failure.reason)

    def test_the_verifier_keeps_answering_after_a_trap_on_a_fresh_instance(self) -> None:
        created: list[int] = []
        real = _host.Instance

        def counting(runtime: "_host.Runtime") -> Any:
            created.append(1)
            return real(runtime)

        with mock.patch.object(_host, "Instance", counting):
            verifier = double_verifier()
            self.assertEqual(1, len(created), "one instance, made and initialised at create")
            self.assertEqual(Reason.INTERNAL_ERROR, failure_of(verifier.verify_receipt("T")).reason)
            for _ in range(3):
                # A reused trapped instance would trap again; a second init on
                # one instance traps too, so a pool that re-inits shows here.
                failure = failure_of(verifier.verify_receipt("ok"))
                self.assertEqual(Reason.MALFORMED, failure.reason)
            self.assertEqual(2, len(created), "the trapped instance was replaced exactly once")

    def test_an_instance_that_grew_large_is_dropped_not_pooled(self) -> None:
        verifier = double_verifier()
        pool = verifier._pool
        self.assertEqual(1, len(pool._free))
        verifier.verify_receipt("G")  # grows the double's memory by 68 MiB
        self.assertEqual(0, len(pool._free))
        self.assertEqual(Reason.MALFORMED, failure_of(verifier.verify_receipt("ok")).reason)
        self.assertEqual(1, len(pool._free))

    def test_a_clock_failure_and_a_trap_have_different_causes(self) -> None:
        def clock() -> int:
            raise RuntimeError("clock backend unavailable")

        failure = failure_of(double_verifier(clock=clock).verify_receipt("x"))
        self.assertIsInstance(failure.cause, RuntimeError)
        trap = failure_of(double_verifier().verify_receipt("T"))
        self.assertNotIsInstance(trap.cause, RuntimeError)


class ClockTest(unittest.TestCase):
    NOW = 1_735_689_600_123

    def test_the_clock_is_read_once_per_call_before_the_input_is_touched(self) -> None:
        events: list[str] = []

        class Spy(str):
            def encode(self, *args: Any, **kwargs: Any) -> bytes:
                events.append("input")
                return super().encode(*args, **kwargs)

        def clock() -> int:
            events.append("clock")
            return self.NOW

        verifier = double_verifier(clock=clock)
        calls = (
            lambda: verifier.verify_receipt(Spy("r")),
            lambda: verifier.verify_signed_data(Spy("j")),
            lambda: verifier.verify_receipt_endpoint(Environment.SANDBOX, Spy("{}")),
        )
        for call in calls:
            events.clear()
            call()
            self.assertEqual(["clock", "input"], events)

    def test_the_value_read_crosses_as_now_ms_and_the_environment_as_0_or_1(self) -> None:
        verifier = double_verifier(clock=lambda: self.NOW)
        receipt = failure_of(verifier.verify_receipt("x")).message
        signed = failure_of(verifier.verify_signed_data("x")).message
        self.assertEqual(f"receipt now={self.NOW}", receipt)
        self.assertEqual(f"jws now={self.NOW}", signed)
        production = verifier.verify_receipt_endpoint(Environment.PRODUCTION, "x")
        sandbox = verifier.verify_receipt_endpoint(Environment.SANDBOX, "x")
        self.assertEqual(f'{{"status":21009,"env":0,"now":{self.NOW}}}', production)
        self.assertEqual(f'{{"status":21009,"env":1,"now":{self.NOW}}}', sandbox)

    def test_the_largest_instant_the_module_takes_crosses_unchanged(self) -> None:
        limit = 2**63 - 1
        message = failure_of(double_verifier(clock=lambda: limit).verify_receipt("x")).message
        self.assertEqual(f"receipt now={limit}", message)
        self.assertEqual(
            "receipt now=0",
            failure_of(double_verifier(clock=lambda: 0).verify_receipt("x")).message,
        )

    def test_a_clock_that_fails_is_internal_error_and_the_module_is_never_called(self) -> None:
        def clock() -> int:
            raise RuntimeError("clock backend unavailable")

        verifier = double_verifier(clock=clock)
        with mock.patch.object(_host.Instance, "call", side_effect=AssertionError("called")):
            failure = failure_of(verifier.verify_receipt("T"))
            self.assertEqual(Reason.INTERNAL_ERROR, failure.reason)
            self.assertIsInstance(failure.cause, RuntimeError)
            self.assertEqual(
                Reason.INTERNAL_ERROR, failure_of(verifier.verify_signed_data("T")).reason
            )
            answer = verifier.verify_receipt_endpoint(Environment.SANDBOX, "T")
        self.assertEqual('{"status":21009}', answer)

    def test_a_clock_that_answers_anything_but_epoch_milliseconds_is_internal_error(self) -> None:
        for bad in (1.5, "1", None, True, -1, 2**63, 2**64):
            with self.subTest(bad=bad):
                verifier = double_verifier(clock=lambda bad=bad: bad)  # type: ignore[misc]
                self.assertEqual(
                    Reason.INTERNAL_ERROR, failure_of(verifier.verify_receipt("x")).reason
                )
                self.assertEqual(
                    '{"status":21009}', verifier.verify_receipt_endpoint(Environment.SANDBOX, "x")
                )

    def test_the_default_clock_is_the_system_clock_in_milliseconds(self) -> None:
        import time

        before = int(time.time() * 1000)
        now = Config.defaults().clock()
        self.assertIsInstance(now, int)
        self.assertLessEqual(before, now)
        self.assertLess(now - before, 5_000)


class InputTest(unittest.TestCase):
    def test_anything_but_a_string_reaches_the_module_as_empty_input(self) -> None:
        verifier = double_verifier(clock=lambda: 7)
        for bad in (None, b"bytes", 5, ["x"]):
            with self.subTest(bad=bad):
                self.assertEqual("receipt now=7", failure_of(verifier.verify_receipt(bad)).message)  # type: ignore[arg-type]
                self.assertEqual("jws now=7", failure_of(verifier.verify_signed_data(bad)).message)  # type: ignore[arg-type]
                self.assertEqual(
                    '{"status":21009,"env":1,"now":7}',
                    verifier.verify_receipt_endpoint(Environment.SANDBOX, bad),  # type: ignore[arg-type]
                )

    def test_text_crosses_as_utf8_and_a_lone_surrogate_survives_as_non_utf8_bytes(self) -> None:
        from apple_purchase_receipt_verifier.verifier import _bytes

        self.assertEqual("é\U0001f600".encode(), _bytes("é\U0001f600"))
        self.assertEqual(b"\xed\xa0\x80", _bytes("\ud800"))
        self.assertEqual(b"", _bytes(""))

    def test_a_module_answer_that_is_not_utf8_is_internal_error(self) -> None:
        # 'E' echoes the rest of the input; a lone surrogate encodes to bytes
        # that are not UTF-8, so the answer cannot be decoded.
        failure = failure_of(double_verifier().verify_receipt("E\ud800"))
        self.assertEqual(Reason.INTERNAL_ERROR, failure.reason)


class PoolTest(unittest.TestCase):
    def test_init_runs_once_per_instance_however_many_calls_follow(self) -> None:
        # The double traps on a second init, so a pool that inits twice fails.
        verifier = double_verifier()
        for _ in range(50):
            self.assertEqual(Reason.MALFORMED, failure_of(verifier.verify_receipt("x")).reason)

    def test_threads_never_share_an_instance_at_one_moment(self) -> None:
        verifier = double_verifier()
        runtime = double_runtime()
        pool = _host.Pool(runtime, _wire.init_config([ROOT]), 2, _wire.init_accepted)
        inside = 0
        peak = 0
        guard = threading.Lock()
        reached = threading.Barrier(2)

        def parse(answer: str) -> str:
            nonlocal inside, peak
            with guard:
                inside += 1
                peak = max(peak, inside)
            with contextlib.suppress(threading.BrokenBarrierError):
                reached.wait(timeout=5)  # both threads inside at once: two instances
            with guard:
                inside -= 1
            return answer

        def run() -> None:
            pool.run("verify-receipt", (1,), b"x", parse)

        threads = [threading.Thread(target=run) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        self.assertEqual(2, peak)
        self.assertEqual(2, len(pool._free), "both instances went back to the pool")
        self.assertEqual(Reason.MALFORMED, failure_of(verifier.verify_receipt("x")).reason)

    def test_a_pool_of_one_makes_the_second_caller_wait(self) -> None:
        pool = _host.Pool(double_runtime(), _wire.init_config([ROOT]), 1, _wire.init_accepted)
        first_inside, release, second_entered = (
            threading.Event(),
            threading.Event(),
            threading.Event(),
        )

        def hold(answer: str) -> str:
            first_inside.set()
            release.wait(timeout=10)
            return answer

        first = threading.Thread(target=lambda: pool.run("verify-receipt", (1,), b"x", hold))

        def enter(answer: str) -> str:
            second_entered.set()
            return answer

        second = threading.Thread(target=lambda: pool.run("verify-receipt", (1,), b"x", enter))
        first.start()
        self.assertTrue(first_inside.wait(timeout=10))
        second.start()
        self.assertFalse(
            second_entered.wait(timeout=0.3), "entered while the only instance was busy"
        )
        release.set()
        first.join(timeout=10)
        second.join(timeout=10)
        self.assertTrue(second_entered.is_set())

    def test_a_failing_parse_or_an_interrupt_frees_the_slot_and_drops_the_instance(self) -> None:
        pool = _host.Pool(double_runtime(), _wire.init_config([ROOT]), 1, _wire.init_accepted)

        def broken(answer: str) -> str:
            raise KeyError(answer)

        with self.assertRaises(_host.Fault):
            pool.run("verify-receipt", (1,), b"x", broken)

        def interrupted(answer: str) -> str:
            raise KeyboardInterrupt

        with self.assertRaises(KeyboardInterrupt):
            pool.run("verify-receipt", (1,), b"x", interrupted)
        self.assertEqual(0, len(pool._free))
        # A pool of one that leaked its slot would block here forever.
        self.assertIn("MALFORMED", pool.run("verify-receipt", (1,), b"x", str))

    def test_instances_die_with_the_verifier(self) -> None:
        verifier = double_verifier()
        pool = weakref.ref(verifier._pool)
        del verifier
        gc.collect()
        self.assertIsNone(pool())

    def test_the_default_runtime_is_one_process_wide_object(self) -> None:
        self.assertIs(_host.default_runtime(), _host.default_runtime())


if __name__ == "__main__":
    unittest.main()
