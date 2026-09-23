"""``VerifyReceiptResult``: one verification, then any number of renders.

What matters here is what a caller builds a retry on. The receipt must
survive a 21007/21008 so the other environment can be rendered without a
second verification, and that re-render must recompute the status from the
receipt itself: a result from a production endpoint must never be turned
into a production 0 for a sandbox receipt, or the 21007 routing that keeps
sandbox purchases out of production would be one method call away from
being bypassed.
"""

import base64
import json
import unittest
from collections.abc import Callable, Iterator, Mapping
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest import mock

from apple_purchase_receipt_verifier import (
    Reason,
    VerifyReceiptEndpoint,
    VerifyReceiptResult,
    apple_receipt_roots,
)
from cryptography import x509

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
GENERATED = FIXTURES / "generated"
CLOCK_NOW = 1767225600.0  # 2026-01-01T00:00:00Z
EXPLICIT = datetime(2025, 6, 15, 12, 34, 56, 789000, tzinfo=timezone.utc)
ENVIRONMENTS = ("Production", "Sandbox")


def cert(name: str) -> x509.Certificate:
    return x509.load_der_x509_certificate((GENERATED / name).read_bytes())


def b64(name: str) -> str:
    return base64.b64encode((GENERATED / name).read_bytes()).decode("ascii")


class CountingClock:
    """A fixed clock that counts how often the endpoint reads it."""

    def __init__(self, now: float = CLOCK_NOW) -> None:
        self.now = now
        self.calls = 0

    def __call__(self) -> float:
        self.calls += 1
        return self.now


def endpoint(
    environment: str, root: str = "receipt-root.der", clock: CountingClock | None = None
) -> VerifyReceiptEndpoint:
    return VerifyReceiptEndpoint([cert(root)], environment, clock or CountingClock())


class BrokenMapping(Mapping[str, Any]):
    """A request mapping whose lookup raises: any unexpected failure inside
    the pipeline, reached through the public API."""

    error = RuntimeError("broken request mapping")

    def __getitem__(self, key: str) -> Any:
        raise self.error

    def __iter__(self) -> Iterator[str]:
        raise self.error

    def __len__(self) -> int:
        return 1


class VerifyReceiptResultTest(unittest.TestCase):
    def assert_invariant(self, result: VerifyReceiptResult, label: str) -> None:
        self.assertNotEqual(
            result.receipt is None,
            result.failure_reason is None,
            f"{label}: exactly one of receipt and failure_reason must be set",
        )
        self.assertEqual(result.receipt is not None, result.verified, label)
        self.assertEqual(
            result.failure_reason == Reason.INTERNAL_ERROR,
            result.failure_cause is not None,
            f"{label}: failure_cause is set exactly for INTERNAL_ERROR",
        )
        self.assertEqual(result.status, result.to_response()["status"], label)
        self.assertIsNotNone(result.request_date.utcoffset(), label)

    def test_exactly_one_of_receipt_and_failure_reason_for_every_status(self) -> None:
        results = {
            "0 sandbox": endpoint("Sandbox").verify_receipt_data(b64("receipt.der")),
            "0 production": endpoint("Production").verify_receipt_data(
                b64("receipt-type-production.der")
            ),
            "21007": endpoint("Production").verify_receipt_data(b64("receipt.der")),
            "21008": endpoint("Sandbox").verify_receipt_data(b64("receipt-type-production.der")),
            "21002": endpoint("Sandbox").verify_receipt_data("AQIDBA=="),
            "21003": endpoint("Sandbox").verify_receipt_data(b64("receipt-foreign.der")),
            "21009": endpoint("Sandbox").verify_receipt_result(BrokenMapping()),
        }
        for label, result in results.items():
            self.assert_invariant(result, label)
            self.assertEqual(int(label.split()[0]), result.status, label)
        # 21007 and 21008 are routing answers, not failures: the receipt
        # verified, so `verified` is not the same check as `status == 0`.
        for label in ("0 sandbox", "0 production", "21007", "21008"):
            self.assertTrue(results[label].verified, label)
            self.assertIsNotNone(results[label].receipt, label)
        for label in ("21002", "21003", "21009"):
            self.assertFalse(results[label].verified, label)

    def test_re_renders_for_either_environment_from_the_receipts_own_type(self) -> None:
        # A production receipt is 0 on Production and 21008 on Sandbox; a
        # sandbox one (and one with no receipt_type, which fails closed as
        # sandbox) is 21007 on Production and 0 on Sandbox; a failure keeps
        # its status. The same whichever environment verified it.
        table = [
            ("receipt-type-production.der", "receipt-root.der", 0, 21008),
            ("receipt-type-vpp.der", "receipt-root.der", 0, 21008),
            ("receipt.der", "receipt-root.der", 21007, 0),
            ("receipt-type-vpp-sandbox.der", "receipt-root.der", 21007, 0),
            ("receipt-no-type.der", "receipt-root.der", 21007, 0),
            ("receipt-foreign.der", "receipt-root.der", 21003, 21003),
            ("receipt-tampered-payload.der", "gaps-receipt-root.der", 21003, 21003),
        ]
        for fixture, root, on_production, on_sandbox in table:
            for own in ENVIRONMENTS:
                label = f"{fixture} from a {own} endpoint"
                result = endpoint(own, root).verify_receipt_data(b64(fixture), now=EXPLICIT)
                self.assertEqual(on_production, result.to_response("Production")["status"], label)
                self.assertEqual(on_sandbox, result.to_response("Sandbox")["status"], label)
                for target in ENVIRONMENTS:
                    # Each render is byte for byte what an endpoint of that
                    # environment answers on its own.
                    direct = (
                        endpoint(target, root).verify_receipt_data(b64(fixture), now=EXPLICIT)
                    ).to_json()
                    self.assertEqual(direct, result.to_json(target), f"{label} for {target}")

    def test_a_sandbox_receipt_never_renders_a_production_zero(self) -> None:
        for fixture in ("receipt.der", "receipt-type-vpp-sandbox.der", "receipt-no-type.der"):
            for own in ENVIRONMENTS:
                result = endpoint(own).verify_receipt_data(b64(fixture))
                self.assertTrue(result.verified, fixture)
                self.assertEqual('{"status":21007}', result.to_json("Production"), fixture)
                self.assertEqual({"status": 21007}, result.to_response("Production"), fixture)

    def test_rendering_for_an_environment_apple_does_not_have_is_refused(self) -> None:
        result = endpoint("Sandbox").verify_receipt_data(b64("receipt.der"))
        for environment in ("Xcode", "LocalTesting", "production", ""):
            with self.subTest(environment), self.assertRaises(ValueError):
                result.to_response(environment)
            with self.subTest(environment), self.assertRaises(ValueError):
                result.to_json(environment)

    def test_an_explicit_now_sets_request_date_and_the_clock_is_read_once(self) -> None:
        clock = CountingClock()
        sandbox = endpoint("Sandbox", clock=clock)
        receipt_data = b64("receipt.der")
        body = json.dumps({"receipt-data": receipt_data})

        explicit = sandbox.verify_receipt_result({"receipt-data": receipt_data}, now=EXPLICIT)
        self.assertEqual(0, clock.calls, "an explicit now replaces the clock")
        self.assertEqual(EXPLICIT, explicit.request_date)
        receipt = explicit.to_response()["receipt"]
        self.assertEqual("2025-06-15 12:34:56 Etc/GMT", receipt["request_date"])
        self.assertEqual("1749990896789", receipt["request_date_ms"])
        self.assertEqual("2025-06-15 05:34:56 America/Los_Angeles", receipt["request_date_pst"])
        # Any timezone names the same instant.
        eastern = EXPLICIT.astimezone(timezone(timedelta(hours=-4)))
        self.assertEqual(
            explicit.to_json(), sandbox.verify_receipt_data(receipt_data, now=eastern).to_json()
        )
        self.assertEqual(
            explicit.to_json(), sandbox.verify_receipt_result(body, now=EXPLICIT).to_json()
        )
        self.assertEqual(0, clock.calls)

        # Without one, each call reads the clock exactly once, and rendering
        # (in either environment, any number of times) never reads it again,
        # so one result cannot carry two request dates.
        clocked_calls: list[Callable[[], VerifyReceiptResult]] = [
            lambda: sandbox.verify_receipt_result({"receipt-data": receipt_data}),
            lambda: sandbox.verify_receipt_result(body),
            lambda: sandbox.verify_receipt_data(receipt_data),
        ]
        for call in clocked_calls:
            before = clock.calls
            result = call()
            result.to_json()
            result.to_json("Production")
            result.to_response()
            self.assertEqual(before + 1, clock.calls)
            self.assertEqual(datetime.fromtimestamp(CLOCK_NOW, timezone.utc), result.request_date)
        before = clock.calls
        sandbox.verify_receipt_json(body)
        self.assertEqual(before + 1, clock.calls)

        with self.assertRaises(ValueError):
            sandbox.verify_receipt_data(receipt_data, now=datetime(2025, 6, 15))

    def test_an_explicit_now_does_not_move_certificate_validity(self) -> None:
        # receipt-expired-fresh.der was created after its signing certificate
        # expired; 2020-06-01 is inside that certificate's window. A `now`
        # that reached the chain check would rescue it.
        sandbox = endpoint("Sandbox", "receipt-expired-root.der")
        inside_window = datetime(2020, 6, 1, tzinfo=timezone.utc)
        self.assertTrue(sandbox.verify_receipt_data(b64("receipt-expired-historical.der")).verified)
        result = sandbox.verify_receipt_data(b64("receipt-expired-fresh.der"), now=inside_window)
        self.assertEqual(21003, result.status)
        self.assertEqual(Reason.INVALID_CHAIN, result.failure_reason)

    def test_the_bare_receipt_answers_as_the_json_body_over_every_receipt_fixture(self) -> None:
        # Every receipt the repository has, including the base64 contract
        # strings verbatim (whitespace, base64url, bad padding), through both
        # the bare entry point and a JSON body carrying it.
        roots = [
            *apple_receipt_roots(),
            *(
                x509.load_der_x509_certificate(path.read_bytes())
                for path in sorted(GENERATED.glob("*receipt*root.der"))
            ),
        ]
        receipt_data = [
            b64(path.name)
            for path in sorted(GENERATED.glob("receipt*.der"))
            if not path.name.endswith("root.der")
        ]
        receipt_data += [
            path.read_text() for path in sorted((GENERATED / "receipt-b64").glob("*.txt"))
        ]
        receipt_data += [
            path.read_text() for path in sorted((FIXTURES / "public-receipts").glob("*.b64"))
        ]
        self.assertGreater(len(receipt_data), 40)
        statuses = set()
        for environment in ENVIRONMENTS:
            pinned = VerifyReceiptEndpoint(roots, environment, CountingClock())
            for data in receipt_data:
                request = json.dumps({"receipt-data": data})
                body = pinned.verify_receipt_json(request)
                bare = pinned.verify_receipt_data(data)
                # Every body fits under the 3 MiB request cap, the byte-floor
                # receipt's included, so both entry points agree on all of them.
                self.assertLessEqual(len(request), VerifyReceiptEndpoint.MAX_REQUEST_BYTES)
                self.assertEqual(body, bare.to_json(), data[:40])
                statuses.add(bare.status)
                self.assertNotEqual(Reason.INTERNAL_ERROR, bare.failure_reason, data[:40])
        # The corpus reaches every status except the internal error.
        self.assertEqual({0, 21002, 21003, 21007, 21008}, statuses)

    def test_each_failure_names_its_reason(self) -> None:
        sandbox = endpoint("Sandbox")
        malformed: dict[str, VerifyReceiptResult] = {
            "body not JSON": sandbox.verify_receipt_result("not json"),
            "body a JSON array": sandbox.verify_receipt_result('[{"receipt-data":"AQIDBA=="}]'),
            "body JSON null": sandbox.verify_receipt_result("null"),
            "body nested too deep": sandbox.verify_receipt_result("[" * 100_000),
            "None body": sandbox.verify_receipt_result(None),
            "receipt-data missing": sandbox.verify_receipt_result({}),
            "receipt-data empty": sandbox.verify_receipt_result({"receipt-data": ""}),
            "receipt-data a number": sandbox.verify_receipt_result('{"receipt-data":5}'),
            "receipt-data a list": sandbox.verify_receipt_result({"receipt-data": ["AQIDBA=="]}),
            "bare receipt None": sandbox.verify_receipt_data(None),
            "bare receipt empty": sandbox.verify_receipt_data(""),
        }
        for label, result in malformed.items():
            self.assertEqual(Reason.MALFORMED_REQUEST, result.failure_reason, label)
            self.assertEqual(21002, result.status, label)
            self.assert_invariant(result, label)
        self.assertEqual('{"status":21002}', sandbox.verify_receipt_json("[" * 100_000))

        for label, result in {
            "not base64": sandbox.verify_receipt_result({"receipt-data": "not base64!"}),
            "whitespace only": sandbox.verify_receipt_data("  \n"),
            "not a receipt": sandbox.verify_receipt_result({"receipt-data": "AQIDBA=="}),
        }.items():
            self.assertEqual(Reason.INVALID_RECEIPT_FORMAT, result.failure_reason, label)
            self.assertEqual(21002, result.status, label)
            self.assert_invariant(result, label)

        foreign = sandbox.verify_receipt_data(b64("receipt-foreign.der"))
        self.assertEqual(Reason.INVALID_CHAIN, foreign.failure_reason)
        self.assertEqual(21003, foreign.status)
        tampered = endpoint("Sandbox", "gaps-receipt-root.der").verify_receipt_data(
            b64("receipt-tampered-payload.der")
        )
        self.assertEqual(Reason.INVALID_SIGNATURE, tampered.failure_reason)
        self.assertEqual(21003, tampered.status)

    def test_an_unexpected_exception_is_an_internal_error_not_a_raise(self) -> None:
        # The endpoint promises never to raise on a request, so a bug inside
        # it must come back as 21009 with the exception kept for logging.
        for environment in ENVIRONMENTS:
            result = endpoint(environment).verify_receipt_result(BrokenMapping())
            self.assertEqual(Reason.INTERNAL_ERROR, result.failure_reason)
            self.assertIs(BrokenMapping.error, result.failure_cause)
            self.assertIsNone(result.receipt)
            for render in (result.to_json(), *(result.to_json(e) for e in ENVIRONMENTS)):
                self.assertEqual('{"status":21009}', render)

        boom = ValueError("parser bug")
        with mock.patch(
            "apple_purchase_receipt_verifier.verify_receipt_endpoint.verify_receipt_core",
            side_effect=boom,
        ):
            sandbox = endpoint("Sandbox")
            result = sandbox.verify_receipt_data(b64("receipt.der"))
            self.assertEqual(Reason.INTERNAL_ERROR, result.failure_reason)
            self.assertIs(boom, result.failure_cause)
            self.assertEqual(
                '{"status":21009}',
                sandbox.verify_receipt_json(json.dumps({"receipt-data": b64("receipt.der")})),
            )

    def test_to_json_is_what_verify_receipt_json_answers(self) -> None:
        sandbox = endpoint("Sandbox")
        body = json.dumps({"receipt-data": b64("receipt.der")})
        self.assertEqual(
            sandbox.verify_receipt_json(body), sandbox.verify_receipt_result(body).to_json()
        )
        self.assertEqual(
            sandbox.verify_receipt_json(body),
            sandbox.verify_receipt_result(body).to_json("Sandbox"),
        )
        # The dict is a copy: a caller editing it cannot change a later render.
        result = sandbox.verify_receipt_result(body)
        result.to_response()["status"] = 21003
        self.assertEqual(0, result.to_response()["status"])
        self.assertEqual(json.loads(result.to_json()), result.to_response())

    def test_only_the_endpoint_creates_a_result_and_it_cannot_be_changed(self) -> None:
        # A caller must not be able to fabricate or edit a status 0.
        with self.assertRaises(TypeError):
            VerifyReceiptResult()
        result = endpoint("Production").verify_receipt_data(b64("receipt.der"))
        with self.assertRaises(AttributeError):
            result.status = 0  # type: ignore[misc]
        with self.assertRaises(AttributeError):
            result._environment = "Sandbox"
        with self.assertRaises(AttributeError):
            del result._receipt
        self.assertEqual(21007, result.status)

    def test_the_mapping_in_mapping_out_method_is_gone(self) -> None:
        # Breaking change: verify_receipt(body) is now
        # verify_receipt_result(body).to_response().
        self.assertFalse(hasattr(VerifyReceiptEndpoint, "verify_receipt"))


if __name__ == "__main__":
    unittest.main()
