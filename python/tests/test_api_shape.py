"""The 0.7 public API, pinned: the names a caller imports, the eight reasons,
the pinned Apple roots, the shapes of the results. 0.8 changes what sits
under the API, not the API (docs/rust-core/SURFACE.md), so a change here is
a change to the contract."""

import hashlib
import importlib.util
import inspect
import json
import unittest

import apple_purchase_receipt_verifier as package
from apple_purchase_receipt_verifier import (
    Config,
    Environment,
    Failure,
    JsonPayload,
    Reason,
    ReceiptPayload,
    VerificationResult,
    Verifier,
    apple_status,
    receipt,
)

import _support

# SURFACE.md section 3: the eight reasons, and no others.
REASONS = [
    "MALFORMED",
    "TOO_LARGE",
    "INVALID_SIGNATURE",
    "UNTRUSTED_CHAIN",
    "INVALID_CERTIFICATE",
    "INVALID_CERTIFICATE_PURPOSE",
    "UNREADABLE_PAYLOAD",
    "INTERNAL_ERROR",
]


class NamesTest(unittest.TestCase):
    def test_the_package_exports_exactly_the_0_7_names(self) -> None:
        # 0.7's names less default_roots(): the roots are compiled into the
        # module and the package carries no copy to return.
        self.assertEqual(
            [
                "Config",
                "Environment",
                "Failure",
                "InAppPurchase",
                "JsonPayload",
                "Reason",
                "ReceiptPayload",
                "VERSION",
                "VerificationResult",
                "Verifier",
                "apple_status",
            ],
            sorted(package.__all__),
        )
        for name in package.__all__:
            self.assertTrue(hasattr(package, name), name)

    def test_the_reasons_are_the_eight_of_0_7(self) -> None:
        self.assertEqual(REASONS, [reason.name for reason in Reason])
        self.assertEqual(REASONS, [reason.value for reason in Reason])

    def test_the_verifier_methods_keep_their_0_7_signatures(self) -> None:
        self.assertEqual(["self", "config"], list(inspect.signature(Verifier.__init__).parameters))
        self.assertEqual(
            ["self", "base64"], list(inspect.signature(Verifier.verify_receipt).parameters)
        )
        self.assertEqual(
            ["self", "jws"], list(inspect.signature(Verifier.verify_signed_data).parameters)
        )
        self.assertEqual(
            ["self", "environment", "request_json"],
            list(inspect.signature(Verifier.verify_receipt_endpoint).parameters),
        )

    def test_the_published_bounds_are_the_documented_ones(self) -> None:
        self.assertEqual(10, receipt.MAX_EMBEDDED_CERTIFICATES)
        self.assertEqual(4, receipt.MAX_SIGNER_INFOS)

    def test_the_byte_caps_are_the_modules_and_not_restated(self) -> None:
        # 0.8 drops 0.7's MAX_RECEIPT_BYTES, MAX_REQUEST_BYTES and
        # MAX_JWS_BYTES, as Go and Swift dropped theirs: nothing here read
        # them, and the module enforces the caps (TOO_LARGE). The endpoint
        # and jws modules held nothing else, so they go too.
        self.assertFalse(hasattr(receipt, "MAX_RECEIPT_BYTES"))
        for gone in ("endpoint", "jws"):
            self.assertFalse(hasattr(package, gone))
            self.assertIsNone(importlib.util.find_spec(f"{package.__name__}.{gone}"))

    def test_the_status_codes_are_apples(self) -> None:
        self.assertEqual(
            (0, 21002, 21003, 21007, 21008, 21009),
            (
                apple_status.OK,
                apple_status.MALFORMED_RECEIPT_DATA,
                apple_status.RECEIPT_NOT_AUTHENTICATED,
                apple_status.SANDBOX_RECEIPT_ON_PRODUCTION,
                apple_status.PRODUCTION_RECEIPT_ON_SANDBOX,
                apple_status.INTERNAL_DATA_ACCESS_ERROR,
            ),
        )


class RootsAndConfigTest(unittest.TestCase):
    PINNED = frozenset(
        {
            "b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024",  # Apple Root CA
            "c2b9b042dd57830e7d117dac55ac8ae19407d38e41d88f3215bc3a890444a050",  # G2
            "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179",  # G3
        }
    )

    def test_the_tests_apple_roots_are_the_three_published_apple_roots(self) -> None:
        # The package ships no roots (they are compiled into the module);
        # the tests that pass Apple's roots explicitly read certs/.
        digests = {hashlib.sha256(der).hexdigest() for der in _support.apple_roots()}
        self.assertEqual(self.PINNED, digests)
        self.assertEqual(3, len(_support.apple_roots()))

    def test_config_with_no_arguments_names_no_roots_and_the_system_clock(self) -> None:
        config = Config()
        self.assertIsNone(config.roots, "None: the Apple roots compiled into the module")
        self.assertEqual(config, Config())
        self.assertEqual(config, Config(roots=None, clock=None))
        self.assertIs(type(config.clock()), int)

    def test_the_constructor_replaces_only_what_it_is_given(self) -> None:
        clock = lambda: 5  # noqa: E731
        self.assertEqual((b"a",), Config(roots=[b"a"]).roots)
        self.assertEqual((b"a",), Config(roots=iter([bytearray(b"a")])).roots)
        self.assertIsNone(Config(clock=clock).roots)
        self.assertIs(clock, Config(clock=clock).clock)
        self.assertEqual((), Config(roots=[]).roots, "empty is refused by Verifier, not Config")

    def test_config_is_built_one_way(self) -> None:
        # 0.8 drops 0.7's Config.create and Config.defaults: the
        # constructor with keyword arguments is the one spelling.
        self.assertFalse(hasattr(Config, "create"))
        self.assertFalse(hasattr(Config, "defaults"))
        parameters = list(inspect.signature(Config.__init__).parameters)
        self.assertEqual(["self", "roots", "clock"], parameters)

    def test_a_config_is_immutable(self) -> None:
        with self.assertRaises(AttributeError):
            Config().roots = ()  # type: ignore[misc]


class ResultsTest(unittest.TestCase):
    def test_a_result_holds_exactly_one_of_payload_and_failure(self) -> None:
        failure = Failure(Reason.MALFORMED, "m")
        with self.assertRaises(ValueError):
            VerificationResult()
        with self.assertRaises(ValueError):
            VerificationResult(payload=object(), failure=failure)
        self.assertTrue(VerificationResult(payload=object()).verified)
        self.assertFalse(VerificationResult(failure=failure).verified)

    def test_a_failure_equals_another_with_the_same_reason_and_message_whatever_the_cause(
        self,
    ) -> None:
        one = Failure(Reason.INTERNAL_ERROR, "m", RuntimeError("a"))
        two = Failure(Reason.INTERNAL_ERROR, "m", ValueError("b"))
        self.assertEqual(one, two)
        self.assertEqual(hash(one), hash(two))
        self.assertNotEqual(one, Failure(Reason.MALFORMED, "m"))
        self.assertNotEqual(one, Failure(Reason.INTERNAL_ERROR, "other"))

    def test_the_environment_is_stated_on_the_payloads_and_no_helper_derives_it(self) -> None:
        # DECISIONS.md R42: the module states it; the wrapper keeps no rule.
        self.assertEqual({"PRODUCTION", "SANDBOX"}, {e.name for e in Environment})
        for helper in ("from_receipt_type", "from_jws_environment"):
            self.assertFalse(hasattr(Environment, helper), helper)
        self.assertIsNone(ReceiptPayload().environment)
        self.assertIsNone(JsonPayload(json="{}").environment)
        stated = ReceiptPayload(receipt_type="Xcode", environment=Environment.PRODUCTION)
        self.assertIs(Environment.PRODUCTION, stated.environment, "nothing reads receipt_type")
        self.assertNotIn("environment", json.loads(stated.to_json()))
        signed = JsonPayload(json='{"environment":"Sandbox"}')
        self.assertIsNone(signed.environment, "nothing reads it from the JSON")
        self.assertNotEqual(
            JsonPayload(json="{}", environment=Environment.SANDBOX), JsonPayload(json="{}")
        )

    def test_the_device_hash_is_sha1_over_the_three_inputs(self) -> None:
        expected = hashlib.sha1(b"dev" + b"opaque" + b"bundle").digest()
        self.assertEqual(expected, receipt.device_hash(b"dev", b"opaque", b"bundle"))


if __name__ == "__main__":
    unittest.main()
