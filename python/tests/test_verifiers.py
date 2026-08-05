"""Mirrors the Java/Node test matrices over the shared fixture sets:
fixtures/generated/ (cross-language parity) and fixtures/apple-official/
(Apple's own library fixtures)."""

import base64
import json
import unittest
from pathlib import Path

from cryptography import x509

from apple_purchase_verifier import (
    JwsVerifier,
    ReceiptVerifier,
    VerificationError,
    apple_jws_roots,
    apple_receipt_roots,
)

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
BUNDLE = "com.example.app"
APPLE_BUNDLE = "com.example"
XCODE_BUNDLE = "com.example.naturelab.backyardbirds.example"


def fixture(*segments):
    return (FIXTURES.joinpath(*segments)).read_bytes()


def text(*segments):
    return fixture(*segments).decode("ascii").strip()


def cert(*segments):
    return x509.load_der_x509_certificate(fixture(*segments))


def jws_verifier(**overrides):
    options = dict(
        trusted_roots=[cert("generated", "jws-root.der")],
        bundle_id=BUNDLE,
        accepted_environments=["Sandbox"],
    )
    options.update(overrides)
    return JwsVerifier(**options)


class SharedFixturesTest(unittest.TestCase):
    def test_verifies_shared_transaction_fixture(self):
        payload = jws_verifier().verify_transaction(text("generated", "transaction.jws"))
        self.assertEqual(payload["productId"], f"{BUNDLE}.pro")
        self.assertEqual(payload["transactionId"], "2000000000000001")
        self.assertEqual(payload["signedDate"], 1722945600000)

    def test_verifies_shared_app_transaction_fixture(self):
        payload = jws_verifier(app_apple_id=123456789).verify_app_transaction(
            text("generated", "app-transaction.jws"))
        self.assertEqual(payload["appAppleId"], 123456789)
        self.assertEqual(payload["applicationVersion"], "1.2.3")

    def test_expired_chain_fixtures_behave_as_manifested(self):
        verifier = jws_verifier(trusted_roots=[cert("generated", "jws-expired-root.der")])
        historical = verifier.verify_transaction(text("generated", "expired-cert-historical.jws"))
        self.assertEqual(historical["signedDate"], 1590969600000)
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify_transaction(text("generated", "expired-cert-fresh.jws"))
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")

    def test_verifies_shared_receipt_fixture_with_device_hash(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        guid = bytes.fromhex(text("generated", "device-guid.hex"))
        receipt = verifier.verify(fixture("generated", "receipt.der"), guid)
        self.assertEqual(receipt.app_version, "1.2.3")
        self.assertEqual(receipt.creation_date.isoformat(), "2024-08-06T12:00:00+00:00")
        self.assertEqual(len(receipt.in_app_purchases), 2)
        vip = next(p for p in receipt.in_app_purchases if p.product_id == f"{BUNDLE}.vip")
        self.assertEqual(vip.expires_date.isoformat(), "2030-02-01T09:30:00+00:00")
        self.assertEqual(vip.web_order_line_item_id, 42)

    def test_rejects_shared_foreign_root_receipt(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(fixture("generated", "receipt-foreign.der"))
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")


class AppleOfficialFixturesTest(unittest.TestCase):
    def apple_verifier(self):
        return JwsVerifier(
            trusted_roots=[cert("apple-official", "certs", "testCA.der")],
            bundle_id=APPLE_BUNDLE,
            accepted_environments=["Sandbox"],
        )

    def test_verifies_apple_transaction_info(self):
        payload = self.apple_verifier().verify_transaction(
            text("apple-official", "mock_signed_data", "transactionInfo"))
        self.assertEqual(payload["bundleId"], APPLE_BUNDLE)
        self.assertEqual(payload["environment"], "Sandbox")
        self.assertEqual(payload["signedDate"], 1672956154000)

    def test_verifies_apple_renewal_info_and_notification(self):
        verifier = self.apple_verifier()
        renewal = verifier.verify_raw(text("apple-official", "mock_signed_data", "renewalInfo"))
        self.assertEqual(renewal["environment"], "Sandbox")
        notification = verifier.verify_raw(
            text("apple-official", "mock_signed_data", "testNotification"))
        self.assertEqual(notification["notificationType"], "TEST")

    def test_rejects_apple_negative_fixtures(self):
        verifier = self.apple_verifier()
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify_transaction(
                text("apple-official", "mock_signed_data", "wrongBundleId"))
        self.assertEqual(ctx.exception.reason, "WRONG_BUNDLE_ID")
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify_transaction(
                text("apple-official", "mock_signed_data", "missingX5CHeaderClaim"))
        self.assertEqual(ctx.exception.reason, "INVALID_JWS_FORMAT")
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify_transaction(
                text("apple-official", "xcode", "xcode-signed-transaction"))
        self.assertEqual(ctx.exception.reason, "INVALID_JWS_FORMAT")

    def test_rejects_xcode_receipt_against_real_apple_roots(self):
        verifier = ReceiptVerifier(apple_receipt_roots(), XCODE_BUNDLE)
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(text("apple-official", "xcode", "xcode-app-receipt-empty"))
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")


class NegativeTest(unittest.TestCase):
    def test_rejects_tampered_payload(self):
        header, payload, signature = text("generated", "transaction.jws").split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["productId"] = f"{BUNDLE}.premium_forever"
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(f"{header}.{forged}.{signature}")
        self.assertEqual(ctx.exception.reason, "INVALID_SIGNATURE")

    def test_rejects_wrong_bundle_environment_and_staleness(self):
        jws = text("generated", "transaction.jws")
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier(bundle_id="com.other.app").verify_transaction(jws)
        self.assertEqual(ctx.exception.reason, "WRONG_BUNDLE_ID")
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier(accepted_environments=["Production"]).verify_transaction(jws)
        self.assertEqual(ctx.exception.reason, "WRONG_ENVIRONMENT")
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier(max_signed_age_millis=60_000).verify_transaction(jws)
        self.assertEqual(ctx.exception.reason, "STALE_PAYLOAD")

    def test_rejects_garbage_and_foreign_root(self):
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction("not-a-jws")
        self.assertEqual(ctx.exception.reason, "INVALID_JWS_FORMAT")
        pinned = jws_verifier(trusted_roots=apple_jws_roots())
        with self.assertRaises(VerificationError) as ctx:
            pinned.verify_transaction(text("generated", "transaction.jws"))
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")

    def test_verify_raw_skips_claim_checks_but_not_signature(self):
        claims = jws_verifier(bundle_id="com.whatever.else").verify_raw(
            text("generated", "transaction.jws"))
        self.assertEqual(claims["bundleId"], BUNDLE)

    def test_rejects_tampered_receipt_and_wrong_guid_and_garbage(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        tampered = bytearray(fixture("generated", "receipt.der"))
        index = bytes(tampered).find(BUNDLE.encode())
        self.assertGreater(index, 0)
        tampered[index] ^= 0x01
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(bytes(tampered))
        self.assertEqual(ctx.exception.reason, "INVALID_SIGNATURE")

        guid = bytearray(bytes.fromhex(text("generated", "device-guid.hex")))
        guid[0] ^= 0x01
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(fixture("generated", "receipt.der"), bytes(guid))
        self.assertEqual(ctx.exception.reason, "DEVICE_HASH_MISMATCH")

        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(b"\x01\x02\x03\x04")
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")

    def test_bundled_apple_roots_load(self):
        self.assertIn("Apple Root CA - G3",
                      apple_jws_roots()[0].subject.rfc4514_string())
        self.assertIn("Apple Root CA",
                      apple_receipt_roots()[0].subject.rfc4514_string())


if __name__ == "__main__":
    unittest.main()


class VerifyReceiptEndpointTest(unittest.TestCase):
    """verifyReceipt-compat semantics over the shared receipt fixture."""

    def endpoint(self, environment):
        from apple_purchase_verifier import VerifyReceiptEndpoint
        return VerifyReceiptEndpoint(
            [cert("generated", "receipt-root.der")], environment)

    def request(self):
        return {"receipt-data": base64.b64encode(
            fixture("generated", "receipt.der")).decode()}

    def test_answers_like_verify_receipt_for_valid_sandbox_receipt(self):
        response = self.endpoint("Sandbox").verify_receipt(self.request())
        self.assertEqual(response["status"], 0)
        self.assertEqual(response["environment"], "Sandbox")
        receipt = response["receipt"]
        self.assertEqual(receipt["receipt_type"], "ProductionSandbox")
        self.assertEqual(receipt["bundle_id"], BUNDLE)
        self.assertEqual(receipt["receipt_creation_date"], "2024-08-06 12:00:00 Etc/GMT")
        self.assertEqual(receipt["receipt_creation_date_ms"], "1722945600000")
        self.assertEqual(receipt["receipt_creation_date_pst"],
                         "2024-08-06 05:00:00 America/Los_Angeles")
        self.assertEqual(len(receipt["in_app"]), 2)
        self.assertEqual(receipt["in_app"][0]["quantity"], "1")
        self.assertEqual(receipt["in_app"][0]["web_order_line_item_id"], "42")

    def test_routes_sandbox_receipt_on_production_to_21007(self):
        self.assertEqual(
            self.endpoint("Production").verify_receipt(self.request())["status"], 21007)

    def test_reports_malformed_requests_as_21002(self):
        endpoint = self.endpoint("Sandbox")
        self.assertEqual(endpoint.verify_receipt({})["status"], 21002)
        self.assertEqual(endpoint.verify_receipt(None)["status"], 21002)
        self.assertEqual(
            endpoint.verify_receipt({"receipt-data": "AQIDBA=="})["status"], 21002)

    def test_reports_unauthentic_receipts_as_21003(self):
        response = self.endpoint("Sandbox").verify_receipt({
            "receipt-data": base64.b64encode(
                fixture("generated", "receipt-foreign.der")).decode()})
        self.assertEqual(response["status"], 21003)


class ReviewFixesTest(unittest.TestCase):
    """Regression tests for the adversarial-review findings + PLAN D10."""

    def test_routes_receipt_type_variants_per_apple_matrix(self):
        from apple_purchase_verifier import VerifyReceiptEndpoint
        cases = [
            ("receipt-type-production.der", True),
            ("receipt-type-vpp.der", True),
            ("receipt-type-vpp-sandbox.der", False),
            ("receipt-no-type.der", False),
        ]
        roots = [cert("generated", "receipt-root.der")]
        for name, is_production in cases:
            body = {"receipt-data": base64.b64encode(fixture("generated", name)).decode()}
            self.assertEqual(
                VerifyReceiptEndpoint(roots, "Production").verify_receipt(body)["status"],
                0 if is_production else 21007, f"{name} on Production")
            self.assertEqual(
                VerifyReceiptEndpoint(roots, "Sandbox").verify_receipt(body)["status"],
                21008 if is_production else 0, f"{name} on Sandbox")

    def test_rejects_trailing_bytes_after_cms(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        padded = fixture("generated", "receipt.der") + b"\x00\xde\xad\xbe"
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(padded)
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")

    def test_exposes_unknown_attributes_for_forward_compatibility(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        receipt = verifier.verify(fixture("generated", "receipt.der"))
        self.assertEqual(receipt.unknown_attributes[9999], [b"\x01\x02\x03"])

    def test_is_transaction_active_at_helper(self):
        from apple_purchase_verifier import is_transaction_active_at
        self.assertTrue(is_transaction_active_at({}, 1000))
        self.assertFalse(is_transaction_active_at({"revocationDate": 500}, 1000))
        self.assertFalse(is_transaction_active_at({"expiresDate": 900}, 1000))
        self.assertTrue(is_transaction_active_at({"expiresDate": 2000}, 1000))

    def test_unwraps_double_wrapped_receipt_payload(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        receipt = verifier.verify(fixture("generated", "receipt-double-wrapped.der"))
        self.assertEqual(receipt.app_version, "1.2.3")
