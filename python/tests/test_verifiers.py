"""Mirrors the Java/Node test matrices over the shared fixture sets:
fixtures/generated/ (cross-language parity) and fixtures/apple-official/
(Apple's own library fixtures)."""

import base64
import datetime
import json
import random
import time
import unittest
from pathlib import Path

from asn1crypto import cms as asn1cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from apple_purchase_receipt_verifier import (
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

    def test_rejects_receipt_issued_for_another_app(self):
        # The control that stops app A's genuine receipt from unlocking app B:
        # everything below the bundle id verifies, only the claim differs.
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], "com.other.app")
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(fixture("generated", "receipt.der"))
        self.assertEqual(ctx.exception.reason, "WRONG_BUNDLE_ID")

    def test_bundled_apple_roots_are_all_three_published_roots(self):
        # Both sets carry all three published Apple roots (PLAN D15).
        for roots in (apple_jws_roots(), apple_receipt_roots()):
            subjects = [c.subject.rfc4514_string() for c in roots]
            self.assertEqual(3, len(subjects), subjects)
            self.assertTrue(any("Apple Root CA - G2" in s for s in subjects), subjects)
            self.assertTrue(any("Apple Root CA - G3" in s for s in subjects), subjects)
            # The file Apple labels "Apple Inc. Root" has subject CN=Apple Root CA.
            self.assertTrue(any(s.startswith("CN=Apple Root CA,") for s in subjects), subjects)


if __name__ == "__main__":
    unittest.main()


class VerifyReceiptEndpointTest(unittest.TestCase):
    """verifyReceipt-compat semantics over the shared receipt fixture."""

    def endpoint(self, environment):
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint
        return VerifyReceiptEndpoint(
            [cert("generated", "receipt-root.der")], environment)

    def request(self):
        return {"receipt-data": base64.b64encode(
            fixture("generated", "receipt.der")).decode()}

    @staticmethod
    def without_request_date(response):
        # request_date is "now": two calls legitimately disagree on it.
        copy = json.loads(json.dumps(response))
        for key in ("request_date", "request_date_ms", "request_date_pst"):
            copy.get("receipt", {}).pop(key, None)
        return copy

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
        # Full COMPARISON.md "full fidelity" field set (parity with Node).
        self.assertEqual(receipt["original_application_version"], "1.0")
        for key in ("request_date", "request_date_ms", "request_date_pst"):
            self.assertIn(key, receipt)
        coins = next(p for p in receipt["in_app"] if p["product_id"] == "com.example.app.coins100")
        self.assertEqual(coins["transaction_id"], "70000000000001")
        self.assertEqual(coins["original_transaction_id"], "70000000000001")
        for key in ("purchase_date", "purchase_date_ms", "purchase_date_pst"):
            self.assertIn(key, coins)
        vip = next(p for p in receipt["in_app"] if p["product_id"] == "com.example.app.vip")
        self.assertEqual(vip["expires_date"], "2030-02-01 09:30:00 Etc/GMT")
        self.assertIn("expires_date_ms", vip)
        self.assertIn("expires_date_pst", vip)

    def test_routes_sandbox_receipt_on_production_to_21007(self):
        response = self.endpoint("Production").verify_receipt(self.request())
        self.assertEqual(response["status"], 21007)
        self.assertNotIn("receipt", response)
        self.assertNotIn("environment", response)

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

    def test_verify_receipt_json_pins_the_wire_types(self):
        body = self.endpoint("Sandbox").verify_receipt_json(json.dumps(self.request()))
        # Raw bytes, not just the parse: status is a JSON number and every
        # number-shaped receipt field is a JSON string, as Apple sends them.
        self.assertIn('"status":0', body)
        self.assertIn('"quantity":"1"', body)
        self.assertIn('"web_order_line_item_id":"42"', body)
        parsed = json.loads(body)
        self.assertIsInstance(parsed["status"], int)
        self.assertNotIsInstance(parsed["status"], bool)
        self.assertEqual(parsed["environment"], "Sandbox")
        receipt = parsed["receipt"]
        self.assertIsInstance(receipt["receipt_creation_date_ms"], str)
        self.assertIsInstance(receipt["request_date_ms"], str)
        for purchase in receipt["in_app"]:
            self.assertIsInstance(purchase["quantity"], str)
            self.assertIsInstance(purchase["web_order_line_item_id"], str)
            self.assertIsInstance(purchase["purchase_date_ms"], str)

    def test_verify_receipt_json_renders_is_in_intro_offer_period_as_a_string(self):
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint
        receipt_data = (FIXTURES / "public-receipts" / "receipt-sandbox-g5.b64") \
            .read_text().strip()
        body = VerifyReceiptEndpoint(apple_receipt_roots(), "Sandbox") \
            .verify_receipt_json(json.dumps({"receipt-data": receipt_data}))
        self.assertIn('"is_in_intro_offer_period":"false"', body)
        purchases = json.loads(body)["receipt"]["in_app"]
        self.assertTrue(purchases)
        for purchase in purchases:
            self.assertIsInstance(purchase["is_in_intro_offer_period"], str)

    def test_verify_receipt_json_omits_receipt_and_environment_on_non_zero_status(self):
        self.assertEqual(
            self.endpoint("Production").verify_receipt_json(json.dumps(self.request())),
            '{"status":21007}')

    def test_verify_receipt_json_answers_21002_for_a_body_that_is_not_an_object(self):
        endpoint = self.endpoint("Sandbox")
        for body in ("", "not json", "{", "[]", '[{"receipt-data":"x"}]', "null",
                     "3", '"receipt"', "true", None):
            self.assertEqual(endpoint.verify_receipt_json(body), '{"status":21002}', body)

    def test_verify_receipt_json_matches_the_mapping_api(self):
        endpoint = self.endpoint("Sandbox")
        via_map = endpoint.verify_receipt(self.request())
        via_json = json.loads(endpoint.verify_receipt_json(json.dumps(self.request())))
        self.assertEqual(self.without_request_date(via_json),
                         self.without_request_date(via_map))


class ReviewFixesTest(unittest.TestCase):
    """Regression tests for the adversarial-review findings + PLAN D10."""

    def test_routes_receipt_type_variants_per_apple_matrix(self):
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint
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
        from apple_purchase_receipt_verifier import is_transaction_active_at
        self.assertTrue(is_transaction_active_at({}, 1000))
        self.assertFalse(is_transaction_active_at({"revocationDate": 500}, 1000))
        self.assertFalse(is_transaction_active_at({"expiresDate": 900}, 1000))
        self.assertTrue(is_transaction_active_at({"expiresDate": 2000}, 1000))

    def test_unwraps_double_wrapped_receipt_payload(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        receipt = verifier.verify(fixture("generated", "receipt-double-wrapped.der"))
        self.assertEqual(receipt.app_version, "1.2.3")


class PublicReceiptsTest(unittest.TestCase):
    """Genuine Apple-signed receipts vs the REAL pinned Apple root."""

    def receipt(self, name):
        return (FIXTURES / "public-receipts" / f"{name}.b64").read_text().strip()

    def test_verifies_genuine_sandbox_receipt(self):
        verifier = ReceiptVerifier(apple_receipt_roots(), "dev.bonzer.weeka.app")
        self.assertEqual(verifier.verify(self.receipt("receipt-sandbox-g5")).receipt_type,
                         "ProductionSandbox")

    def test_verifies_genuine_legacy_sha1_chain_receipt(self):
        verifier = ReceiptVerifier(apple_receipt_roots(), "com.nutcall.alert")
        receipt = verifier.verify(self.receipt("receipt-sandbox-legacy"))
        self.assertEqual(len(receipt.in_app_purchases), 187)

    def test_rejects_xcode_signed_public_receipt(self):
        verifier = ReceiptVerifier(apple_receipt_roots(), "*")
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(self.receipt("receipt-xcode-with-purchases"))
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")


class ParityTest(unittest.TestCase):
    """Anti-forgery controls and signing-time behaviour, at parity with Java."""

    def test_rejects_receipt_signer_without_marker_oid(self):
        v = ReceiptVerifier([cert("generated", "receipt-no-signer-oid-root.der")], BUNDLE)
        with self.assertRaises(VerificationError) as ctx:
            v.verify(fixture("generated", "receipt-no-signer-oid.der"))
        self.assertEqual(ctx.exception.reason, "INVALID_CERTIFICATE_PURPOSE")

    def test_rejects_jws_without_leaf_or_intermediate_oid(self):
        leaf = JwsVerifier([cert("generated", "jws-no-leaf-oid-root.der")], BUNDLE, ["Sandbox"])
        with self.assertRaises(VerificationError) as ctx:
            leaf.verify_transaction(text("generated", "transaction-no-leaf-oid.jws"))
        self.assertEqual(ctx.exception.reason, "INVALID_CERTIFICATE_PURPOSE")
        inter = JwsVerifier([cert("generated", "jws-no-intermediate-oid-root.der")], BUNDLE, ["Sandbox"])
        with self.assertRaises(VerificationError) as ctx:
            inter.verify_transaction(text("generated", "transaction-no-intermediate-oid.jws"))
        self.assertEqual(ctx.exception.reason, "INVALID_CERTIFICATE_PURPOSE")

    def test_production_app_transaction_enforces_app_apple_id(self):
        good = JwsVerifier([cert("generated", "jws-root.der")], BUNDLE, ["Production"], app_apple_id=123456789)
        self.assertEqual(good.verify_app_transaction(
            text("generated", "app-transaction-production.jws"))["appAppleId"], 123456789)
        bad = JwsVerifier([cert("generated", "jws-root.der")], BUNDLE, ["Production"], app_apple_id=999)
        with self.assertRaises(VerificationError) as ctx:
            bad.verify_app_transaction(text("generated", "app-transaction-production.jws"))
        self.assertEqual(ctx.exception.reason, "WRONG_APP_APPLE_ID")

    def test_receipt_signing_time_cert_validity(self):
        v = ReceiptVerifier([cert("generated", "receipt-expired-root.der")], BUNDLE)
        self.assertEqual(v.verify(fixture("generated", "receipt-expired-historical.der")).app_version, "1.2.3")
        with self.assertRaises(VerificationError) as ctx:
            v.verify(fixture("generated", "receipt-expired-fresh.der"))
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")


def tlv(tag, contents):
    """DER tag-length-value — these builders emit structures no encoder would
    produce for them (empty value sets, wrong tags, 5000-deep nesting)."""
    if len(contents) < 0x80:
        return bytes([tag, len(contents)]) + contents
    length = len(contents).to_bytes((len(contents).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + contents


def date_payload(value):
    """A receipt payload SET carrying only attribute 12 (creation date)."""
    attribute = tlv(0x02, b"\x0c") + tlv(0x02, b"\x01") + tlv(0x04, tlv(0x16, value.encode()))
    return tlv(0x31, tlv(0x30, attribute))


def payload_with_attribute_type(type_bytes):
    """A receipt payload SET carrying the creation date and one attribute
    whose type INTEGER is ``type_bytes``."""
    date = tlv(0x02, b"\x0c") + tlv(0x02, b"\x01") + tlv(0x04, tlv(0x16, b"2024-08-06T12:00:00Z"))
    probe = tlv(0x02, type_bytes) + tlv(0x02, b"\x01") + tlv(0x04, b"")
    return tlv(0x31, tlv(0x30, date) + tlv(0x30, probe))


# An anonymous 162-byte blob: no certificates, no signature, one creation date
# of 0001-01-01T00:00:00+10:00. The payload is parsed before the chain check,
# so this reaches the date decoder against the real pinned Apple roots.
OUT_OF_RANGE_DATE_RECEIPT = (
    "MIGfBgkqhkiG9w0BBwKggZEwgY4CAQExDzANBglghkgBZQMEAgEFADA2BgkqhkiG9w0BBwGgKQQnMSUw"
    "IwIBDAIBAQQbFhkwMDAxLTAxLTAxVDAwOjAwOjAwKzEwOjAwMUAwPgIBATARMAwxCjAIBgNVBAMMAXgC"
    "AQEwDQYJYIZIAWUDBAIBBQAwDQYJKoZIhvcNAQEBBQAECAAAAAAAAAAA")

_OID_MESSAGE_DIGEST = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04"
_OID_SIGNING_TIME = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05"
_OID_UNKNOWN = b"\x06\x03\x2a\x03\x04"


def hostile_attribute_sets():
    """signedAttrs an attacker can splice in, one per raw exception class."""
    nested = b""
    for _ in range(5000):
        nested = tlv(0x30, nested)
    return {
        "empty messageDigest value set":
            tlv(0x31, tlv(0x30, _OID_MESSAGE_DIGEST + tlv(0x31, b""))),
        "two messageDigest values":
            tlv(0x31, tlv(0x30, _OID_MESSAGE_DIGEST
                          + tlv(0x31, tlv(0x04, b"\x00" * 32) + tlv(0x04, b"\x01" * 32)))),
        "messageDigest that is not an octet string":
            tlv(0x31, tlv(0x30, _OID_MESSAGE_DIGEST + tlv(0x31, tlv(0x02, b"\x01")))),
        "signingTime with month 13":
            tlv(0x31, tlv(0x30, _OID_SIGNING_TIME
                          + tlv(0x31, tlv(0x17, b"241301000000Z")))),
        "unknown attribute holding invalid UTF-8":
            tlv(0x31, tlv(0x30, _OID_UNKNOWN + tlv(0x31, tlv(0x0C, b"\xff\xfe")))),
        "unknown attribute nested 5000 deep":
            tlv(0x31, tlv(0x30, _OID_UNKNOWN + tlv(0x31, nested))),
        "integer where the attribute OID belongs":
            tlv(0x31, tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, b""))),
    }


def spliced_receipt(signed_attrs=None, digest_algorithm=None, signature=None):
    """The shared receipt with attacker-supplied SignerInfo fields spliced in.
    Its certificates and payload are untouched, so the chain and marker-OID
    checks still pass and the decoder runs on hostile bytes before the
    signature check gets to reject them."""
    info = asn1cms.ContentInfo.load(fixture("generated", "receipt.der"))
    signed_data = info["content"]
    signer = signed_data["signer_infos"][0]
    spliced = tlv(0x30, signer["version"].dump()
                  + signer["sid"].dump()
                  + (digest_algorithm or signer["digest_algorithm"].dump())
                  + (b"\xa0" + signed_attrs[1:] if signed_attrs  # SET tag -> implicit [0]
                     else signer["signed_attrs"].dump())
                  + signer["signature_algorithm"].dump()
                  + (signature or signer["signature"].dump()))
    body = (signed_data["version"].dump()
            + signed_data["digest_algorithms"].dump()
            + signed_data["encap_content_info"].dump()
            + signed_data["certificates"].dump()
            + signed_data["crls"].dump()
            + tlv(0x31, spliced))
    return tlv(0x30, info["content_type"].dump() + tlv(0xA0, tlv(0x30, body)))


class HostileInputTest(unittest.TestCase):
    """The payload and the signedAttrs are decoded BEFORE any signature check,
    so an attacker reaches both decoders with arbitrary bytes and neither may
    leak a raw Python exception."""

    def test_rejects_a_date_astimezone_cannot_convert(self):
        verifier = ReceiptVerifier(apple_receipt_roots(), "com.anything")
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(OUT_OF_RANGE_DATE_RECEIPT)
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")

    def test_rejects_a_date_without_a_timezone_designator(self):
        # Driven through the payload parser directly: an unsigned blob fails
        # the same way whether or not the date is rejected, so only the parser
        # can show that a naive date is not silently read as server-local time
        # (a 26-hour spread across hosts, and creation_date is where chain
        # validity is anchored).
        from apple_purchase_receipt_verifier.receipt import _parse_payload
        self.assertEqual(
            _parse_payload(date_payload("2024-08-06T12:00:00Z")).creation_date.isoformat(),
            "2024-08-06T12:00:00+00:00")
        with self.assertRaises(VerificationError) as ctx:
            _parse_payload(date_payload("2024-08-06T12:00:00"))
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")

    def test_rejects_attribute_integers_at_the_edge_of_each_guard(self):
        # Driven through the payload parser like the date above. 0x80 is the
        # smallest leading byte of a negative two's-complement INTEGER and
        # nine bytes is one past the cap; a comparison one step wider admits
        # each. Eight bytes under 0x80 is the largest value the cap admits.
        from apple_purchase_receipt_verifier.receipt import _parse_payload
        for name, type_bytes, message in (
                ("leading byte 0x80", b"\x80", "negative receipt integer"),
                ("nine bytes", b"\x00" * 8 + b"\x01", "out of range")):
            with self.subTest(name):
                with self.assertRaises(VerificationError) as ctx:
                    _parse_payload(payload_with_attribute_type(type_bytes))
                self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")
                self.assertIn(message, str(ctx.exception))
        largest = _parse_payload(payload_with_attribute_type(b"\x7f" + b"\xff" * 7))
        self.assertEqual(largest.unknown_attributes, {2**63 - 1: [b""]})

    def test_contains_hostile_signed_attrs(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        for name, attributes in hostile_attribute_sets().items():
            with self.subTest(name):
                with self.assertRaises(VerificationError):
                    verifier.verify(spliced_receipt(signed_attrs=attributes))

    def test_rejects_a_message_digest_with_more_than_one_value(self):
        # RFC 5652 §5.3 allows exactly one value; unguarded, the decoder
        # silently takes the first of whatever list the attacker supplied.
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(spliced_receipt(
                signed_attrs=hostile_attribute_sets()["two messageDigest values"]))
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")

    def test_verify_raises_nothing_but_verification_error(self):
        # The absent test that let the two crashes above ship: any other
        # exception type propagates out of assertRaises and fails the subtest.
        # Covers the payload and SignerInfo decoders; a mutated embedded
        # certificate reaches other decoders that this corpus does not exercise.
        pinned = ReceiptVerifier(apple_receipt_roots(), "com.anything")
        generated = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        hostile = hostile_attribute_sets()
        corpus = [
            ("empty", pinned, b""),
            ("garbage", pinned, b"\x01\x02\x03\x04"),
            ("not base64", pinned, "!!!not-base64!!!"),
            ("truncated receipt", generated, fixture("generated", "receipt.der")[:200]),
            ("out-of-range date", pinned, OUT_OF_RANGE_DATE_RECEIPT),
            ("base64 hostile signedAttrs", generated, base64.b64encode(spliced_receipt(
                signed_attrs=hostile["empty messageDigest value set"])).decode()),
            ("nested signedAttrs", generated, spliced_receipt(
                signed_attrs=hostile["unknown attribute nested 5000 deep"])),
            ("digest algorithm that is not an OID", generated, spliced_receipt(
                digest_algorithm=tlv(0x30, tlv(0x02, b"\x01")))),
            ("signature that is not an octet string", generated, spliced_receipt(
                signature=tlv(0x02, b"\x01"))),
        ]
        for name, verifier, blob in corpus:
            with self.subTest(name):
                with self.assertRaises(VerificationError):
                    verifier.verify(blob)

    def test_mutations_of_a_genuine_receipt_raise_nothing_else_either(self):
        # The corpus above says in its own comment that it does not reach the
        # decoders behind a mutated embedded certificate, and it does not: this
        # sweep found 115 escapes it missed, out of chain building
        # (UnsupportedAlgorithm, ValueError) and SignerInfo parsing. Mutating a
        # receipt that is otherwise valid is what carries the input deep enough
        # to reach them, so the corpus and this sweep are not redundant.
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        genuine = fixture("generated", "receipt.der")
        rnd = random.Random(1234)  # fixed seed: a failure must be reproducible
        for i in range(2000):
            mutant = bytearray(genuine)
            for _ in range(rnd.randint(1, 3)):
                mutant[rnd.randrange(len(mutant))] = rnd.randrange(256)
            try:
                verifier.verify(bytes(mutant))
            except VerificationError:
                pass
            except Exception as e:  # noqa: BLE001 - the assertion is the point
                self.fail(f"mutation {i} leaked {type(e).__name__}: {e}")


# The two issuer names in the shared generated chain. Decoy certificates carry
# them so each one stays a candidate the path builder must actually verify,
# rather than one it can reject on a name comparison.
MESH_NAMES = ("Fake WWDR CA", "Fake Apple Inc Root")


def cross_signed_mesh(layers=14, branching=2):
    """``branching`` CA certificates per layer, each cross-signed by every node
    of the layer above and the top layer wrapped back onto the bottom, so no
    path ever terminates — the shape that makes a path builder without a length
    bound explore b**L paths (swift-certificates: 3.9 s at L=14, x3.8 per two
    added layers). Every certificate is a CA, valid now, and named after the
    layer's issuer, so nothing but the count disqualifies it as a candidate."""
    now = datetime.datetime.now(datetime.timezone.utc)
    keys = [[rsa.generate_private_key(public_exponent=65537, key_size=2048)
             for _ in range(branching)] for _ in range(layers)]
    certificates = []
    for layer in range(layers):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, MESH_NAMES[layer % 2])])
        above = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, MESH_NAMES[(layer + 1) % 2])])
        for key in keys[layer]:
            for issuer in keys[(layer + 1) % layers]:
                certificates.append((x509.CertificateBuilder()
                    .subject_name(name).issuer_name(above)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=3650))
                    .not_valid_after(now + datetime.timedelta(days=3650))
                    .add_extension(x509.BasicConstraints(ca=True, path_length=None),
                                   critical=True)
                    .sign(issuer, hashes.SHA256()))
                    .public_bytes(serialization.Encoding.DER))
    return certificates


def receipt_with_extra_certificates(extra):
    """The shared receipt with ``extra`` certificates spliced in ahead of its
    own. Payload, chain and signature are untouched, so without a bound on the
    count everything still verifies — after the extras have been parsed and
    offered to path building."""
    info = asn1cms.ContentInfo.load(fixture("generated", "receipt.der"))
    signed_data = info["content"]
    genuine = [choice.chosen.dump() for choice in signed_data["certificates"]]
    body = (signed_data["version"].dump()
            + signed_data["digest_algorithms"].dump()
            + signed_data["encap_content_info"].dump()
            + tlv(0xA0, b"".join(extra + genuine))
            + signed_data["crls"].dump()
            + signed_data["signer_infos"].dump())
    return tlv(0x30, info["content_type"].dump() + tlv(0xA0, tlv(0x30, body)))


# A SEQUENCE holding an INTEGER: enough of a certificate for asn1crypto to
# count it among the CertificateChoices, and not enough for cryptography, which
# rejects it on the first field of the TBSCertificate.
NOT_A_CERTIFICATE = tlv(0x30, tlv(0x02, b"\x01"))


def embedded_certificate_count(receipt):
    der = base64.b64decode(receipt) if isinstance(receipt, str) else receipt
    return len(asn1cms.ContentInfo.load(der)["content"]["certificates"])


class EmbeddedCertificateFloodTest(unittest.TestCase):
    """The embedded certificates are attacker-supplied and are parsed and
    offered to path building before anything about the receipt has been
    verified, so their count is bounded before any of that runs."""

    @classmethod
    def setUpClass(cls):
        cls.mesh = cross_signed_mesh()

    def verifier(self):
        return ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)

    def test_rejects_a_receipt_embedding_more_certificates_than_a_chain_holds(self):
        receipt = receipt_with_extra_certificates(self.mesh[:8])  # 8 + the chain's own 3
        self.assertEqual(11, embedded_certificate_count(receipt))
        with self.assertRaises(VerificationError) as ctx:
            self.verifier().verify(receipt)
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")
        self.assertIn("11 certificates", str(ctx.exception))
        self.assertIn("more than the 10", str(ctx.exception))

    def test_admits_a_receipt_embedding_exactly_the_bound(self):
        # Seven mesh certificates ahead of the chain's own three is exactly the
        # bound, so the guard stands aside and the receipt verifies as it
        # would without them.
        receipt = receipt_with_extra_certificates(self.mesh[:7])
        self.assertEqual(10, embedded_certificate_count(receipt))
        self.verifier().verify(receipt)

    def test_counts_the_embedded_certificates_before_parsing_any_of_them(self):
        # Eight of the eleven are not certificates at all, so where the count is
        # checked decides which rejection a caller gets: counting first names the
        # count, parsing first reports a malformed PKCS#7 instead. That is the
        # only difference the two orderings have that a test can see — the work
        # the ordering saves is measured, not asserted (see the mesh below).
        receipt = receipt_with_extra_certificates([NOT_A_CERTIFICATE] * 8)
        self.assertEqual(11, embedded_certificate_count(receipt))
        with self.assertRaises(VerificationError) as ctx:
            self.verifier().verify(receipt)
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")
        self.assertIn("11 certificates", str(ctx.exception))

    def test_rejects_a_cross_signed_certificate_mesh_promptly(self):
        # Why the bound exists: this mesh costs the sender nothing and is what
        # a path builder that backtracks spends b**L on (swift-certificates:
        # 3.9 s at L=14, and tens of seconds two layers further). This
        # implementation walks at most 6 candidates deep, so uncapped it pays
        # one RSA verification per decoy instead — 4.4 ms here, against 1.3 ms
        # for the genuine receipt. The budget is ~4000x the genuine cost so a
        # loaded runner cannot flake it, and only a combinatorial regression
        # can exceed it.
        receipt = receipt_with_extra_certificates(self.mesh)
        self.assertEqual(59, embedded_certificate_count(receipt))
        started = time.perf_counter()
        with self.assertRaises(VerificationError) as ctx:
            self.verifier().verify(receipt)
        elapsed = time.perf_counter() - started
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")
        self.assertLess(elapsed, 5.0, f"rejecting the mesh took {elapsed:.3f}s")

    def test_limit_clears_the_genuine_receipts_it_has_to_admit(self):
        # Read rather than asserted: the bound is only safe while it stays
        # above what Apple actually embeds.
        from apple_purchase_receipt_verifier.receipt import _MAX_EMBEDDED_CERTIFICATES
        counts = {name: embedded_certificate_count(
                      (FIXTURES / "public-receipts" / f"{name}.b64").read_text().strip())
                  for name in ("receipt-sandbox-g5", "receipt-sandbox-legacy",
                               "receipt-xcode-with-purchases")}
        self.assertLess(max(counts.values()), _MAX_EMBEDDED_CERTIFICATES, counts)
