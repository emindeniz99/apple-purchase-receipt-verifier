"""Python-only tests over the shared fixture sets. The facts that every
implementation must agree on live in fixtures/cases.json and are run by
tests/test_conformance.py; what is left here is what a shared vector cannot
express: forged and mutated inputs built at run time, the raw JSON wire form,
and the resource bounds."""

import base64
import datetime
import json
import random
import string
import time
import unittest
from pathlib import Path
from typing import Any, ClassVar
from unittest import mock

from apple_purchase_receipt_verifier import (
    JwsVerifier,
    ReceiptVerifier,
    VerificationError,
    VerifyReceiptEndpoint,
    apple_jws_roots,
    apple_receipt_roots,
)
from asn1crypto import cms as asn1cms
from asn1crypto import x509 as asn1x509
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"
BUNDLE = "com.example.app"


def fixture(*segments):
    return (FIXTURES.joinpath(*segments)).read_bytes()


def text(*segments):
    return fixture(*segments).decode("ascii").strip()


def cert(*segments):
    return x509.load_der_x509_certificate(fixture(*segments))


def jws_verifier(**overrides):
    options: dict[str, Any] = dict(
        trusted_roots=[cert("generated", "jws-root.der")],
        bundle_id=BUNDLE,
        accepted_environments=["Sandbox"],
    )
    options.update(overrides)
    return JwsVerifier(**options)


class NegativeTest(unittest.TestCase):
    def test_rejects_tampered_payload(self):
        header, payload, signature = text("generated", "transaction.jws").split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["productId"] = f"{BUNDLE}.premium_forever"
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(f"{header}.{forged}.{signature}")
        self.assertEqual(ctx.exception.reason, "INVALID_SIGNATURE")

    def test_never_rejects_a_payload_for_its_age(self):
        # Freshness is the caller's decision (PLAN.md D5): a payload signed in
        # 2024 still verifies, and its signedDate is there for the caller.
        payload = jws_verifier().verify_transaction(text("generated", "transaction.jws"))
        self.assertEqual(1722945600000, payload["signedDate"])

    def test_rejects_garbage(self):
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction("not-a-jws")
        self.assertEqual(ctx.exception.reason, "INVALID_JWS_FORMAT")

    def test_rejects_tampered_receipt_and_garbage(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        tampered = bytearray(fixture("generated", "receipt.der"))
        index = bytes(tampered).find(BUNDLE.encode())
        self.assertGreater(index, 0)
        tampered[index] ^= 0x01
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(bytes(tampered))
        self.assertEqual(ctx.exception.reason, "INVALID_SIGNATURE")

        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(b"\x01\x02\x03\x04")
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")

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

        return VerifyReceiptEndpoint([cert("generated", "receipt-root.der")], environment)

    def request(self):
        return {"receipt-data": base64.b64encode(fixture("generated", "receipt.der")).decode()}

    @staticmethod
    def without_request_date(response):
        # request_date is "now": two calls legitimately disagree on it.
        copy = json.loads(json.dumps(response))
        for key in ("request_date", "request_date_ms", "request_date_pst"):
            copy.get("receipt", {}).pop(key, None)
        return copy

    def test_renders_the_fields_cases_json_cannot_pin(self):
        # The verdict and every deterministic field are pinned by
        # endpoint/sandbox-receipt-on-sandbox-answers-0 in fixtures/cases.json.
        # What is left here is the COMPARISON.md "full fidelity" field set that
        # a shared vector cannot express: request_date is the wall clock at
        # call time, and the _ms/_pst siblings of each date are asserted by
        # presence rather than by value.
        receipt = (
            self.endpoint("Sandbox").verify_receipt_result(self.request()).to_response()["receipt"]
        )
        self.assertEqual(receipt["in_app"][0]["web_order_line_item_id"], "42")
        for key in ("request_date", "request_date_ms", "request_date_pst"):
            self.assertIn(key, receipt)
        coins = next(p for p in receipt["in_app"] if p["product_id"] == "com.example.app.coins100")
        for key in ("purchase_date", "purchase_date_ms", "purchase_date_pst"):
            self.assertIn(key, coins)
        vip = next(p for p in receipt["in_app"] if p["product_id"] == "com.example.app.vip")
        self.assertIn("expires_date_ms", vip)
        self.assertIn("expires_date_pst", vip)

    def test_reports_malformed_requests_as_21002(self):
        endpoint = self.endpoint("Sandbox")
        self.assertEqual(endpoint.verify_receipt_result({}).to_response()["status"], 21002)
        self.assertEqual(endpoint.verify_receipt_result(None).to_response()["status"], 21002)
        self.assertEqual(
            endpoint.verify_receipt_result({"receipt-data": "AQIDBA=="}).to_response()["status"],
            21002,
        )

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

        receipt_data = (FIXTURES / "public-receipts" / "receipt-sandbox-g5.b64").read_text().strip()
        body = VerifyReceiptEndpoint(apple_receipt_roots(), "Sandbox").verify_receipt_json(
            json.dumps({"receipt-data": receipt_data})
        )
        self.assertIn('"is_in_intro_offer_period":"false"', body)
        purchases = json.loads(body)["receipt"]["in_app"]
        self.assertTrue(purchases)
        for purchase in purchases:
            self.assertIsInstance(purchase["is_in_intro_offer_period"], str)

    def test_verify_receipt_json_omits_receipt_and_environment_on_non_zero_status(self):
        self.assertEqual(
            self.endpoint("Production").verify_receipt_json(json.dumps(self.request())),
            '{"status":21007}',
        )

    def test_verify_receipt_json_answers_21002_for_a_body_that_is_not_an_object(self):
        endpoint = self.endpoint("Sandbox")
        for body in (
            "",
            "not json",
            "{",
            "[]",
            '[{"receipt-data":"x"}]',
            "null",
            "3",
            '"receipt"',
            "true",
            None,
        ):
            self.assertEqual(endpoint.verify_receipt_json(body), '{"status":21002}', body)

    def test_verify_receipt_json_matches_the_mapping_api(self):
        endpoint = self.endpoint("Sandbox")
        via_map = endpoint.verify_receipt_result(self.request()).to_response()
        via_json = json.loads(endpoint.verify_receipt_json(json.dumps(self.request())))
        self.assertEqual(self.without_request_date(via_json), self.without_request_date(via_map))


class ReceiptIdsAttributesTest(unittest.TestCase):
    """Attribute types 1 (app item id), 15 (download id), 16 (version
    external identifier) and 1713 (is trial period). The cross-language
    contract is pinned by receipt/ids-are-decoded,
    receipt/ids-absent-when-not-carried, endpoint/ids-echo-apples-keys and
    endpoint/ids-absent-are-omitted in fixtures/cases.json; what's left here
    is proving the 2^63-1 download id survives as exact digits rather than a
    rounded double, both through the accessor and through the endpoint's raw
    JSON text, and that the four types leave unknownAttributes."""

    def receipt(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-ids-root.der")], BUNDLE)
        return verifier.verify(fixture("generated", "receipt-ids.der"))

    def test_decodes_the_four_attributes_with_exact_digits(self):
        receipt = self.receipt()
        self.assertEqual(receipt.app_item_id, 1234567890)
        self.assertEqual(receipt.download_id, 9223372036854775807)  # 2**63 - 1
        self.assertEqual(receipt.version_external_identifier, 456789012)
        coins = next(
            p for p in receipt.in_app_purchases if p.product_id == "com.example.app.coins100"
        )
        vip = next(p for p in receipt.in_app_purchases if p.product_id == "com.example.app.vip")
        self.assertEqual(coins.is_trial_period, 0)
        self.assertEqual(vip.is_trial_period, 1)

    def test_absent_attributes_are_none_not_zero(self):
        receipt = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE).verify(
            fixture("generated", "receipt.der")
        )
        self.assertIsNone(receipt.app_item_id)
        self.assertIsNone(receipt.download_id)
        self.assertIsNone(receipt.version_external_identifier)
        coins = next(
            p for p in receipt.in_app_purchases if p.product_id == "com.example.app.coins100"
        )
        self.assertIsNone(coins.is_trial_period)

    def test_the_four_types_leave_unknown_attributes_while_9999_stays(self):
        receipt = self.receipt()
        for attr_type in (1, 15, 16):
            self.assertNotIn(attr_type, receipt.unknown_attributes)
        self.assertIn(9999, receipt.unknown_attributes)
        coins = next(
            p for p in receipt.in_app_purchases if p.product_id == "com.example.app.coins100"
        )
        self.assertNotIn(1713, coins.unknown_attributes)

    def test_endpoint_json_text_carries_exact_digits_and_the_trial_string(self):
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint

        body = VerifyReceiptEndpoint(
            [cert("generated", "receipt-ids-root.der")], "Production"
        ).verify_receipt_json(
            json.dumps(
                {"receipt-data": base64.b64encode(fixture("generated", "receipt-ids.der")).decode()}
            )
        )
        # Bare JSON numbers with exact digits, not the rounded double an
        # IEEE-754 round trip would produce (9223372036854775808).
        self.assertIn('"adam_id":1234567890', body)
        self.assertIn('"app_item_id":1234567890', body)
        self.assertIn('"download_id":9223372036854775807', body)
        self.assertIn('"version_external_identifier":456789012', body)
        self.assertIn('"is_trial_period":"false"', body)
        self.assertIn('"is_trial_period":"true"', body)
        parsed = json.loads(body)
        self.assertIsInstance(parsed["receipt"]["download_id"], int)
        self.assertEqual(parsed["receipt"]["download_id"], 9223372036854775807)

    def test_endpoint_omits_the_four_keys_when_absent_rather_than_nulling_them(self):
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint

        endpoint = VerifyReceiptEndpoint([cert("generated", "receipt-root.der")], "Sandbox")
        response = endpoint.verify_receipt_result(
            {"receipt-data": base64.b64encode(fixture("generated", "receipt.der")).decode()}
        ).to_response()
        receipt = response["receipt"]
        for key in ("adam_id", "app_item_id", "download_id", "version_external_identifier"):
            self.assertNotIn(key, receipt)
        coins = next(p for p in receipt["in_app"] if p["product_id"] == "com.example.app.coins100")
        self.assertNotIn("is_trial_period", coins)


class ReviewFixesTest(unittest.TestCase):
    """Regression tests for the adversarial-review findings + PLAN D10."""

    def test_rejects_trailing_bytes_after_cms(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        padded = fixture("generated", "receipt.der") + b"\x00\xde\xad\xbe"
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(padded)
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")

    def test_is_transaction_active_at_helper(self):
        from apple_purchase_receipt_verifier import is_transaction_active_at

        self.assertTrue(is_transaction_active_at({}, 1000))
        self.assertFalse(is_transaction_active_at({"revocationDate": 500}, 1000))
        self.assertFalse(is_transaction_active_at({"expiresDate": 900}, 1000))
        self.assertTrue(is_transaction_active_at({"expiresDate": 2000}, 1000))


class TypedClaimReadTest(unittest.TestCase):
    """What cases.json cannot pin for this port: bool is a subclass of int in
    Python, so a boolean where an integer claim belongs passes a bare
    isinstance(value, int) check. The signature step is stubbed so the test
    reaches the typed read with any payload; the shared cases cover the real
    signed path."""

    def verify(self, payload):
        with mock.patch.object(JwsVerifier, "_verify_signature", return_value=payload):
            return jws_verifier().verify_transaction("unused")

    def test_refuses_a_boolean_integer_claim(self):
        with self.assertRaises(VerificationError) as ctx:
            self.verify({"bundleId": BUNDLE, "environment": "Sandbox", "quantity": True})
        self.assertEqual(ctx.exception.reason, "INTERNAL_ERROR")

    def test_returns_a_whole_float_as_int(self):
        # A caller comparing or serializing the claim must see the integer the
        # model promises, not 1.0.
        result = self.verify({"bundleId": BUNDLE, "environment": "Sandbox", "quantity": 1.0})
        self.assertIs(type(result["quantity"]), int)


class PublicReceiptsTest(unittest.TestCase):
    """Genuine Apple-signed receipts vs the REAL pinned Apple root. The
    verdicts live in fixtures/cases.json; what stays here is the base64-string
    input form, which the conformance harness never takes (it always hands
    verify() the decoded bytes)."""

    def receipt(self, name):
        return (FIXTURES / "public-receipts" / f"{name}.b64").read_text().strip()

    def test_verifies_genuine_sandbox_receipt_from_its_base64_form(self):
        verifier = ReceiptVerifier(apple_receipt_roots(), "dev.bonzer.weeka.app")
        self.assertEqual(
            verifier.verify(self.receipt("receipt-sandbox-g5")).receipt_type, "ProductionSandbox"
        )


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


def payload_with_in_app_integer(attribute_type, value_bytes):
    """A receipt payload SET carrying one in-app purchase (attribute 17) whose
    only field is ``attribute_type`` holding the INTEGER ``value_bytes``."""
    field = (
        tlv(0x02, attribute_type.to_bytes(2, "big"))
        + tlv(0x02, b"\x01")
        + tlv(0x04, tlv(0x02, value_bytes))
    )
    in_app = tlv(0x02, b"\x11") + tlv(0x02, b"\x01") + tlv(0x04, tlv(0x31, tlv(0x30, field)))
    return tlv(0x31, tlv(0x30, in_app))


# An anonymous 162-byte blob: no certificates, no signature, one creation date
# of 0001-01-01T00:00:00+10:00. Only the creation date is read before trust,
# and an unreadable one only moves the chain instant to now, so through the
# verifier this stops at "signer not embedded"; the date decoder itself is
# driven directly below.
OUT_OF_RANGE_DATE_RECEIPT = (
    "MIGfBgkqhkiG9w0BBwKggZEwgY4CAQExDzANBglghkgBZQMEAgEFADA2BgkqhkiG9w0BBwGgKQQnMSUw"
    "IwIBDAIBAQQbFhkwMDAxLTAxLTAxVDAwOjAwOjAwKzEwOjAwMUAwPgIBATARMAwxCjAIBgNVBAMMAXgC"
    "AQEwDQYJYIZIAWUDBAIBBQAwDQYJKoZIhvcNAQEBBQAECAAAAAAAAAAA"
)

_OID_MESSAGE_DIGEST = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04"
_OID_SIGNING_TIME = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05"
_OID_UNKNOWN = b"\x06\x03\x2a\x03\x04"


def hostile_attribute_sets():
    """signedAttrs an attacker can splice in, one per raw exception class."""
    nested = b""
    for _ in range(5000):
        nested = tlv(0x30, nested)
    return {
        "empty messageDigest value set": tlv(0x31, tlv(0x30, _OID_MESSAGE_DIGEST + tlv(0x31, b""))),
        "two messageDigest values": tlv(
            0x31,
            tlv(
                0x30,
                _OID_MESSAGE_DIGEST + tlv(0x31, tlv(0x04, b"\x00" * 32) + tlv(0x04, b"\x01" * 32)),
            ),
        ),
        "messageDigest that is not an octet string": tlv(
            0x31, tlv(0x30, _OID_MESSAGE_DIGEST + tlv(0x31, tlv(0x02, b"\x01")))
        ),
        "signingTime with month 13": tlv(
            0x31, tlv(0x30, _OID_SIGNING_TIME + tlv(0x31, tlv(0x17, b"241301000000Z")))
        ),
        "unknown attribute holding invalid UTF-8": tlv(
            0x31, tlv(0x30, _OID_UNKNOWN + tlv(0x31, tlv(0x0C, b"\xff\xfe")))
        ),
        "unknown attribute nested 5000 deep": tlv(
            0x31, tlv(0x30, _OID_UNKNOWN + tlv(0x31, nested))
        ),
        "integer where the attribute OID belongs": tlv(
            0x31, tlv(0x30, tlv(0x02, b"\x01") + tlv(0x31, b""))
        ),
    }


def spliced_receipt(signed_attrs=None, digest_algorithm=None, signature=None):
    """The shared receipt with attacker-supplied SignerInfo fields spliced in.
    Its certificates and payload are untouched, so the chain and marker-OID
    checks still pass and the decoder runs on hostile bytes before the
    signature check gets to reject them."""
    info = asn1cms.ContentInfo.load(fixture("generated", "receipt.der"))
    signed_data = info["content"]
    signer = signed_data["signer_infos"][0]
    spliced = tlv(
        0x30,
        signer["version"].dump()
        + signer["sid"].dump()
        + (digest_algorithm or signer["digest_algorithm"].dump())
        + (
            b"\xa0" + signed_attrs[1:]
            if signed_attrs  # SET tag -> implicit [0]
            else signer["signed_attrs"].dump()
        )
        + signer["signature_algorithm"].dump()
        + (signature or signer["signature"].dump()),
    )
    body = (
        signed_data["version"].dump()
        + signed_data["digest_algorithms"].dump()
        + signed_data["encap_content_info"].dump()
        + signed_data["certificates"].dump()
        + signed_data["crls"].dump()
        + tlv(0x31, spliced)
    )
    return tlv(0x30, info["content_type"].dump() + tlv(0xA0, tlv(0x30, body)))


class HostileInputTest(unittest.TestCase):
    """The creation date (attribute 12) and the signedAttrs are decoded BEFORE
    any signature check, so an attacker reaches both decoders with arbitrary
    bytes and neither may leak a raw Python exception. The rest of the payload
    is decoded only after the chain and the signature pass."""

    def test_rejects_a_date_astimezone_cannot_convert(self):
        from apple_purchase_receipt_verifier.receipt import (
            _parse_payload,
            _read_creation_date,
        )

        out_of_range = date_payload("0001-01-01T00:00:00+10:00")
        # Before trust: not a verdict, only "judge the chain at now".
        self.assertIsNone(_read_creation_date(out_of_range))
        # After trust: the parser's own verdict, which the verifier reports
        # as INTERNAL_ERROR for a trusted signer.
        with self.assertRaises(VerificationError) as ctx:
            _parse_payload(out_of_range)
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")
        self.assertIsInstance(ctx.exception.__cause__, OverflowError)
        # Through the verifier the blob embeds no signer, which is a defect
        # of the CMS and so still a format error, never a leaked exception.
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

        creation_date = _parse_payload(date_payload("2024-08-06T12:00:00Z")).creation_date
        assert creation_date is not None
        self.assertEqual("2024-08-06T12:00:00+00:00", creation_date.isoformat())
        with self.assertRaises(VerificationError) as ctx:
            _parse_payload(date_payload("2024-08-06T12:00:00"))
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")

    def test_rejects_attribute_integers_at_the_edge_of_each_guard(self):
        # Driven through the payload parser like the date above. 0x80 is the
        # smallest leading byte of a negative two's-complement INTEGER and
        # nine bytes is one past the cap; a comparison one step wider admits
        # each.
        from apple_purchase_receipt_verifier.receipt import _parse_payload

        for name, type_bytes, message in (
            ("leading byte 0x80", b"\x80", "negative receipt integer"),
            ("nine bytes", b"\x00" * 8 + b"\x01", "out of range"),
        ):
            with self.subTest(name):
                with self.assertRaises(VerificationError) as ctx:
                    _parse_payload(payload_with_attribute_type(type_bytes))
                self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")
                self.assertIn(message, str(ctx.exception))

    def test_rejects_an_attribute_type_above_the_32_bit_signed_range(self):
        # Cross-language decision: an attribute type is a 32-bit signed space
        # in every port. Java used to map an unrepresentable type onto -1 and
        # file it under unknownAttributes, and this port used to admit it up to
        # 2^63-1; both let two ports report different contents for the same
        # bytes, so every port now rejects it as a malformed receipt instead.
        from apple_purchase_receipt_verifier.receipt import _parse_payload

        largest = _parse_payload(payload_with_attribute_type(b"\x7f\xff\xff\xff"))
        self.assertEqual(largest.unknown_attributes, {2**31 - 1: [b""]})
        for name, type_bytes in (
            ("one past 2^31-1", b"\x00\x80\x00\x00\x00"),
            ("the old 8-byte ceiling", b"\x7f" + b"\xff" * 7),
        ):
            with self.subTest(name):
                with self.assertRaises(VerificationError) as ctx:
                    _parse_payload(payload_with_attribute_type(type_bytes))
                self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")
                self.assertIn("exceeds the 32-bit signed range", str(ctx.exception))

    def test_attribute_values_keep_the_wider_integer_range(self):
        # The 32-bit bound above is on the attribute TYPE only. Values stay on
        # the 8-byte cap, because web_order_line_item_id is genuinely a 7-byte
        # integer — a bound that narrowed both would reject real receipts.
        from apple_purchase_receipt_verifier.receipt import _parse_payload

        purchase = _parse_payload(
            payload_with_in_app_integer(1711, b"\x7f" + b"\xff" * 7)
        ).in_app_purchases[0]
        self.assertEqual(purchase.web_order_line_item_id, 2**63 - 1)
        with self.assertRaises(VerificationError) as ctx:
            _parse_payload(payload_with_in_app_integer(1711, b"\x00" * 8 + b"\x01"))
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")
        self.assertIn("out of range", str(ctx.exception))

    def test_contains_hostile_signed_attrs(self):
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        for name, attributes in hostile_attribute_sets().items():
            with self.subTest(name), self.assertRaises(VerificationError):
                verifier.verify(spliced_receipt(signed_attrs=attributes))

    def test_rejects_a_message_digest_with_more_than_one_value(self):
        # RFC 5652 §5.3 allows exactly one value; unguarded, the decoder
        # silently takes the first of whatever list the attacker supplied.
        verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(
                spliced_receipt(signed_attrs=hostile_attribute_sets()["two messageDigest values"])
            )
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
            (
                "base64 hostile signedAttrs",
                generated,
                base64.b64encode(
                    spliced_receipt(signed_attrs=hostile["empty messageDigest value set"])
                ).decode(),
            ),
            (
                "nested signedAttrs",
                generated,
                spliced_receipt(signed_attrs=hostile["unknown attribute nested 5000 deep"]),
            ),
            (
                "digest algorithm that is not an OID",
                generated,
                spliced_receipt(digest_algorithm=tlv(0x30, tlv(0x02, b"\x01"))),
            ),
            (
                "signature that is not an octet string",
                generated,
                spliced_receipt(signature=tlv(0x02, b"\x01")),
            ),
        ]
        for name, verifier, blob in corpus:
            with self.subTest(name), self.assertRaises(VerificationError):
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
            # Catching bare Exception is the assertion: verify() must never
            # leak anything but VerificationError, whatever the mutation.
            except Exception as e:
                self.fail(f"mutation {i} leaked {type(e).__name__}: {e}")


class JwsHostileInputTest(unittest.TestCase):
    """The JWS header and payload are attacker-supplied JSON, decoded — along
    with the two x5c certificates — before the signature that would reject
    them. Every case here is a fuzz finding (python/fuzz): a raw Python
    exception that a caller of the JwsVerifier used to have to catch, and that
    the statically typed ports never had."""

    def setUp(self):
        self.header, self.payload, self.signature = text("generated", "transaction.jws").split(".")

    @staticmethod
    def segment(raw):
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    def header_claims(self):
        return json.loads(base64.urlsafe_b64decode(self.header + "=" * (-len(self.header) % 4)))

    def assemble(self, header=None, payload=None):
        return ".".join(
            (
                self.header if header is None else header,
                self.payload if payload is None else payload,
                self.signature,
            )
        )

    def test_rejects_x5c_entries_that_are_not_strings(self):
        # `"x5c": [1, 2, 3]` used to reach base64.b64decode, whose TypeError is
        # neither of the two exception types the decode site catches. Node
        # rejects the same header with the same reason; it gets the check from
        # its JSON types, this port has to make it.
        claims = self.header_claims()
        for name, entries in (
            ("numbers", [1, 2, 3]),
            ("nested containers", [[], {}, None]),
            ("one entry short of all strings", [claims["x5c"][0], claims["x5c"][1], 3]),
        ):
            with self.subTest(name):
                hostile = dict(claims, x5c=entries)
                with self.assertRaises(VerificationError) as ctx:
                    jws_verifier().verify_transaction(
                        self.assemble(header=self.segment(json.dumps(hostile).encode()))
                    )
                self.assertEqual(ctx.exception.reason, "INVALID_JWS_FORMAT")

    def test_rejects_a_signing_date_no_calendar_can_express(self):
        # datetime covers years 1 to 9999, so a signedDate of 1e300 raised
        # OverflowError out of as_utc(), and NaN — which json.loads accepts,
        # standard JSON or not — raised ValueError. An instant no calendar can
        # express is inside no certificate's validity window, which is the
        # verdict the other ports reach through their own date types.
        for name, raw in (
            ("far future float", b'{"signedDate": 1e300}'),
            ("far past float", b'{"signedDate": -1e300}'),
            ("integer past the range", b'{"signedDate": 1' + b"0" * 30 + b"}"),
            ("NaN", b'{"signedDate": NaN}'),
            ("Infinity", b'{"signedDate": Infinity}'),
            ("receiptCreationDate, the fallback claim", b'{"receiptCreationDate": 1e300}'),
        ):
            with self.subTest(name):
                with self.assertRaises(VerificationError) as ctx:
                    jws_verifier().verify_raw(self.assemble(payload=self.segment(raw)))
                self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")

    def test_rejects_a_certificate_whose_extensions_cannot_be_parsed(self):
        # cryptography parses a certificate's extension block lazily, so ONE
        # corrupt extension makes the marker-OID lookup raise ValueError
        # instead of ExtensionNotFound — and the lookup runs on an x5c entry
        # nothing has authenticated. One flipped byte inside the intermediate's
        # basicConstraints is enough to reach it.
        claims = self.header_claims()
        der = bytearray(base64.b64decode(claims["x5c"][1]))
        extension = asn1x509.Certificate.load(bytes(der))["tbs_certificate"]["extensions"][0]
        der[der.find(extension["extn_value"].contents)] ^= 0xFF

        # The premise. Without it this would only be testing a certificate
        # that lacks the marker OID, which was never the failing case.
        with self.assertRaises(ValueError):
            list(x509.load_der_x509_certificate(bytes(der)).extensions)

        hostile = dict(claims)
        hostile["x5c"] = list(claims["x5c"])
        hostile["x5c"][1] = base64.b64encode(bytes(der)).decode()
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(
                self.assemble(header=self.segment(json.dumps(hostile).encode()))
            )
        self.assertEqual(ctx.exception.reason, "INVALID_CERTIFICATE_PURPOSE")

    def test_rejects_a_certificate_the_loader_itself_refuses(self):
        # load_der_x509_certificate raises InvalidVersion — which derives from
        # Exception, not from ValueError — for a TBSCertificate whose version
        # field is not 0, 1 or 2. Naming exception types at that call site is
        # what let it through; three bytes into the intermediate is enough.
        claims = self.header_claims()
        der = bytearray(base64.b64decode(claims["x5c"][1]))
        version = der.find(b"\xa0\x03\x02\x01\x02")
        self.assertGreater(version, 0, "the intermediate has no explicit v3 version field")
        der[version + 4] = 11

        with self.assertRaises(x509.InvalidVersion):
            x509.load_der_x509_certificate(bytes(der))

        hostile = dict(claims)
        hostile["x5c"] = list(claims["x5c"])
        hostile["x5c"][1] = base64.b64encode(bytes(der)).decode()
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(
                self.assemble(header=self.segment(json.dumps(hostile).encode()))
            )
        self.assertEqual(ctx.exception.reason, "INVALID_CERTIFICATE")

    def test_rejects_a_certificate_carrying_one_extension_twice(self):
        # The extension block refuses to be read for a second reason, and
        # cryptography reports it as DuplicateExtension — which derives from
        # Exception rather than ValueError, so it escaped the marker-OID
        # lookup, every other `except` in the module and the caller. Fuzzing
        # reached it by mutation; here the intermediate's extension list is
        # rebuilt with a byte-identical second copy of its first extension,
        # which is enough because the lookup reads the whole block. The
        # certificate's signature is stale afterwards and that is not what is
        # being tested: nothing gets as far as checking it.
        claims = self.header_claims()
        certificate = asn1x509.Certificate.load(base64.b64decode(claims["x5c"][1]))
        extensions = certificate["tbs_certificate"]["extensions"]
        extensions.append(extensions[0])
        der = certificate.dump(force=True)

        # The premise: loadable, and unreadable only at the extension block.
        with self.assertRaises(x509.DuplicateExtension):
            list(x509.load_der_x509_certificate(der).extensions)

        hostile = dict(claims)
        hostile["x5c"] = list(claims["x5c"])
        hostile["x5c"][1] = base64.b64encode(der).decode()
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(
                self.assemble(header=self.segment(json.dumps(hostile).encode()))
            )
        self.assertEqual(ctx.exception.reason, "INVALID_CERTIFICATE")

    def test_mutations_of_a_genuine_jws_raise_nothing_else_either(self):
        # The JWS counterpart of the receipt sweep above, and it exists for the
        # same reason: mutating a transaction that is otherwise valid is what
        # carries an input past the format checks and into the certificate and
        # claim decoders, which is where all three findings above were. The
        # mutations stay inside the compact-JWS character set, so they exercise
        # those decoders rather than the UTF-8 boundary in front of them.
        verifier = jws_verifier()
        genuine = text("generated", "transaction.jws")
        alphabet = string.ascii_letters + string.digits + "-_."
        rnd = random.Random(1234)  # fixed seed: a failure must be reproducible
        for i in range(400):
            mutant = list(genuine)
            for _ in range(rnd.randint(1, 3)):
                mutant[rnd.randrange(len(mutant))] = rnd.choice(alphabet)
            candidate = "".join(mutant)
            for name, call in (
                ("verify_transaction", verifier.verify_transaction),
                ("verify_app_transaction", verifier.verify_app_transaction),
                ("verify_raw", verifier.verify_raw),
            ):
                try:
                    call(candidate)
                except VerificationError:
                    pass
                # Catching bare Exception is the assertion: nothing but
                # VerificationError may reach a caller, whatever the mutation.
                except Exception as e:
                    self.fail(f"mutation {i} leaked {type(e).__name__} out of {name}: {e}")


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
    keys = [
        [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(branching)]
        for _ in range(layers)
    ]
    certificates = []
    for layer in range(layers):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, MESH_NAMES[layer % 2])])
        above = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, MESH_NAMES[(layer + 1) % 2])])
        for key in keys[layer]:
            for issuer in keys[(layer + 1) % layers]:
                certificates.append(
                    (
                        x509.CertificateBuilder()
                        .subject_name(name)
                        .issuer_name(above)
                        .public_key(key.public_key())
                        .serial_number(x509.random_serial_number())
                        .not_valid_before(now - datetime.timedelta(days=3650))
                        .not_valid_after(now + datetime.timedelta(days=3650))
                        .add_extension(
                            x509.BasicConstraints(ca=True, path_length=None), critical=True
                        )
                        .sign(issuer, hashes.SHA256())
                    ).public_bytes(serialization.Encoding.DER)
                )
    return certificates


def receipt_with_extra_certificates(extra):
    """The shared receipt with ``extra`` certificates spliced in ahead of its
    own. Payload, chain and signature are untouched, so without a bound on the
    count everything still verifies — after the extras have been parsed and
    offered to path building."""
    info = asn1cms.ContentInfo.load(fixture("generated", "receipt.der"))
    signed_data = info["content"]
    genuine = [choice.chosen.dump() for choice in signed_data["certificates"]]
    body = (
        signed_data["version"].dump()
        + signed_data["digest_algorithms"].dump()
        + signed_data["encap_content_info"].dump()
        + tlv(0xA0, b"".join(extra + genuine))
        + signed_data["crls"].dump()
        + signed_data["signer_infos"].dump()
    )
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

    # cross_signed_mesh() is an untyped helper, so its element type is Any.
    mesh: ClassVar[list[Any]]

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

        counts = {
            name: embedded_certificate_count(
                (FIXTURES / "public-receipts" / f"{name}.b64").read_text().strip()
            )
            for name in (
                "receipt-sandbox-g5",
                "receipt-sandbox-legacy",
                "receipt-xcode-with-purchases",
            )
        }
        self.assertLess(max(counts.values()), _MAX_EMBEDDED_CERTIFICATES, counts)


def receipt_without_creation_date(der):
    """The given receipt with attribute 12 removed from its payload, so the
    certificate-validity anchor has to fall back to "current time" (PLAN.md
    §2.2 step 2). The chain is checked before the signature, so this reaches
    the chain check even though dropping the attribute invalidates the
    signature over the payload."""
    from apple_purchase_receipt_verifier.receipt import _children, _read_tlv

    info = asn1cms.ContentInfo.load(der)
    signed_data = info["content"]
    encap = signed_data["encap_content_info"]
    tag, contents, end = _read_tlv(encap["content"].native, 0)
    assert tag == 0x31 and end == len(encap["content"].native)
    kept = b""
    for child_tag, child_value in _children(contents):
        if int.from_bytes(_children(child_value)[0][1], "big") == 12:
            continue
        kept += tlv(child_tag, child_value)
    new_encap = tlv(0x30, encap["content_type"].dump() + tlv(0xA0, tlv(0x04, tlv(0x31, kept))))
    body = (
        signed_data["version"].dump()
        + signed_data["digest_algorithms"].dump()
        + new_encap
        + signed_data["certificates"].dump()
        + signed_data["crls"].dump()
        + signed_data["signer_infos"].dump()
    )
    return tlv(0x30, info["content_type"].dump() + tlv(0xA0, tlv(0x30, body)))


def jws_without_signed_date(compact):
    """The given JWS with ``signedDate`` and ``receiptCreationDate`` dropped
    from its payload, so PLAN.md §2.1 step 4's "else current time" fallback is
    what anchors chain validity. The chain is checked before the signature, so
    this reaches the chain check."""
    header, payload, signature = compact.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims.pop("signedDate", None)
    claims.pop("receiptCreationDate", None)
    undated = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{undated}.{signature}"


class CrossPortApiShapeTest(unittest.TestCase):
    """The API decisions the four ports must agree on. Each of these was a
    real divergence between two implementations of the same algorithm."""

    def test_verifiers_take_no_clock(self):
        # Nothing on the receipt or JWS path has a verdict that moves with the
        # current time: chain validity anchors at the signing date, and the
        # "else current time" fallback is a certificate-validity judgement an
        # injected clock must not be able to shift. How old a payload may be
        # is the caller's decision, so there is no max-age option either. The
        # clock seam lives on the endpoint (request_date) only.
        import inspect

        from apple_purchase_receipt_verifier import verify_receipt_core

        for callable_ in (
            ReceiptVerifier.__init__,
            ReceiptVerifier.verify,
            verify_receipt_core,
            JwsVerifier.__init__,
        ):
            with self.subTest(callable_.__qualname__):
                parameters = inspect.signature(callable_).parameters
                self.assertNotIn("clock", parameters)
                self.assertNotIn("max_signed_age_millis", parameters)

    def test_verify_receipt_core_is_public(self):
        # The endpoint accepts any bundle id, exactly as Apple's does. It gets
        # that by calling the bundle-agnostic primitive, which is part of the
        # published API — not by constructing a ReceiptVerifier with a wildcard
        # bundle id, which would put a bundle-id check one typo away from
        # passing for everyone.
        import apple_purchase_receipt_verifier as package

        self.assertIn("verify_receipt_core", package.__all__)
        fields = package.verify_receipt_core(
            fixture("generated", "receipt.der"), [cert("generated", "receipt-root.der")]
        )
        self.assertEqual(BUNDLE, fields.bundle_id)

    def test_endpoint_environment_is_the_typed_enum(self):
        # cases.json spells the endpoint's environment as the same enum the
        # rest of the library uses, not as a boolean "production" flag.
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint

        roots = [cert("generated", "receipt-root.der")]
        for environment in ("Production", "Sandbox"):
            VerifyReceiptEndpoint(roots, environment)
        for rejected in (True, False, "production", "sandbox", "", None):
            with self.subTest(rejected), self.assertRaises(ValueError):
                # Deliberately wrong types for `environment`; the assertion is
                # that the constructor rejects each of them.
                VerifyReceiptEndpoint(roots, rejected)  # type: ignore[arg-type]


class ClockSeamTest(unittest.TestCase):
    """Time. The JWS and receipt verifiers take no clock, and certificate
    validity is judged at the signing date or, without one, at the system
    clock. The endpoint's optional ``clock`` (a zero-argument callable
    returning epoch seconds, the same contract as ``time.time``) moves
    ``request_date`` and nothing else."""

    def expired_chain_verifier(self):
        return jws_verifier(trusted_roots=[cert("generated", "jws-expired-root.der")])

    def test_certificate_validity_is_judged_at_the_signed_date(self):
        # PLAN.md 2.1 step 4: the chain window is judged at the payload's
        # signedDate, never at wall-clock time.
        with self.assertRaises(VerificationError) as ctx:
            self.expired_chain_verifier().verify_transaction(
                text("generated", "expired-cert-fresh.jws")
            )
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")
        payload = self.expired_chain_verifier().verify_transaction(
            text("generated", "expired-cert-historical.jws")
        )
        self.assertEqual(1590969600000, payload["signedDate"])

    def test_payload_without_a_signed_date_anchors_on_the_system_clock(self):
        # With neither signedDate nor receiptCreationDate, PLAN.md §2.1 step 4
        # falls back to the current time. The same payload WITH its signedDate
        # verifies, so the INVALID_CHAIN below is the fallback's doing.
        dated = text("generated", "expired-cert-historical.jws")
        self.assertEqual(
            1590969600000, self.expired_chain_verifier().verify_transaction(dated)["signedDate"]
        )
        with self.assertRaises(VerificationError) as ctx:
            self.expired_chain_verifier().verify_transaction(jws_without_signed_date(dated))
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")

    def test_receipt_without_a_creation_date_anchors_on_the_system_clock(self):
        # PLAN.md §2.2 step 2's fallback on the receipt path. The receipt
        # verifier takes no clock at all (CrossPortApiShapeTest), so what this
        # pins is that the fallback is real time: the same receipt WITH its
        # 2020-06-01 creation date verifies against the expired chain, and
        # stripped of it, it is rejected because the chain is long expired now.
        expired_root = [cert("generated", "receipt-expired-root.der")]
        verifier = ReceiptVerifier(expired_root, BUNDLE)
        historical = fixture("generated", "receipt-expired-historical.der")
        creation_date = verifier.verify(historical).creation_date
        assert creation_date is not None
        self.assertEqual("2020-06-01T00:00:00+00:00", creation_date.isoformat())
        with self.assertRaises(VerificationError) as ctx:
            verifier.verify(receipt_without_creation_date(historical))
        self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")

    def test_endpoint_clock_does_not_move_certificate_validity(self):
        # The endpoint is the one place on the receipt path that takes a clock
        # at all (request_date), so it is where a caller could hope to move the
        # chain window. receipt-expired-fresh.der is intact and was created
        # after its signing certificate expired; the sibling receipt created
        # while that certificate was valid verifies, so a clock pinned to
        # 2020-06-01 is inside the window and would rescue this one if it
        # reached the anchor. It answers 21003 at every clock instead.
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint

        roots = [cert("generated", "receipt-expired-root.der")]
        data = {
            "receipt-data": base64.b64encode(
                fixture("generated", "receipt-expired-fresh.der")
            ).decode()
        }
        historical = {
            "receipt-data": base64.b64encode(
                fixture("generated", "receipt-expired-historical.der")
            ).decode()
        }
        self.assertEqual(
            0,
            VerifyReceiptEndpoint(roots, "Sandbox")
            .verify_receipt_result(historical)
            .to_response()["status"],
        )
        for now in (None, 1590969600.0, 4102444800.0):  # system, 2020-06-01, 2100
            with self.subTest(now=now):
                clock = None if now is None else (lambda moment: lambda: moment)(now)
                endpoint = VerifyReceiptEndpoint(roots, "Sandbox", clock=clock)
                self.assertEqual(
                    21003, endpoint.verify_receipt_result(data).to_response()["status"]
                )

    def test_endpoint_clock_drives_request_date(self):
        # request_date is the one wall-clock field in a verifyReceipt
        # response (every other date comes off the signed receipt), so the
        # same seam covers it — consistency, and it makes the response
        # byte-reproducible for a caller that pins the clock.
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint

        endpoint = VerifyReceiptEndpoint(
            [cert("generated", "receipt-root.der")], "Sandbox", clock=lambda: 1735689600.0
        )  # 2025-01-01T00:00:00Z
        response = endpoint.verify_receipt_result(
            {"receipt-data": base64.b64encode(fixture("generated", "receipt.der")).decode()}
        ).to_response()
        self.assertEqual(0, response["status"])
        receipt = response["receipt"]
        self.assertEqual("2025-01-01 00:00:00 Etc/GMT", receipt["request_date"])
        self.assertEqual("1735689600000", receipt["request_date_ms"])
        self.assertEqual("2024-12-31 16:00:00 America/Los_Angeles", receipt["request_date_pst"])
        # The receipt's own dates are unaffected by the clock.
        self.assertEqual("2024-08-06 12:00:00 Etc/GMT", receipt["receipt_creation_date"])


class InputSizeBoundsTest(unittest.TestCase):
    """The input caps exist so that hostile input costs little to refuse:
    base64 decoding and JSON parsing both allocate a multiple of their input
    before any signature is checked. So the over-cap tests prove the
    expensive step never runs, and the at-cap tests prove the cap is not set
    below what a genuine receipt needs."""

    endpoint_module = "apple_purchase_receipt_verifier.verify_receipt_endpoint"

    def setUp(self):
        self.der = fixture("generated", "receipt.der")
        self.receipt_b64 = base64.b64encode(self.der).decode()
        self.verifier = ReceiptVerifier([cert("generated", "receipt-root.der")], BUNDLE)
        self.endpoint = VerifyReceiptEndpoint([cert("generated", "receipt-root.der")], "Sandbox")
        self.jws = text("generated", "transaction.jws")

    @staticmethod
    def padded(text, length):
        # Whitespace around a JSON body keeps a genuine body genuine. A
        # receipt string padded this way is not valid receipt-data, which is
        # why the over-cap receipt tests prove the decoder never ran rather
        # than relying on the verdict.
        return text + "\n" * (length - len(text))

    @staticmethod
    def at_cap_receipt():
        # Canonical base64 admits nothing around the data, so the string at
        # the cap is a genuinely signed receipt whose base64 is exactly the
        # cap (ReceiptBase64CapFixture), under a root of its own.
        return fixture("limits", "receipt-b64-at-cap.txt").decode("ascii"), [
            cert("generated", "receipt-b64-cap-root.der")
        ]

    def request_body(self, extra=""):
        return '{"receipt-data":"' + self.receipt_b64 + '"' + extra + "}"

    def test_receipt_string_over_the_cap_is_refused_without_decoding(self):
        receipt = self.padded(self.receipt_b64, ReceiptVerifier.MAX_RECEIPT_BYTES + 1)
        with (
            mock.patch("apple_purchase_receipt_verifier.receipt.decode_receipt_base64") as decode,
            self.assertRaises(VerificationError) as ctx,
        ):
            self.verifier.verify(receipt)
        decode.assert_not_called()
        self.assertEqual("INVALID_RECEIPT_FORMAT", ctx.exception.reason)

    def test_receipt_string_at_the_cap_still_verifies(self):
        receipt, roots = self.at_cap_receipt()
        self.assertEqual(ReceiptVerifier.MAX_RECEIPT_BYTES, len(receipt))
        self.assertEqual(BUNDLE, ReceiptVerifier(roots, BUNDLE).verify(receipt).bundle_id)

    def test_receipt_der_over_the_cap_is_refused_before_it_is_parsed(self):
        # verify_receipt_core is the primitive under the endpoint, so the
        # bytes cap has to hold there, not only on ReceiptVerifier.
        from apple_purchase_receipt_verifier import verify_receipt_core

        der = b"\x30" + bytes(ReceiptVerifier.MAX_RECEIPT_BYTES)
        roots = [cert("generated", "receipt-root.der")]
        for label, call in (
            ("ReceiptVerifier.verify", lambda: self.verifier.verify(der)),
            ("verify_receipt_core", lambda: verify_receipt_core(der, roots)),
        ):
            with (
                self.subTest(label),
                mock.patch("apple_purchase_receipt_verifier.receipt._parse_cms") as parse,
                self.assertRaises(VerificationError) as ctx,
            ):
                call()
            parse.assert_not_called()
            self.assertEqual("INVALID_RECEIPT_FORMAT", ctx.exception.reason)

    def test_receipt_der_at_the_cap_reaches_the_parser(self):
        der = b"\x30" + bytes(ReceiptVerifier.MAX_RECEIPT_BYTES - 1)
        with (
            mock.patch(
                "apple_purchase_receipt_verifier.receipt._parse_cms",
                side_effect=VerificationError("INVALID_RECEIPT_FORMAT", "parsed"),
            ) as parse,
            self.assertRaises(VerificationError),
        ):
            self.verifier.verify(der)
        parse.assert_called_once()

    def test_the_caps_are_apples_three_mebibytes(self):
        # The limits are Apple's, fixed in every port by fixtures/cases.json:
        # Apple's verifyReceipt answers a 3,145,728-byte request body and
        # refuses a 3,145,729-byte one (measured 2026-09-23), and no receipt
        # it accepts can be larger than the body that carries it.
        self.assertEqual(3145728, VerifyReceiptEndpoint.MAX_REQUEST_BYTES)
        self.assertEqual(3145728, ReceiptVerifier.MAX_RECEIPT_BYTES)

    def test_endpoint_receipt_data_over_the_cap_answers_21002_without_decoding(self):
        receipt = self.padded(self.receipt_b64, ReceiptVerifier.MAX_RECEIPT_BYTES + 1)
        with mock.patch(f"{self.endpoint_module}.decode_receipt_base64") as decode:
            results = {
                "mapping": self.endpoint.verify_receipt_result({"receipt-data": receipt}),
                "bare": self.endpoint.verify_receipt_data(receipt),
            }
        decode.assert_not_called()
        for label, result in results.items():
            self.assertEqual("INVALID_RECEIPT_FORMAT", result.failure_reason, label)
            self.assertEqual(21002, result.status, label)

        at_cap, roots = self.at_cap_receipt()
        self.assertEqual(
            0, VerifyReceiptEndpoint(roots, "Sandbox").verify_receipt_data(at_cap).status
        )

    def test_request_body_over_the_cap_answers_21002_without_parsing(self):
        body = self.padded(self.request_body(), VerifyReceiptEndpoint.MAX_REQUEST_BYTES + 1)
        with mock.patch(f"{self.endpoint_module}.json.loads") as loads:
            results = {
                "str": self.endpoint.verify_receipt_result(body),
                "bytes": self.endpoint.verify_receipt_result(body.encode()),
            }
            wire = self.endpoint.verify_receipt_json(body)
        loads.assert_not_called()
        self.assertEqual('{"status":21002}', wire)
        for label, result in results.items():
            # REQUEST_TOO_LARGE, the reason an HTTP layer maps to 413 as
            # Apple does, not the MALFORMED_REQUEST of an unusable body.
            self.assertEqual("REQUEST_TOO_LARGE", result.failure_reason, label)
            self.assertEqual(21002, result.status, label)

    def test_request_body_at_the_cap_still_verifies(self):
        body = self.padded(self.request_body(), VerifyReceiptEndpoint.MAX_REQUEST_BYTES)
        self.assertEqual(0, self.endpoint.verify_receipt_result(body).status)
        self.assertEqual(0, self.endpoint.verify_receipt_result(body.encode()).status)

    def test_request_body_is_measured_in_utf8_bytes_not_characters(self):
        # Apple's limit counts UTF-8 bytes. A body padded with U+00E9 to one
        # byte over the limit is barely half the limit in code points, so a
        # len() check lets it through; the same shape one byte shorter
        # verifies. Both forms of the body must agree.
        limit = VerifyReceiptEndpoint.MAX_REQUEST_BYTES
        fixed = len(self.request_body(',"password":""'))

        def body(size):
            padding = "\u00e9" * ((size - fixed) // 2) + "a" * ((size - fixed) % 2)
            return self.request_body(',"password":"' + padding + '"')

        over = body(limit + 1)
        self.assertEqual(limit + 1, len(over.encode()))
        self.assertLess(len(over), limit // 2 + fixed, "len() calls this one far under")
        at = body(limit)
        self.assertEqual(limit, len(at.encode()))
        for form in (over, over.encode()):
            with self.subTest(type=type(form).__name__):
                result = self.endpoint.verify_receipt_result(form)
                self.assertEqual("REQUEST_TOO_LARGE", result.failure_reason)
                self.assertEqual(21002, result.status)
        for form in (at, at.encode()):
            with self.subTest(type=type(form).__name__):
                self.assertEqual(0, self.endpoint.verify_receipt_result(form).status)

    def test_receipt_string_is_measured_in_utf8_bytes_not_characters(self):
        # The receipt cap counts the same unit. Two-byte characters are not
        # base64, so one byte over is refused for its size before the decode
        # could object to its alphabet.
        receipt = "\u00e9" * (ReceiptVerifier.MAX_RECEIPT_BYTES // 2) + "a"
        self.assertLess(len(receipt), ReceiptVerifier.MAX_RECEIPT_BYTES)
        with (
            mock.patch("apple_purchase_receipt_verifier.receipt.decode_receipt_base64") as decode,
            self.assertRaises(VerificationError) as ctx,
        ):
            self.verifier.verify(receipt)
        decode.assert_not_called()
        self.assertEqual("INVALID_RECEIPT_FORMAT", ctx.exception.reason)
        with mock.patch(f"{self.endpoint_module}.decode_receipt_base64") as decode:
            result = self.endpoint.verify_receipt_data(receipt)
        decode.assert_not_called()
        self.assertEqual("INVALID_RECEIPT_FORMAT", result.failure_reason)

    def test_utf8_count_matches_the_encoder_on_each_side_of_the_limit(self):
        # The shortcuts decide on len() alone; each width is checked at the
        # limit and one byte past it, so a wrong shortcut factor shows up as
        # a verdict that disagrees with the encoder.
        from apple_purchase_receipt_verifier._utf8 import utf8_exceeds

        limit = 12
        for char in ("a", "é", "€", "\U0001f600", "\ud800"):
            width = len(char.encode("utf-8", "surrogatepass"))
            for text in (char * (limit // width), char * (limit // width) + "a"):
                with self.subTest(char=ascii(char), length=len(text)):
                    size = len(text.encode("utf-8", "surrogatepass"))
                    self.assertEqual(size > limit, utf8_exceeds(text, limit))

    def test_huge_malformed_body_is_too_large_rather_than_malformed(self):
        # The size is decided before the parse and before the depth scan.
        body = "[" * (VerifyReceiptEndpoint.MAX_REQUEST_BYTES + 1)
        with mock.patch(f"{self.endpoint_module}._nesting_exceeds_limit") as scan:
            result = self.endpoint.verify_receipt_result(body)
        scan.assert_not_called()
        self.assertEqual("REQUEST_TOO_LARGE", result.failure_reason)

    def test_body_nested_past_the_limit_answers_21002_before_parsing(self):
        # json.loads recurses once per level and has no depth option, so a
        # deep body must be refused before it runs, not caught afterwards.
        # The object itself is level 1, so 64 inner arrays make 65.
        for depth in (64, 100_000):
            body = self.request_body(',"deep":' + "[" * depth + "]" * depth)
            for form in (body, body.encode()):
                with (
                    self.subTest(depth=depth, type=type(form).__name__),
                    mock.patch(f"{self.endpoint_module}.json.loads") as loads,
                ):
                    result = self.endpoint.verify_receipt_result(form)
                    loads.assert_not_called()
                    self.assertEqual("MALFORMED_REQUEST", result.failure_reason)
                    self.assertEqual(21002, result.status)

    def test_body_nested_to_the_limit_still_verifies(self):
        at_limit = self.request_body(',"deep":' + "[" * 63 + "]" * 63)
        self.assertEqual(0, self.endpoint.verify_receipt_result(at_limit).status)
        # Brackets inside a string are data, escaped quotes included.
        in_string = self.request_body(',"note":"\\"' + "[" * 1000 + '"')
        self.assertEqual(0, self.endpoint.verify_receipt_result(in_string).status)

    def jws_with_segment(self, index, raw_json):
        parts = self.jws.split(".")
        parts[index] = base64.urlsafe_b64encode(raw_json.encode()).rstrip(b"=").decode()
        return ".".join(parts)

    def test_jws_over_the_cap_is_refused_without_decoding(self):
        oversized = self.padded(self.jws, JwsVerifier.MAX_JWS_BYTES + 1)
        with (
            mock.patch("apple_purchase_receipt_verifier.jws._b64url") as decode,
            self.assertRaises(VerificationError) as ctx,
        ):
            jws_verifier().verify_transaction(oversized)
        decode.assert_not_called()
        self.assertEqual("INVALID_JWS_FORMAT", ctx.exception.reason)
        self.assertIn("exceeds the maximum accepted size", str(ctx.exception))

    def test_jws_at_the_cap_is_not_refused_by_the_cap(self):
        at_cap = self.padded(self.jws, JwsVerifier.MAX_JWS_BYTES)
        self.assertEqual(JwsVerifier.MAX_JWS_BYTES, len(at_cap))
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(at_cap)
        self.assertNotIn("exceeds the maximum accepted size", str(ctx.exception))

    def test_jws_header_nested_past_the_limit_is_refused_before_json_loads(self):
        # json.loads recurses once per level and has no depth option, so a
        # deeply nested segment must be refused before it runs. The segment
        # itself is level 1, so 64 inner arrays make 65. The header is the
        # first segment parsed, so no json.loads call happens at all yet.
        deep = '{"deep":' + "[" * 64 + "]" * 64 + "}"
        with (
            mock.patch("apple_purchase_receipt_verifier.jws.json.loads") as loads,
            self.assertRaises(VerificationError) as ctx,
        ):
            jws_verifier().verify_transaction(self.jws_with_segment(0, deep))
        loads.assert_not_called()
        self.assertEqual("INVALID_JWS_FORMAT", ctx.exception.reason)
        self.assertIn("nested too deeply", str(ctx.exception))

    def test_jws_payload_nested_past_the_limit_is_refused_before_its_json_loads(self):
        # The genuine header parses fine first (one json.loads call); the
        # payload's own depth guard must still fire before ITS json.loads.
        deep = '{"deep":' + "[" * 64 + "]" * 64 + "}"
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(self.jws_with_segment(1, deep))
        self.assertEqual("INVALID_JWS_FORMAT", ctx.exception.reason)
        self.assertIn("nested too deeply", str(ctx.exception))

    def test_jws_segment_nested_to_the_limit_reaches_json_loads(self):
        at_limit = '{"deep":' + "[" * 63 + "]" * 63 + "}"
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(self.jws_with_segment(0, at_limit))
        self.assertNotIn("nested too deeply", str(ctx.exception))
        # No "alg" survives replacing the header with the padding shape, so
        # processing reached the algorithm check rather than being stopped
        # by the depth guard.
        self.assertIn("alg must be ES256", str(ctx.exception))
