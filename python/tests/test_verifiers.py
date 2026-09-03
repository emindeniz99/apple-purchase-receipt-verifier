"""Python-only tests over the shared fixture sets. The facts that every
implementation must agree on live in fixtures/cases.json and are run by
tests/test_conformance.py; what is left here is what a shared vector cannot
express: forged and mutated inputs built at run time, the raw JSON wire form,
and the resource bounds."""

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


class NegativeTest(unittest.TestCase):
    def test_rejects_tampered_payload(self):
        header, payload, signature = text("generated", "transaction.jws").split(".")
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        claims["productId"] = f"{BUNDLE}.premium_forever"
        forged = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier().verify_transaction(f"{header}.{forged}.{signature}")
        self.assertEqual(ctx.exception.reason, "INVALID_SIGNATURE")

    def test_rejects_stale_payload(self):
        # The conformance case for this (transaction/reject-stale-payload)
        # pins a clock and now runs there against an injected one; this keeps
        # the same verdict asserted against the real system clock.
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier(max_signed_age_millis=60_000).verify_transaction(
                text("generated", "transaction.jws"))
        self.assertEqual(ctx.exception.reason, "STALE_PAYLOAD")

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

    def test_renders_the_fields_cases_json_cannot_pin(self):
        # The verdict and every deterministic field are pinned by
        # endpoint/sandbox-receipt-on-sandbox-answers-0 in fixtures/cases.json.
        # What is left here is the COMPARISON.md "full fidelity" field set that
        # a shared vector cannot express: request_date is the wall clock at
        # call time, and the _ms/_pst siblings of each date are asserted by
        # presence rather than by value.
        receipt = self.endpoint("Sandbox").verify_receipt(self.request())["receipt"]
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
        self.assertEqual(endpoint.verify_receipt({})["status"], 21002)
        self.assertEqual(endpoint.verify_receipt(None)["status"], 21002)
        self.assertEqual(
            endpoint.verify_receipt({"receipt-data": "AQIDBA=="})["status"], 21002)

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


class PublicReceiptsTest(unittest.TestCase):
    """Genuine Apple-signed receipts vs the REAL pinned Apple root. The
    verdicts live in fixtures/cases.json; what stays here is the base64-string
    input form, which the conformance harness never takes (it always hands
    verify() the decoded bytes)."""

    def receipt(self, name):
        return (FIXTURES / "public-receipts" / f"{name}.b64").read_text().strip()

    def test_verifies_genuine_sandbox_receipt_from_its_base64_form(self):
        verifier = ReceiptVerifier(apple_receipt_roots(), "dev.bonzer.weeka.app")
        self.assertEqual(verifier.verify(self.receipt("receipt-sandbox-g5")).receipt_type,
                         "ProductionSandbox")


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
    field = tlv(0x02, attribute_type.to_bytes(2, "big")) + tlv(0x02, b"\x01") \
        + tlv(0x04, tlv(0x02, value_bytes))
    in_app = tlv(0x02, b"\x11") + tlv(0x02, b"\x01") + tlv(0x04, tlv(0x31, tlv(0x30, field)))
    return tlv(0x31, tlv(0x30, in_app))


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
        # each.
        from apple_purchase_receipt_verifier.receipt import _parse_payload
        for name, type_bytes, message in (
                ("leading byte 0x80", b"\x80", "negative receipt integer"),
                ("nine bytes", b"\x00" * 8 + b"\x01", "out of range")):
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
                ("the old 8-byte ceiling", b"\x7f" + b"\xff" * 7)):
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
            payload_with_in_app_integer(1711, b"\x7f" + b"\xff" * 7)).in_app_purchases[0]
        self.assertEqual(purchase.web_order_line_item_id, 2**63 - 1)
        with self.assertRaises(VerificationError) as ctx:
            _parse_payload(payload_with_in_app_integer(1711, b"\x00" * 8 + b"\x01"))
        self.assertEqual(ctx.exception.reason, "INVALID_RECEIPT_FORMAT")
        self.assertIn("out of range", str(ctx.exception))

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
    body = (signed_data["version"].dump()
            + signed_data["digest_algorithms"].dump()
            + new_encap
            + signed_data["certificates"].dump()
            + signed_data["crls"].dump()
            + signed_data["signer_infos"].dump())
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

    def test_receipt_verifier_takes_no_clock(self):
        # Nothing on the receipt path has a verdict that moves with the current
        # time: chain validity anchors at the receipt creation date, and the
        # "else current time" fallback is a certificate-validity judgement an
        # injected clock must not be able to shift. So the option does not
        # exist here — the seam lives on the JWS verifier (max signed age) and
        # on the endpoint (request_date) only.
        import inspect

        from apple_purchase_receipt_verifier import verify_receipt_core
        for callable_ in (ReceiptVerifier.__init__, ReceiptVerifier.verify,
                          verify_receipt_core):
            with self.subTest(callable_.__qualname__):
                self.assertNotIn("clock", inspect.signature(callable_).parameters)

    def test_verify_receipt_core_is_public(self):
        # The endpoint accepts any bundle id, exactly as Apple's does. It gets
        # that by calling the bundle-agnostic primitive, which is part of the
        # published API — not by constructing a ReceiptVerifier with a wildcard
        # bundle id, which would put a bundle-id check one typo away from
        # passing for everyone.
        import apple_purchase_receipt_verifier as package
        self.assertIn("verify_receipt_core", package.__all__)
        fields = package.verify_receipt_core(
            fixture("generated", "receipt.der"), [cert("generated", "receipt-root.der")])
        self.assertEqual(BUNDLE, fields.bundle_id)

    def test_endpoint_environment_is_the_typed_enum(self):
        # cases.json spells the endpoint's environment as the same enum the
        # rest of the library uses, not as a boolean "production" flag.
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint
        roots = [cert("generated", "receipt-root.der")]
        for environment in ("Production", "Sandbox"):
            VerifyReceiptEndpoint(roots, environment)
        for rejected in (True, False, "production", "sandbox", "", None):
            with self.subTest(rejected):
                with self.assertRaises(ValueError):
                    VerifyReceiptEndpoint(roots, rejected)


class ClockSeamTest(unittest.TestCase):
    """The optional ``clock`` option: which verdicts it moves, and which it
    must not. A clock is a zero-argument callable returning epoch seconds —
    the same contract as ``time.time``, which is the default."""

    # transaction.jws is signed at 2024-08-06T00:00:00Z. Every expectation
    # below is derived from that instant, never from the machine's clock.
    SIGNED_AT = 1722945600.0
    MAX_AGE_MILLIS = 60_000

    def transaction(self):
        return text("generated", "transaction.jws")

    def expired_chain_verifier(self, clock=None):
        return jws_verifier(
            trusted_roots=[cert("generated", "jws-expired-root.der")], clock=clock)

    def test_omitted_clock_reads_the_actual_system_clock(self):
        # Not "some fixed value": the accepted/rejected boundary is placed
        # either side of the payload's real age right now, so a default that
        # had frozen at import time (or ignored the clock entirely) would
        # fail one of the two halves.
        age_millis = time.time() * 1000 - self.SIGNED_AT * 1000
        self.assertGreater(age_millis, 0, "fixture is signed in the future")
        jws_verifier(max_signed_age_millis=int(age_millis) + 3_600_000) \
            .verify_transaction(self.transaction())
        with self.assertRaises(VerificationError) as ctx:
            jws_verifier(max_signed_age_millis=int(age_millis) - 3_600_000) \
                .verify_transaction(self.transaction())
        self.assertEqual(ctx.exception.reason, "STALE_PAYLOAD")

    def test_injected_clock_decides_the_stale_verdict(self):
        # Same payload, same max age, two clocks: the STALE_PAYLOAD verdict
        # follows the injected "now" and nothing else, which is what makes a
        # staleness vector runnable on any machine at any date.
        fresh = jws_verifier(max_signed_age_millis=self.MAX_AGE_MILLIS,
                             clock=lambda: self.SIGNED_AT + 30)
        self.assertEqual(BUNDLE, fresh.verify_transaction(self.transaction())["bundleId"])

        stale = jws_verifier(max_signed_age_millis=self.MAX_AGE_MILLIS,
                             clock=lambda: self.SIGNED_AT + 120)
        with self.assertRaises(VerificationError) as ctx:
            stale.verify_transaction(self.transaction())
        self.assertEqual(ctx.exception.reason, "STALE_PAYLOAD")

    def test_injected_clock_does_not_move_certificate_validity(self):
        # PLAN.md 2.1 step 4: the chain window is judged at the payload's
        # signedDate, never at wall-clock time. So a clock inside the expired
        # certificate's validity window must not rescue the fresh payload, and
        # a clock long past it must not condemn the historical one.
        for now in (1590969600.0, 4102444800.0):   # 2020-06-01, 2100-01-01
            with self.subTest(now=now):
                clock = (lambda moment: lambda: moment)(now)
                with self.assertRaises(VerificationError) as ctx:
                    self.expired_chain_verifier(clock).verify_transaction(
                        text("generated", "expired-cert-fresh.jws"))
                self.assertEqual(ctx.exception.reason, "INVALID_CHAIN")

                payload = self.expired_chain_verifier(clock).verify_transaction(
                    text("generated", "expired-cert-historical.jws"))
                self.assertEqual(1590969600000, payload["signedDate"])

    def test_injected_clock_does_not_move_certificate_validity_without_a_signed_date(self):
        # The gap the test above cannot reach: with neither signedDate nor
        # receiptCreationDate, PLAN.md §2.1 step 4 falls back to "current
        # time", and that fallback is deliberately the system clock. The same
        # payload WITH its signedDate verifies at 2020-06-01, so a fallback
        # wired to self._clock would let a clock pinned there accept an expired
        # chain — a caller injecting a clock for staleness, or around clock
        # skew, must not thereby widen a certificate's validity window.
        dated = text("generated", "expired-cert-historical.jws")
        self.assertEqual(
            1590969600000,
            self.expired_chain_verifier(lambda: 1590969600.0)
                .verify_transaction(dated)["signedDate"])
        undated = jws_without_signed_date(dated)
        for now in (None, 1590969600.0, 4102444800.0):   # system, 2020-06-01, 2100
            with self.subTest(now=now):
                clock = None if now is None else (lambda moment: lambda: moment)(now)
                with self.assertRaises(VerificationError) as ctx:
                    self.expired_chain_verifier(clock).verify_transaction(undated)
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
        self.assertEqual(
            "2020-06-01T00:00:00+00:00",
            verifier.verify(historical).creation_date.isoformat())
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
        data = {"receipt-data": base64.b64encode(
            fixture("generated", "receipt-expired-fresh.der")).decode()}
        historical = {"receipt-data": base64.b64encode(
            fixture("generated", "receipt-expired-historical.der")).decode()}
        self.assertEqual(
            0, VerifyReceiptEndpoint(roots, "Sandbox").verify_receipt(historical)["status"])
        for now in (None, 1590969600.0, 4102444800.0):   # system, 2020-06-01, 2100
            with self.subTest(now=now):
                clock = None if now is None else (lambda moment: lambda: moment)(now)
                endpoint = VerifyReceiptEndpoint(roots, "Sandbox", clock=clock)
                self.assertEqual(21003, endpoint.verify_receipt(data)["status"])

    def test_injected_clock_is_ignored_without_a_max_signed_age(self):
        # The clock is not a second expiry policy: with no max age configured
        # a payload signed a century "ago" still verifies.
        verifier = jws_verifier(clock=lambda: 4102444800.0)
        self.assertEqual(BUNDLE, verifier.verify_transaction(self.transaction())["bundleId"])

    def test_endpoint_clock_drives_request_date(self):
        # request_date is the one wall-clock field in a verifyReceipt
        # response (every other date comes off the signed receipt), so the
        # same seam covers it — consistency, and it makes the response
        # byte-reproducible for a caller that pins the clock.
        from apple_purchase_receipt_verifier import VerifyReceiptEndpoint
        endpoint = VerifyReceiptEndpoint(
            [cert("generated", "receipt-root.der")], "Sandbox",
            clock=lambda: 1735689600.0)   # 2025-01-01T00:00:00Z
        response = endpoint.verify_receipt({"receipt-data": base64.b64encode(
            fixture("generated", "receipt.der")).decode()})
        self.assertEqual(0, response["status"])
        receipt = response["receipt"]
        self.assertEqual("2025-01-01 00:00:00 Etc/GMT", receipt["request_date"])
        self.assertEqual("1735689600000", receipt["request_date_ms"])
        self.assertEqual("2024-12-31 16:00:00 America/Los_Angeles",
                         receipt["request_date_pst"])
        # The receipt's own dates are unaffected by the clock.
        self.assertEqual("2024-08-06 12:00:00 Etc/GMT", receipt["receipt_creation_date"])
