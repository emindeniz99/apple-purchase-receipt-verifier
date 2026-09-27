"""Python-only tests over the shared fixture sets. The facts every
implementation must agree on live in fixtures/cases.json and are run by
tests/test_conformance.py; what is left here is what a shared vector cannot
express: forged and mutated inputs built at run time, the raw JSON wire
form, resource bounds, and Config/Verifier construction."""

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

from apple_purchase_receipt_verifier import Config, Environment, Reason, Verifier
from asn1crypto import cms as asn1cms
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

FIXTURES = Path(__file__).resolve().parents[2] / "fixtures"


def fixture(*segments: str) -> bytes:
    return (FIXTURES.joinpath(*segments)).read_bytes()


def text(*segments: str) -> str:
    return fixture(*segments).decode("ascii").strip()


def cert(*segments: str) -> x509.Certificate:
    return x509.load_der_x509_certificate(fixture(*segments))


def receipt_verifier(*, roots: "list[x509.Certificate] | None" = None) -> Verifier:
    return Verifier(Config.create(roots=roots or [cert("generated-0.7", "receipt-root.der")]))


def jws_verifier() -> Verifier:
    return Verifier(Config.create(roots=[cert("generated", "jws-root.der")]))


class ConfigAndVerifierTest(unittest.TestCase):
    def test_verifier_rejects_an_empty_root_set(self) -> None:
        with self.assertRaises(ValueError):
            Verifier(Config.create(roots=[]))

    def test_config_defaults_loads_the_bundled_apple_roots(self) -> None:
        config = Config.defaults()
        self.assertEqual(3, len(config.roots))

    def test_endpoint_rejects_a_non_environment(self) -> None:
        with self.assertRaises(TypeError):
            receipt_verifier().verify_receipt_endpoint("PRODUCTION", None)  # type: ignore[arg-type]

    def test_verify_receipt_never_raises_for_garbage_input(self) -> None:
        for value in (None, "", "!!!not-base64!!!", "\x00" * 10, "A" * 5):
            with self.subTest(value=value):
                result = receipt_verifier().verify_receipt(value)
                self.assertFalse(result.verified)
                self.assertIsNotNone(result.failure)

    def test_verify_signed_data_never_raises_for_garbage_input(self) -> None:
        for value in (None, "", "not.a.jws", "\x00.\x00.\x00"):
            with self.subTest(value=value):
                result = jws_verifier().verify_signed_data(value)
                self.assertFalse(result.verified)
                self.assertIsNotNone(result.failure)


class MutationFuzzTest(unittest.TestCase):
    """``Verifier`` never raises for any input (docs/design/0.7-api.md,
    "The verify methods never throw"): every result comes back as a
    ``VerificationResult``, whatever a byte flip did to a genuine receipt or
    JWS. Random mutation is what carries an input deep enough to reach the
    certificate and claim decoders behind the outer structure checks; a
    fixed corpus does not (python/fuzz found several real escapes this way,
    all now closed by the catch-all guards in receipt.py and jws.py)."""

    def test_mutations_of_a_genuine_receipt_never_escape_as_an_exception(self) -> None:
        verifier = receipt_verifier()
        genuine = fixture("generated-0.7", "receipt.der")
        rnd = random.Random(1234)  # fixed seed: a failure must be reproducible
        for i in range(2000):
            mutant = bytearray(genuine)
            for _ in range(rnd.randint(1, 3)):
                mutant[rnd.randrange(len(mutant))] = rnd.randrange(256)
            b64 = base64.b64encode(bytes(mutant)).decode()
            try:
                verifier.verify_receipt(b64)
            except Exception as e:
                self.fail(f"mutation {i} leaked {type(e).__name__}: {e}")

    def test_mutations_of_a_genuine_jws_never_escape_as_an_exception(self) -> None:
        verifier = jws_verifier()
        genuine = text("generated", "transaction.jws")
        alphabet = string.ascii_letters + string.digits + "-_."
        rnd = random.Random(1234)  # fixed seed: a failure must be reproducible
        for i in range(400):
            mutant = list(genuine)
            for _ in range(rnd.randint(1, 3)):
                mutant[rnd.randrange(len(mutant))] = rnd.choice(alphabet)
            candidate = "".join(mutant)
            try:
                verifier.verify_signed_data(candidate)
            except Exception as e:
                self.fail(f"mutation {i} leaked {type(e).__name__}: {e}")


def tlv(tag: int, contents: bytes) -> bytes:
    """DER tag-length-value: these builders emit structures no encoder
    would produce for them (extra decoy certificates spliced in)."""
    if len(contents) < 0x80:
        return bytes([tag, len(contents)]) + contents
    length = len(contents).to_bytes((len(contents).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(length)]) + length + contents


# The two issuer names in the shared generated-0.7 chain. Decoy certificates
# carry them so each one stays a candidate the path builder must actually
# verify, rather than one it can reject on a name comparison alone.
MESH_NAMES = ("Fake WWDR CA", "Fake Apple Inc Root")


def cross_signed_mesh(layers: int = 14, branching: int = 2) -> "list[bytes]":
    """``branching`` CA certificates per layer, each cross-signed by every
    node of the layer above and the top layer wrapped back onto the bottom,
    so no path ever terminates: the shape that makes a path builder
    without a length bound explore ``branching**layers`` paths. Every
    certificate is a CA, valid now, and named after the layer's issuer, so
    nothing but the count disqualifies it as a candidate."""
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


def receipt_with_extra_certificates(extra: "list[bytes]") -> bytes:
    """The shared 0.7 receipt with ``extra`` certificates spliced in ahead
    of its own. Payload, chain and signature are untouched, so without a
    bound on the count everything still verifies, after the extras have
    been parsed and offered to path building."""
    info = asn1cms.ContentInfo.load(fixture("generated-0.7", "receipt.der"))
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
# count it among the CertificateChoices, and not enough for cryptography,
# which rejects it on the first field of the TBSCertificate.
NOT_A_CERTIFICATE = tlv(0x30, tlv(0x02, b"\x01"))


def embedded_certificate_count(der: bytes) -> int:
    return len(asn1cms.ContentInfo.load(der)["content"]["certificates"])


def receipt_base64(der: bytes) -> str:
    return base64.b64encode(der).decode("ascii")


def failure_of(result: Any) -> Any:
    assert result.failure is not None
    return result.failure


class EmbeddedCertificateFloodTest(unittest.TestCase):
    """The embedded certificates are attacker-supplied and are parsed and
    offered to path building before anything about the receipt has been
    verified, so their count is bounded before any of that runs."""

    mesh: ClassVar["list[Any]"]

    @classmethod
    def setUpClass(cls) -> None:
        cls.mesh = cross_signed_mesh()

    def test_rejects_a_receipt_embedding_more_certificates_than_a_chain_holds(self) -> None:
        receipt = receipt_with_extra_certificates(self.mesh[:8])  # 8 + the chain's own 3
        self.assertEqual(11, embedded_certificate_count(receipt))
        result = receipt_verifier().verify_receipt(receipt_base64(receipt))
        self.assertFalse(result.verified)
        self.assertEqual(Reason.MALFORMED, failure_of(result).reason)

    def test_admits_a_receipt_embedding_exactly_the_bound(self) -> None:
        # Seven mesh certificates ahead of the chain's own three is exactly
        # the bound, so the guard stands aside and the receipt verifies as
        # it would without them.
        receipt = receipt_with_extra_certificates(self.mesh[:7])
        self.assertEqual(10, embedded_certificate_count(receipt))
        result = receipt_verifier().verify_receipt(receipt_base64(receipt))
        self.assertTrue(result.verified)

    def test_counts_the_embedded_certificates_before_parsing_any_of_them(self) -> None:
        # Eight of the eleven are not certificates at all, so where the
        # count is checked decides which rejection a caller gets: counting
        # first names the count.
        receipt = receipt_with_extra_certificates([NOT_A_CERTIFICATE] * 8)
        self.assertEqual(11, embedded_certificate_count(receipt))
        result = receipt_verifier().verify_receipt(receipt_base64(receipt))
        self.assertFalse(result.verified)
        self.assertEqual(Reason.MALFORMED, failure_of(result).reason)
        self.assertIn("11 certificates", failure_of(result).message)

    def test_rejects_a_cross_signed_certificate_mesh_promptly(self) -> None:
        # Why the bound exists: this mesh costs the sender nothing and is
        # what a path builder that backtracks spends branching**layers on.
        # The top-down walk here tries at most 6 candidates deep, so
        # uncapped it pays one RSA verification per decoy instead of an
        # exponential search. The budget is generous so a loaded runner
        # cannot flake it, and only a combinatorial regression exceeds it.
        receipt = receipt_with_extra_certificates(self.mesh)
        self.assertEqual(59, embedded_certificate_count(receipt))
        started = time.perf_counter()
        result = receipt_verifier().verify_receipt(receipt_base64(receipt))
        elapsed = time.perf_counter() - started
        self.assertFalse(result.verified)
        self.assertEqual(Reason.MALFORMED, failure_of(result).reason)
        self.assertLess(elapsed, 5.0, f"rejecting the mesh took {elapsed:.3f}s")


class BoundsTest(unittest.TestCase):
    def test_receipt_string_over_the_cap_is_refused_as_too_large(self) -> None:
        from apple_purchase_receipt_verifier.receipt import MAX_RECEIPT_BYTES

        over = "A" * (MAX_RECEIPT_BYTES + 4)
        result = receipt_verifier().verify_receipt(over)
        self.assertFalse(result.verified)
        self.assertEqual(Reason.TOO_LARGE, failure_of(result).reason)

    def test_jws_over_the_cap_is_refused_as_too_large(self) -> None:
        from apple_purchase_receipt_verifier.jws import MAX_JWS_BYTES

        over = "A." * (MAX_JWS_BYTES // 2 + 4)
        result = jws_verifier().verify_signed_data(over)
        self.assertFalse(result.verified)
        self.assertEqual(Reason.TOO_LARGE, failure_of(result).reason)

    def test_request_body_over_the_cap_is_malformed_status_21002(self) -> None:
        from apple_purchase_receipt_verifier.endpoint import MAX_REQUEST_BYTES

        body = json.dumps({"receipt-data": "A" * MAX_REQUEST_BYTES})
        response = receipt_verifier().verify_receipt_endpoint(Environment.PRODUCTION, body)
        self.assertEqual(21002, json.loads(response)["status"])

    def test_receipt_string_is_measured_in_utf8_bytes_not_characters(self) -> None:
        from apple_purchase_receipt_verifier.receipt import MAX_RECEIPT_BYTES

        # Each "e" with a combining accent is 1 character but 3 UTF-8 bytes;
        # this string is well under MAX_RECEIPT_BYTES characters but over it
        # in bytes, so a character-counted cap would wrongly admit it.
        non_ascii = "é" * (MAX_RECEIPT_BYTES // 2 - 1)
        self.assertLess(len(non_ascii), MAX_RECEIPT_BYTES)
        self.assertGreater(len(non_ascii.encode("utf-8")), MAX_RECEIPT_BYTES)
        result = receipt_verifier().verify_receipt(non_ascii)
        self.assertFalse(result.verified)
        self.assertEqual(Reason.TOO_LARGE, failure_of(result).reason)


class ClockTest(unittest.TestCase):
    def test_receipt_without_a_creation_date_anchors_on_the_configured_clock(self) -> None:
        # The shared 0.7 root's own validity covers "now" for any
        # reasonable test run, so a receipt with no creation date verifying
        # at all shows the fallback reached the clock rather than raising.
        moment = datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc)
        clock = lambda: int(moment.timestamp() * 1000)  # noqa: E731
        verifier = Verifier(
            Config.create(roots=[cert("generated-0.7", "receipt-root.der")], clock=clock)
        )
        result = verifier.verify_receipt(receipt_base64(fixture("generated-0.7", "receipt.der")))
        self.assertTrue(result.verified)

    def test_endpoint_clock_drives_request_date(self) -> None:
        moment = datetime.datetime(2030, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc)
        clock = lambda: int(moment.timestamp() * 1000)  # noqa: E731
        verifier = Verifier(
            Config.create(roots=[cert("generated-0.7", "receipt-root.der")], clock=clock)
        )
        body = json.dumps({"receipt-data": receipt_base64(fixture("generated-0.7", "receipt.der"))})
        response = json.loads(verifier.verify_receipt_endpoint(Environment.SANDBOX, body))
        self.assertEqual("2030-03-04 05:06:07 Etc/GMT", response["receipt"]["request_date"])


class ClockReadTest(unittest.TestCase):
    """The clock is read at most once per call, and a clock that fails is
    the host's fault: INTERNAL_ERROR (21009 at the endpoint), never a
    verdict about the input and never an exception out of a method that
    promises not to raise (docs/design/0.7-api.md, "Setup")."""

    def dateless(self) -> str:
        return receipt_base64(fixture("generated-0.7", "receipt-no-creation-date.der"))

    def dateless_verifier(self, clock: "Any") -> Verifier:
        roots = [cert("generated-0.7", "divergence-receipt-root.der")]
        return Verifier(Config.create(roots=roots, clock=clock))

    def test_the_endpoint_reads_the_clock_once_for_a_dateless_receipt(self) -> None:
        # A dateless receipt needs "now" twice: for the chain instant and for
        # request_date. Both must be one reading, or the response can show a
        # request_date the chain was not judged at.
        reads: list[int] = []

        def clock() -> int:
            reads.append(1)
            return 1735689600000 + len(reads) * 3_600_000  # 2025-01-01 plus an hour a read

        verifier = self.dateless_verifier(clock)
        body = json.dumps({"receipt-data": self.dateless()})
        response = json.loads(verifier.verify_receipt_endpoint(Environment.SANDBOX, body))
        self.assertEqual(0, response["status"])
        self.assertEqual(1, len(reads))
        self.assertEqual("1735693200000", response["receipt"]["request_date_ms"])

        self.assertTrue(verifier.verify_receipt(self.dateless()).verified)
        self.assertEqual(2, len(reads), "verify_receipt must read the clock exactly once")

    def test_a_clock_that_raises_is_an_internal_error(self) -> None:
        def clock() -> int:
            raise RuntimeError("clock backend unavailable")

        verifier = self.dateless_verifier(clock)
        failure = failure_of(verifier.verify_receipt(self.dateless()))
        self.assertEqual(Reason.INTERNAL_ERROR, failure.reason)
        self.assertIsInstance(failure.cause, RuntimeError)

        jws = jws_without_signed_date(text("generated", "transaction.jws"))
        jws_failure = failure_of(
            Verifier(
                Config.create(roots=[cert("generated", "jws-root.der")], clock=clock)
            ).verify_signed_data(jws)
        )
        self.assertEqual(Reason.INTERNAL_ERROR, jws_failure.reason)

        for label, data in (
            ("dateless", self.dateless()),
            # A dated receipt needs the clock only for request_date.
            ("dated", receipt_base64(fixture("generated-0.7", "receipt.der"))),
        ):
            with self.subTest(label):
                roots = (
                    [cert("generated-0.7", "divergence-receipt-root.der")]
                    if label == "dateless"
                    else [cert("generated-0.7", "receipt-root.der")]
                )
                endpoint = Verifier(Config.create(roots=roots, clock=clock))
                body = json.dumps({"receipt-data": data})
                self.assertEqual(
                    '{"status":21009}', endpoint.verify_receipt_endpoint(Environment.SANDBOX, body)
                )


def jws_without_signed_date(compact: str) -> str:
    """The given JWS with ``signedDate`` dropped from its payload, so the
    chain is judged at the configured clock. The signature no longer
    matches; the chain is checked first, so the clock is still read."""
    header, payload, signature = compact.split(".")
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    claims.pop("signedDate", None)
    undated = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    return f"{header}.{undated}.{signature}"


# Reasons a failure before the signature has verified may carry. The input
# is still unauthenticated there, so an unexpected parser error must never
# become INTERNAL_ERROR or UNREADABLE_PAYLOAD (hardening parity change 4).
PRE_SIGNATURE_REASONS = (
    Reason.MALFORMED,
    Reason.TOO_LARGE,
    Reason.INVALID_SIGNATURE,
    Reason.UNTRUSTED_CHAIN,
    Reason.INVALID_CERTIFICATE,
    Reason.INVALID_CERTIFICATE_PURPOSE,
)

# An anonymous 162-byte blob: no certificates, no signature, one creation
# date of 0001-01-01T00:00:00+10:00, which 0.6's datetime-based decoder
# could not convert to UTC (OverflowError).
OUT_OF_RANGE_DATE_RECEIPT = (
    "MIGfBgkqhkiG9w0BBwKggZEwgY4CAQExDzANBglghkgBZQMEAgEFADA2BgkqhkiG9w0BBwGgKQQnMSUw"
    "IwIBDAIBAQQbFhkwMDAxLTAxLTAxVDAwOjAwOjAwKzEwOjAwMUAwPgIBATARMAwxCjAIBgNVBAMMAXgC"
    "AQEwDQYJYIZIAWUDBAIBBQAwDQYJKoZIhvcNAQEBBQAECAAAAAAAAAAA"
)

_OID_MESSAGE_DIGEST = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x04"
_OID_SIGNING_TIME = b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x09\x05"
_OID_UNKNOWN = b"\x06\x03\x2a\x03\x04"


def hostile_attribute_sets() -> "dict[str, bytes]":
    """signedAttrs an attacker can splice in, one per raw exception class
    a Python decoder has raised on them."""
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


def spliced_receipt(
    signed_attrs: "bytes | None" = None,
    digest_algorithm: "bytes | None" = None,
    signature: "bytes | None" = None,
) -> bytes:
    """The shared 0.7 receipt with attacker-supplied SignerInfo fields
    spliced in. Its certificates and payload are untouched, so the chain and
    marker checks still pass and the decoder runs on hostile bytes before
    the signature check gets to reject them."""
    info = asn1cms.ContentInfo.load(fixture("generated-0.7", "receipt.der"))
    signed_data = info["content"]
    signer = signed_data["signer_infos"][0]
    spliced = tlv(
        0x30,
        signer["version"].dump()
        + signer["sid"].dump()
        + (digest_algorithm or signer["digest_algorithm"].dump())
        + (b"\xa0" + signed_attrs[1:] if signed_attrs else signer["signed_attrs"].dump())
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


def payload_with_attribute_type(type_bytes: bytes) -> bytes:
    """A receipt payload SET carrying the creation date and one attribute
    whose type INTEGER is ``type_bytes``."""
    date = tlv(0x02, b"\x0c") + tlv(0x02, b"\x01") + tlv(0x04, tlv(0x16, b"2024-08-06T12:00:00Z"))
    probe = tlv(0x02, type_bytes) + tlv(0x02, b"\x01") + tlv(0x04, b"")
    return tlv(0x31, tlv(0x30, date) + tlv(0x30, probe))


def segment(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class HostileInputTest(unittest.TestCase):
    """The signedAttrs, the SignerInfo fields and the creation date are
    decoded before the signature check, so an attacker reaches those
    decoders with arbitrary bytes. Each must come back as a failure the
    unauthenticated input can earn, never a raised exception and never
    INTERNAL_ERROR."""

    def assert_pre_signature_failure(self, result: Any, label: str) -> None:
        self.assertFalse(result.verified, label)
        self.assertIn(failure_of(result).reason, PRE_SIGNATURE_REASONS, label)

    def test_hostile_signed_attrs_are_contained(self) -> None:
        verifier = receipt_verifier()
        for name, attributes in hostile_attribute_sets().items():
            with self.subTest(name):
                result = verifier.verify_receipt(
                    receipt_base64(spliced_receipt(signed_attrs=attributes))
                )
                self.assert_pre_signature_failure(result, name)

    def test_a_message_digest_with_more_than_one_value_is_refused(self) -> None:
        # RFC 5652 section 5.3 allows exactly one value; unguarded, a decoder
        # silently takes the first of whatever list the attacker supplied.
        attributes = hostile_attribute_sets()["two messageDigest values"]
        result = receipt_verifier().verify_receipt(
            receipt_base64(spliced_receipt(signed_attrs=attributes))
        )
        self.assertEqual(Reason.INVALID_SIGNATURE, failure_of(result).reason)

    def test_hostile_signer_info_fields_are_contained(self) -> None:
        verifier = receipt_verifier()
        corpus = {
            "digest algorithm that is not an OID": spliced_receipt(
                digest_algorithm=tlv(0x30, tlv(0x02, b"\x01"))
            ),
            "signature that is not an octet string": spliced_receipt(signature=tlv(0x02, b"\x01")),
            "truncated receipt": fixture("generated-0.7", "receipt.der")[:200],
        }
        for name, der in corpus.items():
            with self.subTest(name):
                self.assert_pre_signature_failure(
                    verifier.verify_receipt(receipt_base64(der)), name
                )

    def test_a_creation_date_no_calendar_can_convert_is_contained(self) -> None:
        # Before trust the date only picks the chain instant; the blob embeds
        # no signer, so the answer is a format failure, never a leaked
        # OverflowError from the date decoder.
        result = Verifier(Config.defaults()).verify_receipt(OUT_OF_RANGE_DATE_RECEIPT)
        self.assertEqual(Reason.MALFORMED, failure_of(result).reason)

    def test_a_negative_attribute_type_makes_the_payload_unreadable(self) -> None:
        # 0x80 is the smallest leading byte of a negative two's-complement
        # INTEGER. An attribute type is a 32-bit signed value that cannot
        # be negative, so the signed content does not parse. Driven through
        # the payload parser: a shared case cannot sign content this broken
        # under every port's own test PKI.
        from apple_purchase_receipt_verifier._errors import VerificationError
        from apple_purchase_receipt_verifier.receipt import _parse_signed_payload

        with self.assertRaises(VerificationError) as ctx:
            _parse_signed_payload(payload_with_attribute_type(b"\x80"))
        self.assertEqual(Reason.UNREADABLE_PAYLOAD, ctx.exception.reason)

    def test_unreadable_payload_keeps_the_parser_error_as_its_cause(self) -> None:
        # The cause tells an operator why Apple-signed content did not parse
        # (docs/design/0.7-api.md, "cause").
        verifier = Verifier(
            Config.create(
                roots=[cert("generated-0.7", "api-receipt-root.der")],
                clock=lambda: 1735689600000,  # 2025-01-01, inside the chain window
            )
        )
        result = verifier.verify_receipt(
            receipt_base64(fixture("generated-0.7", "receipt-content-not-asn1.der"))
        )
        failure = failure_of(result)
        self.assertEqual(Reason.UNREADABLE_PAYLOAD, failure.reason)
        self.assertIsInstance(failure.cause, Exception)
        # Behind a verdict about unauthenticated input the cause is dropped:
        # its text could quote certificate names from the input.
        self.assertIsNone(failure_of(verifier.verify_receipt("AQIDBA==")).cause)


class JwsHostileInputTest(unittest.TestCase):
    """The JWS header and payload are attacker-supplied JSON, decoded before
    the signature that would reject them. Each case here was a raw Python
    exception out of the 0.6 JWS verifier (python/fuzz)."""

    def setUp(self) -> None:
        self.header, self.payload, self.signature = text("generated", "transaction.jws").split(".")

    def header_claims(self) -> "dict[str, Any]":
        claims: dict[str, Any] = json.loads(
            base64.urlsafe_b64decode(self.header + "=" * (-len(self.header) % 4))
        )
        return claims

    def test_a_signed_date_no_calendar_can_express_is_judged_at_the_clock(self) -> None:
        # datetime covers years 1 to 9999, so 0.6 leaked OverflowError for
        # 1e300 and ValueError for NaN, which json.loads accepts. In 0.7 such
        # a signedDate counts as missing: the chain is judged at the clock,
        # passes, and the forged payload fails the signature.
        for name, raw in (
            ("far future float", b'{"signedDate": 1e300}'),
            ("far past float", b'{"signedDate": -1e300}'),
            ("integer past the range", b'{"signedDate": 1' + b"0" * 30 + b"}"),
            ("NaN", b'{"signedDate": NaN}'),
            ("Infinity", b'{"signedDate": Infinity}'),
        ):
            with self.subTest(name):
                result = jws_verifier().verify_signed_data(
                    f"{self.header}.{segment(raw)}.{self.signature}"
                )
                self.assertEqual(Reason.INVALID_SIGNATURE, failure_of(result).reason)

    def test_x5c_entries_of_any_json_type_but_string_are_malformed(self) -> None:
        # A JSON array of numbers, containers or null used to reach
        # base64.b64decode, whose TypeError the decode site did not catch.
        # The shared case covers one non-string entry; Python's JSON types
        # make every other shape reachable too.
        claims = self.header_claims()
        for name, entries in (
            ("numbers", [1, 2, 3]),
            ("containers and null", [[], {}, None]),
            ("one entry short of all strings", [claims["x5c"][0], claims["x5c"][1], 3]),
        ):
            with self.subTest(name):
                hostile = segment(json.dumps(dict(claims, x5c=entries)).encode())
                result = jws_verifier().verify_signed_data(
                    f"{hostile}.{self.payload}.{self.signature}"
                )
                self.assertEqual(Reason.MALFORMED, failure_of(result).reason)

    def test_deep_nesting_never_reaches_the_recursive_parser(self) -> None:
        # json.loads recurses once per level and has no depth option, so a
        # segment nested past what the interpreter's stack allows must be
        # refused by the bound, not by a RecursionError. 20,000 levels stay
        # under the JWS size cap.
        deep = ("[" * 20_000 + "]" * 20_000).encode()
        header = jws_verifier().verify_signed_data(
            f"{segment(deep)}.{self.payload}.{self.signature}"
        )
        self.assertEqual(Reason.MALFORMED, failure_of(header).reason)
        # An over-bound payload is carried past the signature check, which
        # the forged payload fails.
        payload = jws_verifier().verify_signed_data(
            f"{self.header}.{segment(deep)}.{self.signature}"
        )
        self.assertEqual(Reason.INVALID_SIGNATURE, failure_of(payload).reason)


class EndpointWireTest(unittest.TestCase):
    """The raw JSON text of verifyReceipt answers, which a shared case
    compares only after parsing."""

    def body(self) -> str:
        return json.dumps({"receipt-data": receipt_base64(fixture("generated-0.7", "receipt.der"))})

    def test_the_wire_types_are_apples(self) -> None:
        # Raw bytes, not just the parse: status is a JSON number, every
        # number-shaped receipt field a JSON string, as Apple sends them.
        wire = receipt_verifier().verify_receipt_endpoint(Environment.SANDBOX, self.body())
        self.assertIn('"status":0', wire)
        self.assertIn('"quantity":"1"', wire)
        self.assertIn('"web_order_line_item_id":"42"', wire)
        parsed = json.loads(wire)
        self.assertIs(type(parsed["status"]), int)
        receipt = parsed["receipt"]
        self.assertIsInstance(receipt["receipt_creation_date_ms"], str)
        self.assertIsInstance(receipt["request_date_ms"], str)
        for purchase in receipt["in_app"]:
            for key in ("quantity", "web_order_line_item_id", "purchase_date_ms"):
                self.assertIsInstance(purchase.get(key, ""), str, key)

    def test_every_date_is_rendered_as_apples_triple(self) -> None:
        receipt = json.loads(
            receipt_verifier().verify_receipt_endpoint(Environment.SANDBOX, self.body())
        )["receipt"]
        for key in ("request_date", "request_date_ms", "request_date_pst"):
            self.assertIn(key, receipt)
        coins = next(p for p in receipt["in_app"] if p["product_id"] == "com.example.app.coins100")
        for key in ("purchase_date", "purchase_date_ms", "purchase_date_pst"):
            self.assertIn(key, coins)
        vip = next(p for p in receipt["in_app"] if p["product_id"] == "com.example.app.vip")
        for key in ("expires_date", "expires_date_ms", "expires_date_pst"):
            self.assertIn(key, vip)

    def test_is_in_intro_offer_period_is_the_string_apple_sends(self) -> None:
        receipt_data = (FIXTURES / "public-receipts" / "receipt-sandbox-g5.b64").read_text().strip()
        wire = Verifier(Config.defaults()).verify_receipt_endpoint(
            Environment.SANDBOX, json.dumps({"receipt-data": receipt_data})
        )
        self.assertIn('"is_in_intro_offer_period":"false"', wire)
        purchases = json.loads(wire)["receipt"]["in_app"]
        self.assertTrue(purchases)
        for purchase in purchases:
            self.assertIsInstance(purchase["is_in_intro_offer_period"], str)

    def test_a_non_zero_status_is_the_status_alone(self) -> None:
        self.assertEqual(
            '{"status":21007}',
            receipt_verifier().verify_receipt_endpoint(Environment.PRODUCTION, self.body()),
        )

    def test_anything_but_a_request_object_answers_21002(self) -> None:
        verifier = receipt_verifier()
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
            "NaN",
            "{}",
            '{"receipt-data":null}',
            '{"receipt-data":5}',
            '{"receipt-data":"AQIDBA=="}',
            None,
        ):
            with self.subTest(body=body):
                self.assertEqual(
                    '{"status":21002}', verifier.verify_receipt_endpoint(Environment.SANDBOX, body)
                )

    def test_brackets_inside_a_string_do_not_count_as_nesting(self) -> None:
        body = json.dumps(
            {
                "receipt-data": receipt_base64(fixture("generated-0.7", "receipt.der")),
                "note": '\\"' + "[" * 1000,
            }
        )
        response = json.loads(receipt_verifier().verify_receipt_endpoint(Environment.SANDBOX, body))
        self.assertEqual(0, response["status"])

    def test_a_body_nested_past_the_stack_answers_21002(self) -> None:
        deep = "[" * 100_000 + "]" * 100_000
        body = '{"receipt-data":"AQIDBA==","deep":' + deep + "}"
        self.assertEqual(
            '{"status":21002}',
            receipt_verifier().verify_receipt_endpoint(Environment.SANDBOX, body),
        )


class CostBeforeCapTest(unittest.TestCase):
    """The size caps exist so hostile input costs little to refuse: base64
    decoding and JSON parsing both allocate a multiple of their input before
    any signature is checked. These prove the expensive step never runs for
    an over-cap input. The patches are test-side; nothing in the library
    exists for them."""

    def test_the_caps_are_the_documented_ones(self) -> None:
        from apple_purchase_receipt_verifier.endpoint import MAX_REQUEST_BYTES
        from apple_purchase_receipt_verifier.jws import MAX_JWS_BYTES
        from apple_purchase_receipt_verifier.receipt import MAX_RECEIPT_BYTES

        self.assertEqual(3145728, MAX_RECEIPT_BYTES)
        self.assertEqual(3145728, MAX_REQUEST_BYTES)
        self.assertEqual(262144, MAX_JWS_BYTES)

    def test_an_over_cap_receipt_is_never_decoded(self) -> None:
        from apple_purchase_receipt_verifier.receipt import MAX_RECEIPT_BYTES

        # Two-byte characters: over the cap in UTF-8 bytes while under it in
        # characters, so a character count would let the decode run.
        for label, over in (
            ("ASCII", "A" * (MAX_RECEIPT_BYTES + 4)),
            ("two-byte characters", "\u00e9" * (MAX_RECEIPT_BYTES // 2) + "a"),
        ):
            with (
                self.subTest(label),
                mock.patch(
                    "apple_purchase_receipt_verifier.receipt.decode_receipt_base64"
                ) as decode,
            ):
                result = receipt_verifier().verify_receipt(over)
                decode.assert_not_called()
                self.assertEqual(Reason.TOO_LARGE, failure_of(result).reason)

    def test_an_over_cap_request_body_is_never_parsed(self) -> None:
        from apple_purchase_receipt_verifier.endpoint import MAX_REQUEST_BYTES

        body = "[" * (MAX_REQUEST_BYTES + 1)
        with (
            mock.patch("apple_purchase_receipt_verifier.endpoint.json.loads") as loads,
            mock.patch(
                "apple_purchase_receipt_verifier.endpoint._bounded_json.exceeds_bounds"
            ) as scan,
        ):
            wire = receipt_verifier().verify_receipt_endpoint(Environment.SANDBOX, body)
        loads.assert_not_called()
        scan.assert_not_called()
        self.assertEqual('{"status":21002}', wire)

    def test_an_over_cap_jws_is_never_decoded(self) -> None:
        from apple_purchase_receipt_verifier.jws import MAX_JWS_BYTES

        over = "A." * (MAX_JWS_BYTES // 2 + 4)
        with mock.patch("apple_purchase_receipt_verifier.jws._decode_base64url") as decode:
            result = jws_verifier().verify_signed_data(over)
        decode.assert_not_called()
        self.assertEqual(Reason.TOO_LARGE, failure_of(result).reason)

    def test_utf8_count_matches_the_encoder_on_each_side_of_the_limit(self) -> None:
        # The size check decides on len() shortcuts; each width is checked at
        # the limit and one byte past it, so a wrong shortcut factor shows up
        # as a verdict that disagrees with the encoder.
        from apple_purchase_receipt_verifier._utf8 import utf8_exceeds

        limit = 12
        for char in ("a", "\u00e9", "\u20ac", "\U0001f600", "\ud800"):
            width = len(char.encode("utf-8", "surrogatepass"))
            for sample in (char * (limit // width), char * (limit // width) + "a"):
                with self.subTest(char=ascii(char), length=len(sample)):
                    size = len(sample.encode("utf-8", "surrogatepass"))
                    self.assertEqual(size > limit, utf8_exceeds(sample, limit))

    def test_the_certificate_bound_clears_the_genuine_receipts_it_must_admit(self) -> None:
        # Read rather than asserted: the bound is only safe while it stays
        # above what Apple actually embeds.
        from apple_purchase_receipt_verifier.receipt import MAX_EMBEDDED_CERTIFICATES

        counts = {
            name: embedded_certificate_count(
                base64.b64decode((FIXTURES / "public-receipts" / f"{name}.b64").read_text().strip())
            )
            for name in (
                "receipt-sandbox-g5",
                "receipt-sandbox-legacy",
                "receipt-xcode-with-purchases",
            )
        }
        self.assertLess(max(counts.values()), MAX_EMBEDDED_CERTIFICATES, counts)


class ClockDoesNotMoveADatedChainTest(unittest.TestCase):
    def test_a_clock_inside_the_window_cannot_rescue_a_receipt_dated_outside_it(self) -> None:
        # The clock stands in only for a missing creation date. This receipt
        # states one after its chain expired, and a clock pinned inside the
        # chain window must not move the chain instant back there.
        roots = [cert("generated-0.7", "receipt-expired-root.der")]
        fresh = receipt_base64(fixture("generated-0.7", "receipt-expired-fresh.der"))
        historical = receipt_base64(fixture("generated-0.7", "receipt-expired-historical.der"))
        in_window = (
            int(datetime.datetime(2020, 6, 1, tzinfo=datetime.timezone.utc).timestamp()) * 1000
        )
        for label, clock in (("system", None), ("inside the window", lambda: in_window)):
            with self.subTest(label):
                verifier = Verifier(Config.create(roots=roots, clock=clock))
                self.assertTrue(verifier.verify_receipt(historical).verified)
                self.assertEqual(
                    Reason.INVALID_CERTIFICATE, failure_of(verifier.verify_receipt(fresh)).reason
                )
                body = json.dumps({"receipt-data": fresh})
                self.assertEqual(
                    '{"status":21003}', verifier.verify_receipt_endpoint(Environment.SANDBOX, body)
                )


class ApiShapeTest(unittest.TestCase):
    def test_the_bundled_roots_are_the_three_published_apple_roots(self) -> None:
        subjects = [c.subject.rfc4514_string() for c in Config.defaults().roots]
        self.assertEqual(3, len(subjects), subjects)
        self.assertTrue(any("Apple Root CA - G2" in s for s in subjects), subjects)
        self.assertTrue(any("Apple Root CA - G3" in s for s in subjects), subjects)
        # The file Apple labels "Apple Inc. Root" has subject CN=Apple Root CA.
        self.assertTrue(any(s.startswith("CN=Apple Root CA,") for s in subjects), subjects)

    def test_a_result_holds_exactly_one_of_payload_and_failure(self) -> None:
        from apple_purchase_receipt_verifier import Failure, VerificationResult

        failure = Failure(Reason.MALFORMED, "m")
        with self.assertRaises(ValueError):
            VerificationResult()
        with self.assertRaises(ValueError):
            VerificationResult(payload=object(), failure=failure)
        self.assertTrue(VerificationResult(payload=object()).verified)
        self.assertFalse(VerificationResult(failure=failure).verified)


if __name__ == "__main__":
    unittest.main()
