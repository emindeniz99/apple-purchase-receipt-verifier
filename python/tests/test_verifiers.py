"""Python-only tests over the shared fixture sets. The facts every
implementation must agree on live in fixtures/cases-0.7.json and are run by
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


if __name__ == "__main__":
    unittest.main()
