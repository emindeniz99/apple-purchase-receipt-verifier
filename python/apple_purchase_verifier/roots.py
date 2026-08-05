"""Loads the Apple root certificates bundled with this package (copies of
the public roots from https://www.apple.com/certificateauthority/).
Production trust anchors; tests use the shared fixture PKI instead."""

from pathlib import Path

from cryptography import x509

_CERTS = Path(__file__).parent / "certs"


def _load(name):
    return x509.load_der_x509_certificate((_CERTS / name).read_bytes())


def apple_jws_roots():
    """Apple Root CA - G3 — anchors StoreKit 2 / App Store Server JWS chains."""
    return [_load("AppleRootCA-G3.cer")]


def apple_receipt_roots():
    """Apple Inc. Root CA — anchors legacy PKCS#7 app-receipt chains."""
    return [_load("AppleIncRootCertificate.cer")]
