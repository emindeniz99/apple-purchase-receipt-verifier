"""Loads the Apple root certificates bundled with this package (copies of
the public roots from https://www.apple.com/certificateauthority/).
Production trust anchors; tests use the shared fixture PKI instead.

Both sets contain all three published Apple roots. Apple deliberately
documents the JWS chain as ending in "an Apple root certificate" (not a
specific one) and its guidance is to trust every root on the PKI page, so
anchoring on a single root would break silently if Apple re-anchored a
path — see PLAN.md D15."""

from pathlib import Path

from cryptography import x509

_CERTS = Path(__file__).parent / "certs"


def _load(name: str) -> x509.Certificate:
    return x509.load_der_x509_certificate((_CERTS / name).read_bytes())


def _all_roots() -> "list[x509.Certificate]":
    return [
        _load("AppleIncRootCertificate.cer"),
        _load("AppleRootCA-G2.cer"),
        _load("AppleRootCA-G3.cer"),
    ]


def apple_jws_roots() -> "list[x509.Certificate]":
    """Trust anchors for StoreKit 2 / App Store Server JWS chains.
    Production chains currently end at Apple Root CA - G3."""
    return _all_roots()


def apple_receipt_roots() -> "list[x509.Certificate]":
    """Trust anchors for legacy PKCS#7 app-receipt chains.
    Production chains currently end at the Apple Inc. Root CA."""
    return _all_roots()
