"""Certificate chain validation against pinned trust anchors, walked
top-down (hardening parity change #161): a certificate's signature is
checked only with a key a pinned root has already vouched for, and a
certificate's own key is never decoded until ITS signature has verified
that way. This is what keeps a receipt or JWS padded with a stranger
certificate (including one carrying a key too large to decode cheaply)
from costing more than the handful of signature checks a genuine chain
needs: an unvouched candidate is never tried as an issuer, so its key is
never read.

Hand-rolled because ``cryptography``'s verification API is TLS-oriented;
these are the PKIX-equivalent checks the Java implementation gets from
``CertPathValidator``: signature + name chaining at each step, basic
constraints and keyUsage on every issuing certificate, and validity windows
at signing time. Anchors are trusted by fiat (their own expiry is not
checked).
"""

from collections.abc import Sequence
from datetime import datetime, timezone

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import ExtensionOID

from ._errors import VerificationError
from .reason import Reason

#: The longest path a receipt's embedded certificates may form, anchor
#: excluded: at most this many certificates starting at the signer before a
#: pinned anchor must be reached. Genuine receipt chains are two
#: certificates below the root.
MAX_PATH_LENGTH = 6

#: Extensions this library actually reads. RFC 5280 4.2: a certificate
#: carrying a critical extension outside this set is unusable to a
#: conforming implementation, so an intermediate carrying one is rejected
#: by ``_is_ca`` rather than silently accepted with the extension ignored.
#: The two Apple marker OIDs (jws.LEAF_OID / jws.INTERMEDIATE_OID, not
#: imported here to avoid a cycle) are included even though genuine Apple
#: certificates never mark them critical, because the library does read
#: and act on them (receipt._require_markers, jws._require_markers).
_RECOGNIZED_CRITICAL_EXTENSIONS = frozenset(
    [
        ExtensionOID.BASIC_CONSTRAINTS,
        ExtensionOID.KEY_USAGE,
        x509.ObjectIdentifier("1.2.840.113635.100.6.11.1"),
        x509.ObjectIdentifier("1.2.840.113635.100.6.2.1"),
    ]
)


def _not_valid_before(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_before_utc  # cryptography >= 42
    except AttributeError:
        return cert.not_valid_before.replace(tzinfo=timezone.utc)


def _not_valid_after(cert: x509.Certificate) -> datetime:
    try:
        return cert.not_valid_after_utc
    except AttributeError:
        return cert.not_valid_after.replace(tzinfo=timezone.utc)


def valid_at_ms(cert: x509.Certificate, at_ms: int) -> bool:
    """Whether ``cert``'s own validity window covers ``at_ms`` (epoch
    milliseconds). Compared as plain integers rather than by building a
    ``datetime`` for ``at_ms``: a signing date an attacker chose can be far
    outside the range ``datetime`` represents (years 1-9999) while still
    fitting a signed 64-bit value (the JWS `signedDate: 9e15` case), and
    such an instant is still perfectly comparable to a certificate's
    (always sane) bounds without ever being constructed as a ``datetime``.
    """
    before_ms = int(_not_valid_before(cert).timestamp() * 1000)
    after_ms = int(_not_valid_after(cert).timestamp() * 1000)
    return before_ms <= at_ms <= after_ms


def _is_ca(cert: x509.Certificate) -> bool:
    """Whether ``cert`` may issue further certificates: basicConstraints
    marks it a CA, keyUsage carries ``keyCertSign`` when present, and no
    critical extension outside :data:`_RECOGNIZED_CRITICAL_EXTENSIONS` is
    present (RFC 5280 4.2). Called only on a certificate whose extension
    block already read cleanly (checked once, at load time, alongside its
    structural decode: see ``jws._decode_chain`` and
    ``receipt._decode_embedded``), so nothing here needs to fail closed on
    an unreadable extension block itself."""
    for ext in cert.extensions:
        if ext.critical and ext.oid not in _RECOGNIZED_CRITICAL_EXTENSIONS:
            return False
    try:
        if not cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            return False
    except x509.ExtensionNotFound:
        return False
    try:
        key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
        if not key_usage.key_cert_sign:
            return False
    except x509.ExtensionNotFound:
        pass
    return True


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate, *, strict: bool = False) -> bool:
    """Whether ``issuer``'s key verifies ``cert``'s signature. Only
    ``issuer``'s key is ever decoded or used here (never ``cert``'s),
    which is what makes the walks below top-down: a certificate is tried as
    an issuer only once it is itself vouched for.

    ``strict``: when ``issuer`` is the certificate this call is actually
    settling on (not merely one candidate among several being explored), a
    key ``cryptography`` cannot build at all (an EC curve this build does
    not implement) is a defect of ``issuer`` itself and is raised as
    ``INVALID_CERTIFICATE`` rather than silently read as "not the issuer".
    """
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (TypeError, InvalidSignature):
        return False
    except UnsupportedAlgorithm as e:
        if strict:
            raise VerificationError(
                Reason.INVALID_CERTIFICATE, "certificate key does not decode"
            ) from e
        return False
    except ValueError as e:
        if "Unsupported signature algorithm" not in str(e):
            return False
    # cryptography's helper refuses SHA-1 signature algorithms, but genuine
    # Apple legacy receipt chains are SHA-1 end-to-end; verify manually,
    # matching the Java (PKIX), Node and Swift implementations. No other
    # algorithm restriction is applied (Q14, 2026-09-27): whatever
    # ``cryptography`` can verify for an RSA issuer is accepted.
    if cert.issuer != issuer.subject:
        return False
    try:
        public_key = issuer.public_key()
    except UnsupportedAlgorithm as e:
        if strict:
            raise VerificationError(
                Reason.INVALID_CERTIFICATE, "certificate key does not decode"
            ) from e
        return False
    if not isinstance(public_key, rsa.RSAPublicKey):
        return False
    signature_hash = cert.signature_hash_algorithm
    if signature_hash is None:
        return False
    try:
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            signature_hash,
        )
        return True
    except (InvalidSignature, TypeError, ValueError, UnsupportedAlgorithm):
        return False


def _require_chain_reason(condition: bool, message: str) -> None:
    if not condition:
        raise VerificationError(Reason.UNTRUSTED_CHAIN, message)


def authenticate_pair_top_down(
    leaf: x509.Certificate,
    intermediate: x509.Certificate,
    anchors: "Sequence[x509.Certificate]",
) -> None:
    """The fixed JWS path leaf -> intermediate -> (pinned anchor), walked
    top-down: the intermediate's signature is checked against the anchors
    first, and only once that has verified is the intermediate's key used
    to check the leaf's signature. Raises ``UNTRUSTED_CHAIN`` or
    ``INVALID_CERTIFICATE``; does not check validity (see the caller for
    the design's check order).
    """
    _require_chain_reason(
        any(_issued_by(intermediate, anchor) for anchor in anchors),
        "intermediate certificate is not signed by a pinned Apple root",
    )
    _require_chain_reason(_is_ca(intermediate), "intermediate is not a valid issuing CA")
    _require_chain_reason(
        _issued_by(leaf, intermediate, strict=True),
        "leaf certificate is not signed by the intermediate",
    )


def build_path_top_down(
    target: x509.Certificate,
    embedded: "Sequence[x509.Certificate]",
    anchors: "Sequence[x509.Certificate]",
) -> "list[x509.Certificate]":
    """The path from ``target`` (not itself required to be in ``embedded``)
    up to, but excluding, a pinned anchor: ``[target, intermediate, ...]``.

    Walked top-down in two passes, mirroring the Java port's
    ``authenticatedTopDown``: first every embedded certificate that a
    pinned root vouches for AND may itself issue further certificates
    (basicConstraints/keyUsage) is found: trying only certificates already
    vouched for as an issuer, so a stranger's key, oversized or not, is
    never decoded to test whether it issued anything. ``target``'s own path
    is then read off that result. Raises ``UNTRUSTED_CHAIN`` when no such
    path exists or it is longer than :data:`MAX_PATH_LENGTH`, or
    ``INVALID_CERTIFICATE`` when the certificate actually chosen as
    ``target``'s issuer has a key this build cannot decode.
    """
    for anchor in anchors:
        if _issued_by(target, anchor):
            return [target]

    accepted_by: dict[int, int | None] = {}
    pending = list(enumerate(embedded))
    current_issuers: list[tuple[int | None, x509.Certificate]] = [(None, a) for a in anchors]
    for _round in range(MAX_PATH_LENGTH):
        if not pending:
            break
        accepted_this_round: list[tuple[int, x509.Certificate]] = []
        for idx, candidate in pending:
            # Only a genuine issuing CA can extend the chain further; a
            # candidate that is merely vouched for but not entitled to
            # issue (an end-entity certificate in the intermediate's
            # position, say) is never accepted here.
            if not _is_ca(candidate):
                continue
            for parent_idx, issuer in current_issuers:
                if _issued_by(candidate, issuer):
                    accepted_by[idx] = parent_idx
                    accepted_this_round.append((idx, candidate))
                    break
        if not accepted_this_round:
            break
        accepted_indices = {idx for idx, _ in accepted_this_round}
        pending = [(idx, c) for idx, c in pending if idx not in accepted_indices]
        current_issuers = [(idx, c) for idx, c in accepted_this_round]

    for idx, cert in enumerate(embedded):
        if idx not in accepted_by:
            continue
        if not _issued_by(target, cert, strict=True):
            continue
        path = [target]
        current: int | None = idx
        while current is not None:
            path.append(embedded[current])
            current = accepted_by[current]
        _require_chain_reason(len(path) <= MAX_PATH_LENGTH, "chain exceeds maximum length")
        return path

    raise VerificationError(Reason.UNTRUSTED_CHAIN, "chain does not reach a pinned root")
