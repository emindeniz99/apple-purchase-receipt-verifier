#!/usr/bin/env python3
"""Evidence only (2026-09-29): the shared cases proposed for the port-only
tests that Phase 7 deleted with the hand-written verifiers
(docs/rust-core/TEST-INVENTORY.md, the rows marked "to add"), and what
aprv.wasm answers for each.

    python3 probe.py [OUT_DIR]

It mints every proposed input from generated material, runs it through the
Python package (python/, which must hold the aprv.wasm under test, see its
README) and prints one JSON line per proposal: the case id, the inventory
row it pins, the recipe, and the module's answer. With OUT_DIR it also
writes each input there (<fixture>.der, .b64, .jws or .json) so a later
change can register them in fixtures/cases.json. It never touches
fixtures/ or cases.json.

Needs Python 3.10+ with `cryptography` (41 or later) and `wasmtime`.
ECDSA signatures are randomised, so the minted bytes differ on every run;
the answers do not.

Material:
- the shared generated receipt (fixtures/generated-0.7/receipt.der, under
  receipt-root) respliced, its SignerInfo kept byte for byte;
- the generated transaction (fixtures/generated/transaction.jws, under
  jws-root) with its segments changed;
- receipts and JWSs signed by a P-256 PKI minted here (fixed private
  scalars, valid 2024-01-01 to 2050-01-01 unless a row says otherwise),
  with the core review's helpers (../2026-09-29-core-review-fixes/).
"""

import base64
import datetime
import hashlib
import importlib.util
import json
import os
import sys
import time
import zoneinfo

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, '..', '..', '..'))
OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else None

# The core review's DER helpers and minted PKI. Its module reads argv[1] as
# the repository, so it is loaded with an argv of its own.
_argv, sys.argv = sys.argv, [sys.argv[0]]
_spec = importlib.util.spec_from_file_location(
    'core_review', os.path.join(HERE, '..', '2026-09-29-core-review-fixes', 'gen_fixtures.py'))
cr = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cr)
sys.argv = _argv

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

sys.path.insert(0, os.path.join(REPO, 'python'))
from apple_purchase_receipt_verifier import Config, Environment, Verifier  # noqa: E402

enc, seq, set_of, integer, oid = cr.enc, cr.seq, cr.set_of, cr.integer, cr.oid
children, tlv = cr.children, cr.tlv

FIX = os.path.join(REPO, 'fixtures')
CLOCK_MS = 1735689600000  # 2025-01-01T00:00:00Z
SIGNED_MS = 1722945600000  # 2024-08-06T12:00:00Z, the fixtures' signing instant
OID_EC_PUBLIC_KEY = '1.2.840.10045.2.1'
OID_P256 = '1.2.840.10045.3.1.7'
OID_ECDSA_SHA384 = '1.2.840.10045.4.3.3'
OID_RSA = '1.2.840.113549.1.1.1'
OID_MD5 = '1.2.840.113549.2.5'
OID_CONTENT_TYPE = '1.2.840.113549.1.9.3'
OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4'
OID_SIGNING_TIME = '1.2.840.113549.1.9.5'
P256_ORDER = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
JUNK = b'\x30\x03\x02\x01\x00'  # a SEQUENCE that is no certificate


def fixture(path):
    with open(os.path.join(FIX, path), 'rb') as handle:
        return handle.read()


def b64(octets):
    return base64.b64encode(octets).decode()


def b64url(octets):
    return base64.urlsafe_b64encode(octets).rstrip(b'=').decode()


# --- certificates, written by hand so that any field can be hostile -------

def name(common_name, tag=0x0c):
    return seq(set_of(seq(oid('2.5.4.3'), enc(tag, common_name.encode()))))


def utc(moment):
    """A certificate time as RFC 5280 writes it: UTCTime through 2049,
    GeneralizedTime from 2050."""
    if moment.year >= 2050:
        return enc(0x18, moment.strftime('%Y%m%d%H%M%SZ').encode())
    return enc(0x17, moment.strftime('%y%m%d%H%M%SZ').encode())


def at(*parts):
    return datetime.datetime(*parts, tzinfo=datetime.timezone.utc)


VALID = (at(2024, 1, 1), at(2050, 1, 1))


def spki(key):
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def extension(dotted, value, critical=False):
    parts = [oid(dotted)]
    if critical:
        parts.append(b'\x01\x01\xff')
    return seq(*parts, enc(0x04, value))


def certificate(subject, key, issuer, issuer_key, serial, ca=None, marker=None, validity=VALID,
                validity_der=None, issuer_der=None, subject_der=None, spki_der=None,
                outer_algorithm=cr.OID_ECDSA_SHA256):
    """A v3 certificate signed by `issuer_key` (ECDSA P-256, SHA-256).
    `ca` True or False writes basicConstraints with that cA; None writes
    none. The *_der arguments replace a field with raw bytes."""
    extensions = []
    if ca is not None:
        extensions.append(extension('2.5.29.19', seq(b'\x01\x01\xff') if ca else seq(), critical=True))
    if marker:
        extensions.append(extension(marker, b'\x05\x00'))
    algorithm = seq(oid(cr.OID_ECDSA_SHA256))
    tbs = seq(enc(0xa0, integer(2)), integer(serial), algorithm,
              issuer_der or name(issuer),
              validity_der or seq(utc(validity[0]), utc(validity[1])),
              subject_der or name(subject),
              spki_der or spki(key),
              *([enc(0xa3, seq(*extensions))] if extensions else []))
    signature = issuer_key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    return seq(tbs, seq(oid(outer_algorithm)), enc(0x03, b'\x00' + signature))


def key(scalar):
    return ec.derive_private_key(scalar, ec.SECP256R1())


ROOT_KEY, WWDR_KEY, SIGNER_KEY = key(0x7101), key(0x7102), key(0x7103)
ROOT = certificate('P7 Test Root', ROOT_KEY, 'P7 Test Root', ROOT_KEY, 1, ca=True)
WWDR = certificate('P7 Test WWDR', WWDR_KEY, 'P7 Test Root', ROOT_KEY, 2, ca=True, marker=cr.WWDR_MARKER)
SIGNER = certificate('P7 Test Signer', SIGNER_KEY, 'P7 Test WWDR', WWDR_KEY, 3, marker=cr.SIGNER_MARKER)
JWS_LEAF = certificate('P7 Test JWS Leaf', SIGNER_KEY, 'P7 Test WWDR', WWDR_KEY, 4, marker=cr.SIGNER_MARKER)
FOREIGN_KEY = key(0x7201)
FOREIGN_ROOT = certificate('P7 Foreign Root', FOREIGN_KEY, 'P7 Foreign Root', FOREIGN_KEY, 1, ca=True)


# --- receipts --------------------------------------------------------------

def attribute(type_tlv, value_tlv, *more):
    return seq(type_tlv, integer(1), value_tlv, *more)


def payload(*extra, bundle=None, created=cr.CREATION_DATE):
    """A payload SET: bundle id, creation date, then `extra` attributes."""
    parts = [attribute(integer(2), bundle if bundle is not None else enc(0x04, enc(0x0c, b'com.example.app')))]
    if created is not None:
        parts.append(attribute(integer(12), enc(0x04, enc(0x16, created))))
    return set_of(*parts, *extra)


def receipt(content, certs=(SIGNER, WWDR), signer_key=SIGNER_KEY, issuer='P7 Test WWDR', serial=3,
            signed_attrs=None, digest_algorithm=None, signature_tag=0x04, signer_infos=None):
    """A receipt whose eContent octets `content` are signed by `signer_key`.
    `signed_attrs` is a list of Attribute TLVs, signed as a DER SET."""
    if signed_attrs is None:
        signed = content
        attrs = b''
    else:
        signed = set_of(*signed_attrs)
        attrs = enc(0xa0, b''.join(signed_attrs))
    signature = signer_key.sign(signed, ec.ECDSA(hashes.SHA256()))
    sid = seq(name(issuer), integer(serial))
    info = seq(integer(1), sid, digest_algorithm or seq(oid(cr.OID_SHA256)), *([attrs] if attrs else []),
               seq(oid(cr.OID_ECDSA_SHA256)), enc(signature_tag, signature))
    encap = seq(oid(cr.OID_DATA), enc(0xa0, enc(0x04, content)))
    body = seq(integer(1), set_of(seq(oid(cr.OID_SHA256))), encap, enc(0xa0, b''.join(certs)),
               signer_infos if signer_infos is not None else set_of(info))
    return seq(oid(cr.OID_SIGNED_DATA), enc(0xa0, body))


def standard_attrs(content, digest=None, when=b'240806120000Z', extra=()):
    digest_value = digest if digest is not None else set_of(enc(0x04, hashlib.sha256(content).digest()))
    return [seq(oid(OID_CONTENT_TYPE), set_of(oid(cr.OID_DATA))),
            seq(oid(OID_SIGNING_TIME), set_of(enc(0x17, when))),
            seq(oid(OID_MESSAGE_DIGEST), digest_value),
            *extra]


SHARED = cr.SHARED
SHARED_CERTS = [c[2] for c in children(cr.CERTIFICATES[1])]  # signer (serial 15), WWDR, root copy


def shared_with(certs=None, signer_infos=None, signer_info=None):
    """The shared receipt with its bag or SignerInfos replaced."""
    parts = [cr.VERSION, cr.DIGEST_ALGORITHMS, cr.ENCAP[2],
             enc(0xa0, b''.join(SHARED_CERTS if certs is None else certs)),
             signer_infos if signer_infos is not None else set_of(signer_info or cr.SIGNER_INFO[2])]
    return seq(oid(cr.OID_SIGNED_DATA), enc(0xa0, seq(*parts)))


def flip(octets, offset):
    changed = bytearray(octets)
    changed[offset] ^= 0x01
    return bytes(changed)


def signature_offset(cert):
    """The offset of the last byte of a certificate's signature value."""
    return len(cert) - 1


def signer_info_with(index, replacement):
    fields = [c[2] for c in children(cr.SIGNER_INFO[1])]
    fields[index] = replacement
    return seq(*fields)


# --- JWSs ------------------------------------------------------------------

def jws(payload_text, chain=(JWS_LEAF, WWDR, ROOT), signer_key=SIGNER_KEY, alg='ES256', signature=None):
    header = json.dumps({'alg': alg, 'x5c': [b64(c) for c in chain]}, separators=(',', ':')).encode()
    signing_input = f'{b64url(header)}.{b64url(payload_text)}'.encode()
    if signature is None:
        r, s = decode_dss_signature(signer_key.sign(signing_input, ec.ECDSA(hashes.SHA256())))
        signature = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
    return f'{signing_input.decode()}.{b64url(signature)}'


def claims(signed_date_text):
    return ('{"bundleId":"com.example.app","productId":"com.example.coins","signedDate":'
            + signed_date_text + '}').encode()


TRANSACTION = fixture('generated/transaction.jws').decode().strip()


# --- running ---------------------------------------------------------------

_verifiers = {}


def verifier(roots, clock):
    k = (tuple(roots) if roots is not None else None, clock)
    if k not in _verifiers:
        _verifiers[k] = Verifier(Config.create(roots=roots, clock=lambda: clock))
    return _verifiers[k]


def answer(operation, data, roots, clock=CLOCK_MS, pointers=()):
    v = verifier(roots, clock)
    started = time.perf_counter()
    if operation == 'verifyReceipt':
        result = v.verify_receipt(data)
        document = json.loads(result.payload.to_json()) if result.verified else None
    elif operation == 'verifySignedData':
        result = v.verify_signed_data(data)
        document = json.loads(result.payload.json) if result.verified else None
    else:
        body = json.loads(v.verify_receipt_endpoint(Environment.SANDBOX, data))
        elapsed = round((time.perf_counter() - started) * 1000, 1)
        return {'status': body['status'], 'fields': {p: pointer(body, p) for p in pointers}, 'ms': elapsed}
    elapsed = round((time.perf_counter() - started) * 1000, 1)
    if not result.verified:
        return {'status': 'error', 'reason': result.failure.reason.name, 'ms': elapsed}
    return {'status': 'ok', 'fields': {p: pointer(document, p) for p in pointers}, 'ms': elapsed}


def pointer(document, path):
    value = document
    for part in path.lstrip('/').split('/'):
        if isinstance(value, list):
            value = value[int(part)] if int(part) < len(value) else '<absent>'
        elif isinstance(value, dict):
            value = value.get(part, '<absent>')
        else:
            return '<absent>'
    return value


RESULTS = []


def propose(case_id, rows, recipe, operation, data, roots, clock=CLOCK_MS, pointers=(), write=None):
    """One proposed case: run it and record the module's answer."""
    got = answer(operation, data, roots, clock, pointers)
    entry = {'id': case_id, 'rows': rows, 'recipe': recipe, 'operation': operation,
             'bytes': len(data), 'clock': clock, 'answer': got}
    RESULTS.append(entry)
    print(json.dumps(entry), flush=True)
    if OUT_DIR and write is not None:
        name_, octets = write
        with open(os.path.join(OUT_DIR, name_), 'wb') as handle:
            handle.write(octets)


def receipt_case(case_id, rows, recipe, der, roots, clock=CLOCK_MS, pointers=()):
    propose(case_id, rows, recipe, 'verifyReceipt', b64(der), roots, clock, pointers,
            write=(case_id.replace('/', '--') + '.der', der))


def jws_case(case_id, rows, recipe, text, roots, clock=CLOCK_MS, pointers=()):
    propose(case_id, rows, recipe, 'verifySignedData', text, roots, clock, pointers,
            write=(case_id.replace('/', '--') + '.jws', text.encode()))


def endpoint_case(case_id, rows, recipe, body, roots, clock=CLOCK_MS, pointers=()):
    propose(case_id, rows, recipe, 'verifyReceiptEndpoint', body, roots, clock, pointers,
            write=(case_id.replace('/', '--') + '.json', body.encode()))


def main():
    if OUT_DIR:
        os.makedirs(OUT_DIR, exist_ok=True)
    shared_root = [fixture('generated-0.7/receipt-root.der')]
    jws_root = [fixture('generated/jws-root.der')]
    mine = [ROOT]
    ok_bundle = ('/bundle_id',)

    # Positive controls: the minted PKI verifies, with and without signed
    # attributes, so every refusal below is the row's fault and nothing else.
    body = payload()
    receipt_case('control/minted-receipt', 'control', 'minted PKI, no signed attributes', receipt(body), mine,
                 pointers=ok_bundle)
    receipt_case('control/minted-receipt-signed-attributes', 'control', 'minted PKI, valid signed attributes',
                 receipt(body, signed_attrs=standard_attrs(body)), mine, pointers=ok_bundle)
    jws_case('control/minted-jws', 'control', 'minted PKI, ES256', jws(claims(str(SIGNED_MS))), mine,
             pointers=('/signedDate',))
    receipt_case('control/shared-receipt', 'control', 'fixtures/generated-0.7/receipt.der, respliced as is',
                 shared_with(), shared_root, pointers=ok_bundle)

    # --- Go ---------------------------------------------------------------
    for where, index in (('first', 0), ('middle', 1), ('last', 3)):
        bag = list(SHARED_CERTS)
        bag.insert(index, JUNK)
        receipt_case(f'receipt/reject-an-unparseable-stranger-{where}',
                     'Go certbag_test UnparseableStrangerCertificateIsTolerated...AtEveryPosition',
                     f'shared receipt, `30 03 02 01 00` inserted {where} in the certificates bag',
                     shared_with(certs=bag), shared_root, pointers=ok_bundle)

    def noncanonical(cert):
        """The certificate's ECDSA signature with r re-encoded with a leading
        zero octet: the same value, not DER."""
        tbs, algorithm, bits = children(tlv(cert, 0)[1])
        sig = bits[1][1:]
        r, s = children(tlv(sig, 0)[1])
        wide_r = enc(0x02, b'\x00' + r[1]) if r[1][0] < 0x80 else enc(0x02, b'\x00\x00' + r[1][1:])
        return seq(tbs[2], algorithm[2], enc(0x03, b'\x00' + seq(wide_r, s[2])))

    receipt_case('receipt/reject-noncanonical-signature-on-leaf',
                 'Go certbag_test NonCanonicalCertificateSignatureIsFatalAtEveryPosition',
                 "minted receipt; the signer certificate's ECDSA r carries a redundant leading zero",
                 receipt(body, certs=(noncanonical(SIGNER), WWDR)), mine)
    receipt_case('receipt/reject-noncanonical-signature-on-intermediate',
                 'Go certbag_test NonCanonicalCertificateSignatureIsFatalAtEveryPosition',
                 "minted receipt; the intermediate's ECDSA r carries a redundant leading zero",
                 receipt(body, certs=(SIGNER, noncanonical(WWDR))), mine)

    receipt_case('receipt/verify-with-a-corrupted-redundant-root-copy',
                 'Go certbag_test CorruptedCertificateInGenuineReceipt',
                 "shared receipt, the last byte of the bag's copy of the root flipped",
                 shared_with(certs=SHARED_CERTS[:2] + [flip(SHARED_CERTS[2], signature_offset(SHARED_CERTS[2]))]),
                 shared_root, pointers=ok_bundle)
    receipt_case('receipt/reject-a-corrupted-signer-certificate',
                 'Go certbag_test CorruptedCertificateInGenuineReceipt',
                 "shared receipt, the last byte of the signer certificate's signature flipped",
                 shared_with(certs=[flip(SHARED_CERTS[0], signature_offset(SHARED_CERTS[0]))] + SHARED_CERTS[1:]),
                 shared_root)
    receipt_case('receipt/reject-sixty-four-junk-certificates-as-malformed',
                 'Go certbag_test CertificateCountIsStillCheckedBeforeDecoding',
                 'shared receipt, its three certificates and 64 junk entries',
                 shared_with(certs=SHARED_CERTS + [JUNK] * 64), shared_root)

    # The signer is named (issuer and serial read) but its key is unreadable.
    unreadable_spki = seq(seq(oid(OID_EC_PUBLIC_KEY), oid(OID_P256)), enc(0x03, b'\x00\x04\x01\x02'))
    unreadable_signer = certificate('P7 Test Signer', SIGNER_KEY, 'P7 Test WWDR', WWDR_KEY, 3,
                                    marker=cr.SIGNER_MARKER, spki_der=unreadable_spki)
    receipt_case('receipt/reject-a-signer-that-is-named-but-unreadable',
                 'Go certbag_test AMalformedSignerIsACertificateDefect',
                 "minted receipt; the signer certificate's public key is a 3-byte EC point",
                 receipt(body, certs=(unreadable_signer, WWDR)), mine)

    receipt_case('receipt/verify-with-two-anchors-only-one-used', 'Go chain_test AnchorsArePinnedInBothDirections',
                 'shared receipt; trusted roots receipt-root and jws-root', shared_with(),
                 shared_root + jws_root, pointers=ok_bundle)

    expired_root = certificate('P7 Test Root', ROOT_KEY, 'P7 Test Root', ROOT_KEY, 1, ca=True,
                               validity=(at(2023, 1, 1), at(2024, 6, 1)))
    receipt_case('receipt/accept-an-expired-trust-anchor',
                 'Go chain_test ExpiredAnchorStillAnchors; Ruby receipt_test test_an_anchor_is_not_rejected_for_being_expired',
                 'minted receipt (created 2024-08-06) under a root valid 2023-01-01 to 2024-06-01; the WWDR and '
                 'signer valid 2024-2050', receipt(body), [expired_root], pointers=ok_bundle)

    not_ca = certificate('P7 Test WWDR', WWDR_KEY, 'P7 Test Root', ROOT_KEY, 2, ca=False, marker=cr.WWDR_MARKER)
    receipt_case('receipt/reject-an-intermediate-that-is-not-a-ca', 'Go chain_test IntermediateMustBeAUsableCA',
                 'minted receipt; the WWDR has basicConstraints cA FALSE', receipt(body, certs=(SIGNER, not_ca)),
                 mine)
    jws_case('signed-data/reject-an-intermediate-that-is-not-a-ca',
             'Ruby jws_test test_rejects_an_intermediate_that_is_not_a_ca',
             'minted JWS; the WWDR has basicConstraints cA FALSE',
             jws(claims(str(SIGNED_MS)), chain=(JWS_LEAF, not_ca, ROOT)), mine)

    printable_issuer = certificate('P7 Test Signer', SIGNER_KEY, 'P7 Test WWDR', WWDR_KEY, 3,
                                   marker=cr.SIGNER_MARKER, issuer_der=name('P7 Test WWDR', tag=0x13))
    receipt_case('receipt/verify-a-signer-whose-issuer-name-is-reencoded',
                 'Go chain_test IssuerNameMustMatchByBytes',
                 "minted receipt; the signer's issuer name is the WWDR's subject text as a PrintableString "
                 "(the WWDR's subject is a UTF8String); the SignerInfo names the issuer as UTF8String",
                 receipt(body, certs=(printable_issuer, WWDR)), mine)

    relabelled = fixture('generated-0.7/review-receipt-relabelled-signature-algorithm.der') \
        if os.path.exists(os.path.join(FIX, 'generated-0.7/review-receipt-relabelled-signature-algorithm.der')) else None
    if relabelled is not None:
        receipt_case('receipt/relabelled-signature-algorithm-still-verifies',
                     'Go endpoint_test SignatureAlgorithmIdentifierIsNotConsulted',
                     'the fixture of receipt/relabelled-signature-algorithm-does-not-crash (today oneOf ok|INVALID_SIGNATURE)',
                     relabelled, [fixture('generated-0.7/review-receipt-root.der')], pointers=ok_bundle)

    # Apple's date triple, and request_date_pst, either side of each US DST
    # transition and in 2007 and 2040 (the tzdata vectors of the old tests).
    pacific = zoneinfo.ZoneInfo('America/Los_Angeles')
    for label, instant in (
            ('2026-spring-before', at(2026, 3, 8, 9, 59, 59)), ('2026-spring-after', at(2026, 3, 8, 10, 0, 0)),
            ('2026-autumn-before', at(2026, 11, 1, 8, 59, 59)), ('2026-autumn-after', at(2026, 11, 1, 9, 0, 0)),
            ('2007-spring-after', at(2007, 3, 11, 10, 0, 0)), ('2040-summer', at(2040, 7, 1, 12, 0, 0))):
        # The creation date is also the chain's validity instant, so it
        # follows the clock only inside the minted PKI's window; 2007 pins
        # the clock alone (request_date).
        created = instant.strftime('%Y-%m-%dT%H:%M:%SZ').encode() if instant.year >= 2024 else cr.CREATION_DATE
        der = receipt(payload(created=created))
        clock = int(instant.timestamp() * 1000)
        want = instant.astimezone(pacific).strftime('%Y-%m-%d %H:%M:%S') + ' America/Los_Angeles'
        endpoint_case(f'endpoint/pacific-time-{label}',
                      'Go endpoint_test AppleDateTripleShape; Ruby pacific_time_test (5 rows); Swift and PHP '
                      'Pacific-time rows',
                      f'minted receipt created {created.decode()}, clock pinned at {instant:%Y-%m-%dT%H:%M:%SZ}; '
                      f'zoneinfo renders the clock {want}', json.dumps({'receipt-data': b64(der)}), mine, clock,
                      pointers=('/receipt/request_date', '/receipt/request_date_ms', '/receipt/request_date_pst',
                                '/receipt/receipt_creation_date', '/receipt/receipt_creation_date_ms',
                                '/receipt/receipt_creation_date_pst'))

    edges = os.path.join(FIX, 'generated-0.7/review-receipt-integer-edges.der')
    if os.path.exists(edges):
        endpoint_case('endpoint/ids-at-the-64-bit-edge', 'Go endpoint_test EndpointIdsExactDigits',
                      'the fixture of receipt/integers-at-the-64-bit-edge through the endpoint',
                      json.dumps({'receipt-data': b64(fixture('generated-0.7/review-receipt-integer-edges.der'))}),
                      [fixture('generated-0.7/review-receipt-root.der')],
                      pointers=('/receipt/app_item_id', '/receipt/download_id', '/receipt/version_external_identifier'))

    stranger_root = certificate('P7 Stranger Root', FOREIGN_KEY, 'P7 Stranger Root', FOREIGN_KEY, 9, ca=True)
    jws_case('transaction/accept-a-third-x5c-entry-from-a-stranger-root',
             'Go jws_test ThirdX5CEntryIsUntrustedButMustParse; Ruby jws_test test_x5c_third_element_is_ignored',
             'minted JWS whose x5c is [leaf, WWDR, a self-signed root nobody trusts] instead of [leaf, WWDR, root]',
             jws(claims(str(SIGNED_MS)), chain=(JWS_LEAF, WWDR, stranger_root)), mine, pointers=('/signedDate',))
    jws_case('transaction/accept-signed-date-exponent-spelling', 'Go jws_test EverySpellingOfASignedDateIsRead',
             'minted JWS, signedDate written 1.7229456E12', jws(claims('1.7229456E12')), mine,
             pointers=('/signedDate',))
    for label, text in (('minus-1e300', '-1e300'), ('30-digits', '1' + '0' * 29)):
        jws_case(f'transaction/signed-date-{label}-falls-back-to-the-clock',
                 'Go jws_test UnrepresentableSignedDateFallsBackToTheClock',
                 f'minted JWS, signedDate {text}', jws(claims(text)), mine, pointers=('/signedDate',))

    receipt_case('receipt/empty-date-string-means-absent',
                 'Go receipt_test EmptyDateStringMeansAbsent; PHP "an empty date attribute is absent"',
                 'minted receipt whose creation-date attribute (12) is an empty IA5String',
                 receipt(payload(created=b'')), mine,
                 pointers=('/bundle_id', '/receipt_creation_date_ms', '/unknown_attributes'))

    foreign_wwdr = certificate('P7 Foreign WWDR', WWDR_KEY, 'P7 Foreign Root', FOREIGN_KEY, 2, ca=True,
                               marker=cr.WWDR_MARKER)
    unmarked = certificate('P7 Test Signer', SIGNER_KEY, 'P7 Foreign WWDR', WWDR_KEY, 3)
    receipt_case('receipt/reject-foreign-chain-with-an-unmarked-signer',
                 'Go receipt_test ReceiptChainIsCheckedBeforeTheMarkerOID; Ruby receipt_test '
                 'test_chain_is_reported_before_the_signer_marker_oid',
                 'minted receipt under a foreign root, the signer without the marker OID; trusted: the P7 root',
                 receipt(body, certs=(unmarked, foreign_wwdr), issuer='P7 Foreign WWDR'), mine)

    receipt_case('receipt/bundle-id-that-is-not-asn1-is-kept-raw', 'Go receipt_test BundleIDValueThatIsNotASN1IsKeptRaw',
                 'minted receipt whose bundle id attribute (2) value is the octets ff fe 00 41',
                 receipt(payload(bundle=enc(0x04, b'\xff\xfe\x00\x41'))), mine,
                 pointers=('/bundle_id', '/bundle_id_bytes'))

    start = at(2024, 8, 6, 12, 0, 0)
    for label, validity, created in (
            ('verify-at-not-before-instant', (start, at(2050, 1, 1)), b'2024-08-06T12:00:00Z'),
            ('verify-at-not-after-instant', (at(2024, 1, 1), start), b'2024-08-06T12:00:00Z'),
            ('reject-one-second-after-not-after', (at(2024, 1, 1), start), b'2024-08-06T12:00:01Z')):
        signer = certificate('P7 Test Signer', SIGNER_KEY, 'P7 Test WWDR', WWDR_KEY, 3, marker=cr.SIGNER_MARKER,
                             validity=validity)
        receipt_case(f'receipt/{label}', 'Go internal/chain ValidAtIsInclusiveAtBothEnds',
                     f'minted receipt created {created.decode()}, the signer valid {validity[0]:%Y-%m-%dT%H:%M:%SZ} '
                     f'to {validity[1]:%Y-%m-%dT%H:%M:%SZ}', receipt(payload(created=created), certs=(signer, WWDR)),
                     mine, pointers=ok_bundle)

    modulus = (1 << 16383) | int.from_bytes(hashlib.shake_256(b'p7 modulus').digest(2046), 'big') | 1
    rsa_spki = seq(seq(oid(OID_RSA), b'\x05\x00'),
                   enc(0x03, b'\x00' + seq(integer(modulus), integer(65537))))
    big = certificate('P7 Big Stranger', FOREIGN_KEY, 'P7 Big Stranger', FOREIGN_KEY, 77, spki_der=rsa_spki)
    receipt_case('receipt/verify-beside-a-stranger-with-a-16384-bit-modulus', 'Go internal/chain RSAModulusCap',
                 'shared receipt with a self-issued stranger carrying a 16,384-bit RSA modulus added to the bag',
                 shared_with(certs=SHARED_CERTS + [big]), shared_root, pointers=ok_bundle)

    # --- Ruby -------------------------------------------------------------
    receipt_case('receipt/reject-a-thousand-junk-certificates', 'Ruby certificate_flood_test (thousand certificates)',
                 'shared receipt, its three certificates and 1,000 junk entries',
                 shared_with(certs=SHARED_CERTS + [JUNK] * 1000), shared_root)
    receipt_case('receipt/reject-eleven-junk-certificates-with-the-signer-absent',
                 'Ruby certificate_flood_test test_the_bound_is_reported_before_the_signer_lookup; Python '
                 'reject-eleven-non-certificate-embedded-entries-as-malformed; Java -wasm '
                 'countsEmbeddedCertificatesBeforeDecodingAnyOfThem; Swift chain-walk bounds',
                 'shared receipt whose bag is 11 junk entries and nothing else', shared_with(certs=[JUNK] * 11),
                 shared_root)
    raw = {
        'reject-an-indefinite-length-nesting-bomb': (b'\x30\x80' * 40000, 'Ruby hostile_input_test '
                                                     'test_indefinite_length_nesting_bomb; performance_test',
                                                     '40,000 nested `30 80` opens, no end-of-contents (80 KB)'),
        'reject-a-definite-length-nesting-bomb': (cr.nested(10000), 'Ruby hostile_input_test '
                                                  'test_definite_length_nesting_bomb; performance_test',
                                                  '10,000 nested definite-length SEQUENCEs'),
        'reject-a-length-claiming-two-gigabytes': (b'\x30\x84\x7f\xff\xff\xff' + bytes(34), 'Ruby hostile_input_test '
                                                   'test_a_length_claiming_two_gigabytes_on_a_forty_byte_input',
                                                   '`30 84 7f ff ff ff` and 34 zero octets'),
        'reject-an-unterminated-indefinite-length-container': (b'\x30\x80\x30\x80\x02\x01\x00',
                                                               'Ruby hostile_input_test '
                                                               'test_an_unterminated_indefinite_length_container',
                                                               '`30 80 30 80 02 01 00`'),
        'reject-an-end-of-contents-with-no-open-container': (b'\x30\x02\x00\x00', 'Ruby hostile_input_test '
                                                             'test_an_end_of_contents_with_no_open_container',
                                                             '`30 02 00 00`'),
        'reject-a-multi-byte-tag': (b'\x1f\x81\x00\x01\x00', 'Ruby hostile_input_test '
                                    'test_multi_byte_tags_are_refused_rather_than_interpreted', '`1f 81 00 01 00`'),
        'reject-a-length-field-wider-than-four-octets': (b'\x30\x85\x00\x00\x00\x00\x03\x02\x01\x00',
                                                         'Ruby hostile_input_test '
                                                         'test_length_fields_wider_than_four_octets_are_refused',
                                                         '`30 85 00 00 00 00 03 02 01 00`'),
        'reject-a-contentinfo-holding-only-the-oid': (seq(oid(cr.OID_SIGNED_DATA)), 'Swift "a ContentInfo holding only '
                                                      'the OID"', 'SEQUENCE { signedData OID }'),
    }
    for label, (der, rows, recipe) in raw.items():
        receipt_case(f'receipt/{label}', rows, recipe, der, shared_root)

    flat = payload(*[attribute(integer(10000 + i), enc(0x04, integer(1))) for i in range(5000)])
    receipt_case('receipt/a-huge-flat-attribute-set-is-bounded',
                 'Ruby hostile_input_test test_a_receipt_whose_payload_is_a_huge_flat_set_is_bounded',
                 'minted receipt with 5,000 extra valid attributes', receipt(flat), mine,
                 pointers=('/bundle_id',))
    chunked = payload(attribute(integer(9000), cr.rechunked(80, b'\x02\x01\x01')))
    receipt_case('receipt/unreadable-attribute-value-in-80-constructed-levels',
                 'Ruby hostile_input_test test_a_ber_chunked_attribute_value_is_bounded',
                 'minted receipt, an attribute value written as 80 nested constructed OCTET STRINGs',
                 receipt(chunked), mine, pointers=('/bundle_id', '/unknown_attributes/9000/0'))
    nulls = payload(attribute(integer(9000), enc(0x04, seq(*([b'\x05\x00'] * 49000)))))
    receipt_case('receipt/a-node-budget-flood-is-bounded', 'Ruby hostile_input_test '
                 'test_the_node_budget_ceiling_costs_a_bounded_amount (scaled to 49,000 NULLs, 98 KB)',
                 'minted receipt, an attribute value holding one SEQUENCE of 49,000 NULLs', receipt(nulls), mine,
                 pointers=('/bundle_id',))
    long_date = b'2024-08-06T12:00:00.' + b'0' * 90000 + b'Z'
    long_receipt = receipt(payload(created=long_date))
    receipt_case('receipt/a-date-with-90000-fractional-digits-is-bounded', 'Ruby hostile_input_test '
                 'test_a_date_with_a_million_fractional_digits_is_not_superlinear (scaled to 90,000 digits)',
                 'minted receipt whose creation date has 90,000 fractional-second digits', long_receipt, mine,
                 pointers=('/bundle_id', '/receipt_creation_date_ms'))
    endpoint_case('endpoint/a-date-with-90000-fractional-digits-is-bounded', 'Ruby hostile_input_test '
                  'test_the_endpoint_is_not_superlinear_on_a_long_fractional_second (scaled)',
                  'the receipt above through the endpoint', json.dumps({'receipt-data': b64(long_receipt)}), mine,
                  pointers=('/receipt/receipt_creation_date_ms',))

    header, claims_segment, signature = TRANSACTION.split('.')
    jws_case('transaction/reject-a-header-segment-outside-the-base64url-alphabet',
             'Ruby jws_test test_rejects_a_segment_outside_the_base64url_alphabet',
             "the generated transaction with its header's first character replaced by '+'",
             '+' + header[1:] + '.' + claims_segment + '.' + signature, jws_root)
    jws_case('transaction/reject-a-payload-segment-outside-the-base64url-alphabet',
             'Ruby jws_test test_rejects_a_segment_outside_the_base64url_alphabet',
             "the generated transaction with its payload's first character replaced by '/'",
             header + './' + claims_segment[1:] + '.' + signature, jws_root)
    jws_case('transaction/reject-a-header-that-is-base64url-but-not-json',
             'Ruby jws_test test_rejects_a_segment_that_is_base64url_but_not_json',
             'the generated transaction with its header replaced by base64url("not json")',
             b64url(b'not json') + '.' + claims_segment + '.' + signature, jws_root)
    order = P256_ORDER.to_bytes(32, 'big') + (1).to_bytes(32, 'big')
    jws_case('transaction/reject-a-signature-whose-r-is-the-group-order',
             'Ruby jws_test test_rejects_a_signature_whose_scalars_are_zero_or_out_of_range',
             'the generated transaction with its signature replaced by r = n (the P-256 order), s = 1',
             header + '.' + claims_segment + '.' + b64url(order), jws_root)
    jws_case('raw/reject-a-jws-with-two-segments', 'Ruby jws_test test_rejects_inputs_that_are_not_three_segments',
             'the generated transaction without its signature segment', header + '.' + claims_segment, jws_root)
    jws_case('raw/reject-a-jws-with-one-segment', 'Ruby jws_test test_rejects_inputs_that_are_not_three_segments',
             "the generated transaction's header segment alone", header, jws_root)

    receipt_case('receipt/accept-a-duplicated-genuine-signer-info',
                 'Ruby receipt_test test_a_duplicated_genuine_signer_info_still_verifies',
                 'shared receipt whose SignerInfos SET holds its SignerInfo twice',
                 shared_with(signer_infos=set_of(cr.SIGNER_INFO[2], cr.SIGNER_INFO[2])), shared_root,
                 pointers=ok_bundle)
    receipt_case('receipt/reject-a-signer-certificate-that-is-not-embedded',
                 'Ruby receipt_test test_rejects_a_signer_certificate_that_is_not_embedded; PHP "SignerInfo naming '
                 'a certificate that is not embedded"', 'shared receipt, the signer certificate removed from the bag',
                 shared_with(certs=SHARED_CERTS[1:]), shared_root)

    # --- Python -----------------------------------------------------------
    for label, attrs, rows in (
            ('reject-an-empty-message-digest-set', standard_attrs(body, digest=set_of()),
             'Python "signed attributes: empty message-digest set"'),
            ('reject-a-message-digest-that-is-not-an-octet-string',
             standard_attrs(body, digest=set_of(integer(1))), 'Python "message-digest not an OCTET STRING"'),
            ('verify-with-a-signing-time-in-month-13', standard_attrs(body, when=b'241301120000Z'),
             'Python "signing-time month 13"'),
            ('verify-with-an-unknown-signed-attribute-holding-invalid-utf8',
             standard_attrs(body, extra=(seq(oid('1.2.3.4'), set_of(enc(0x0c, b'\xff\xfe'))),)),
             'Python "unknown attribute with invalid UTF-8"')):
        receipt_case(f'receipt/{label}', rows, 'minted receipt with signed attributes; ' + label.replace('-', ' '),
                     receipt(body, signed_attrs=attrs), mine, pointers=ok_bundle)
    receipt_case('receipt/reject-a-digest-algorithm-that-is-not-an-oid', 'Python "SignerInfo: digest algorithm not an OID"',
                 "minted receipt; the SignerInfo's digestAlgorithm is SEQUENCE { INTEGER 1 }",
                 receipt(body, digest_algorithm=seq(integer(1))), mine)
    receipt_case('receipt/reject-a-signature-that-is-not-an-octet-string',
                 'Python "SignerInfo: signature not an OCTET STRING"',
                 "minted receipt; the SignerInfo's signature is a BIT STRING", receipt(body, signature_tag=0x03), mine)
    receipt_case('receipt/reject-a-negative-attribute-type', 'Python reject-negative-attribute-type',
                 'minted receipt with an attribute of type -1', receipt(payload(attribute(integer(-1),
                                                                                         enc(0x04, integer(1))))),
                 mine)
    for label, text in (('nan', 'NaN'), ('infinity', 'Infinity')):
        jws_case(f'transaction/reject-a-signed-date-of-{label}', 'Python "signed-data NaN and Infinity signed dates"',
                 f'minted JWS whose claims say "signedDate":{text} (not JSON)', jws(claims(text)), mine)

    # --- Swift ------------------------------------------------------------
    for label, value in (('int32-max-is-kept', 2 ** 31 - 1), ('above-int32-max-keeps-the-purchase-raw', 2 ** 31)):
        in_app = set_of(attribute(integer(1702), enc(0x04, enc(0x0c, b'com.example.coins'))),
                        attribute(integer(value), enc(0x04, integer(1))))
        receipt_case(f'receipt/in-app-attribute-type-{label}', 'Swift "in-app attribute type 2^31 and 2^31 - 1"',
                     f'minted receipt with one in-app purchase (17) holding an attribute of type {value}',
                     receipt(payload(attribute(integer(17), enc(0x04, in_app)))), mine,
                     pointers=('/in_app/0/product_id', f'/in_app/0/unknown_attributes/{value}/0',
                               '/unknown_attributes/17/0'))

    # --- PHP --------------------------------------------------------------
    rsa_leaf_spki = rsa_spki  # any RSA key: the JWS names ES256
    rsa_leaf = certificate('P7 RSA JWS Leaf', SIGNER_KEY, 'P7 Test WWDR', WWDR_KEY, 5, marker=cr.SIGNER_MARKER,
                           spki_der=rsa_leaf_spki)
    jws_case('signed-data/reject-an-rsa-leaf-under-es256', 'PHP "an RSA leaf in a JWS"',
             'minted JWS, alg ES256, whose leaf carries an RSA key', jws(claims(str(SIGNED_MS)), chain=(rsa_leaf, WWDR, ROOT)),
             mine)
    jws_case('transaction/reject-signature-of-128-bytes', 'PHP "ES256 signatures of 0, 63, 65 and 128 bytes"',
             'the generated transaction with a 128-byte signature (its own, twice)',
             header + '.' + claims_segment + '.' + b64url(base64.urlsafe_b64decode(signature + '==') * 2), jws_root)
    receipt_case('receipt/reject-an-unknown-digest-algorithm', 'PHP "unknown digest OID in a SignerInfo"',
                 "shared receipt, the SignerInfo's digestAlgorithm replaced by 1.2.3.4",
                 shared_with(signer_info=signer_info_with(2, seq(oid('1.2.3.4')))), shared_root)
    receipt_case('receipt/reject-an-md5-digest-algorithm', 'PHP "MD5 digest"',
                 "shared receipt, the SignerInfo's digestAlgorithm replaced by md5",
                 shared_with(signer_info=signer_info_with(2, seq(oid(OID_MD5), b'\x05\x00'))), shared_root)
    disagreeing = certificate('P7 Test Signer', SIGNER_KEY, 'P7 Test WWDR', WWDR_KEY, 3, marker=cr.SIGNER_MARKER,
                              outer_algorithm=OID_ECDSA_SHA384)
    receipt_case('receipt/reject-a-signer-whose-signature-algorithms-disagree',
                 'PHP "inner and outer signature algorithms disagree"',
                 "minted receipt; the signer certificate's outer signatureAlgorithm says ecdsa-with-SHA384, its TBS "
                 'says ecdsa-with-SHA256', receipt(body, certs=(disagreeing, WWDR)), mine)
    for label, validity_der, rows in (
            ('reject-a-signer-valid-from-month-13', seq(enc(0x17, b'241301000000Z'), utc(at(2050, 1, 1))),
             'PHP "a validity month 13"'),
            ('reject-a-signer-whose-utctime-50-means-1950', seq(utc(at(2024, 1, 1)), enc(0x17, b'500101000000Z')),
             'PHP "the UTCTime pivot"'),
            ('verify-a-signer-whose-utctime-49-means-2049', seq(utc(at(2024, 1, 1)), enc(0x17, b'491231235959Z')),
             'PHP "the UTCTime pivot"'),
            ('reject-a-signer-validity-of-the-wrong-tag', seq(enc(0x16, b'240101000000Z'), utc(at(2050, 1, 1))),
             'PHP "a validity of the wrong tag"')):
        signer = certificate('P7 Test Signer', SIGNER_KEY, 'P7 Test WWDR', WWDR_KEY, 3, marker=cr.SIGNER_MARKER,
                             validity_der=validity_der)
        receipt_case(f'receipt/{label}', rows, f'minted receipt; the signer validity is {validity_der.hex()}',
                     receipt(body, certs=(signer, WWDR)), mine, pointers=ok_bundle)

    print(json.dumps({'proposals': len(RESULTS)}), file=sys.stderr)


if __name__ == '__main__':
    main()
