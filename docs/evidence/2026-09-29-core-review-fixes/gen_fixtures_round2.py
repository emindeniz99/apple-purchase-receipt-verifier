#!/usr/bin/env python3
"""Evidence only (2026-09-29): the shared cases the second core review's
findings became, and their fixtures.

    python3 gen_fixtures_round2.py [REPO]

REPO defaults to the repository this file sits in. It writes
fixtures/generated-0.7/core-review-r2-*.der and registers them, with their
cases, in fixtures/cases.json (replacing entries of the same id). It reuses
gen_fixtures.py's writer, its minted P-256 PKI and its shared-receipt
splicing, and leaves the round-1 fixtures as they are: the minted receipts
here are signed by the same keys, so they verify under the committed
core-review-receipt-root. Needs Python 3.9+ and `cryptography` 41 or later.

Three groups:

- the anchor set (round-2 F2): a twin of receipt-root (its subject name, a
  new key) and a certificate it issued, added to the shared receipt's
  unsigned certificates bag; and a self-signed anchor carrying the subject
  name of the shared receipt's intermediate, and one carrying the shared
  transaction's intermediate's. Each pinned beside the real root, in both
  orders;
- OpenSSL's ANY rules one SEQUENCE deep (F3): signed payloads whose fourth
  field is a SEQUENCE holding a value OpenSSL refuses on its own, and
  unsigned envelope values of the same shape;
- the Xcode wrap in six and seven constructed levels (N1).
"""

import base64
import datetime
import hashlib
import json
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_fixtures as g  # noqa: E402  (the round-1 generator; importing it writes nothing)

FIXTURES, OUT = g.FIXTURES, g.OUT


def _key(scalar):
    return ec.derive_private_key(scalar, ec.SECP256R1())


def _self_signed(subject, key, serial):
    """A self-signed CA certificate: no key identifiers, like the anchors a
    caller might pin by hand."""
    return (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER))


def _issued(subject, key, issuer, issuer_key, serial):
    return (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(serial)
            .not_valid_before(datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2099, 1, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(issuer_key, hashes.SHA256())
            .public_bytes(serialization.Encoding.DER))


def _subject(der):
    return x509.load_der_x509_certificate(der).subject


def _transaction_intermediate():
    with open(os.path.join(FIXTURES, 'generated', 'transaction.jws'), encoding='utf-8') as handle:
        header = handle.read().strip().split('.')[0]
    header += '=' * (-len(header) % 4)
    return base64.b64decode(json.loads(base64.urlsafe_b64decode(header))['x5c'][1])


# The shared receipt's chain is RSA and the shared transaction's is P-256.
# OpenSSL pairs a certificate with a would-be issuer only when the issuer's
# key type fits the certificate's signature algorithm, so each look-alike
# carries the key type of the chain it imitates. RSA keys are drawn fresh,
# so a rerun changes those fixtures and their contentSha256.
TWIN_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
RECEIPT_DECOY_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY, JWS_DECOY_KEY = _key(0x5202), _key(0x5204)

FILES = {}
CASES = []


def add(name, der, *cases):
    FILES[name] = der
    CASES.extend(cases)


def build():
    root, mroot = 'receipt-root', 'core-review-receipt-root'
    tags = g.TAGS + ['core-review-2']
    neg, pos = ['negative'], ['positive']
    pinning = ['receipt', 'pkcs7', 'chain', 'pinning', 'positive', 'core-review', 'core-review-2', 'new-in-0-7']

    # F2 (a): a certificate from a same-named root's PKI in the unsigned bag.
    with open(os.path.join(OUT, 'receipt-root.der'), 'rb') as handle:
        receipt_root = handle.read()
    root_name = _subject(receipt_root)
    twin = _self_signed(root_name, TWIN_KEY, 0x52_01)
    other = _issued(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Core Review Twin Issued')]),
                    OTHER_KEY, root_name, TWIN_KEY, 0x52_02)
    FILES['core-review-r2-twin-receipt-root'] = twin
    add('core-review-r2-receipt-twin-issued-in-bag', g.respliced(extra_choices=other))
    for position, roots in (('second', ['core-review-r2-twin-receipt-root', root]),
                            ('first', [root, 'core-review-r2-twin-receipt-root'])):
        CASES.append(g.case(
            f'receipt/verify-under-the-{position}-of-two-same-named-roots-with-the-other-roots-certificate-in-the-bag',
            'core-review-r2-receipt-twin-issued-in-bag', None, g.OK_BUNDLE,
            'The shared receipt with a certificate added to its unsigned certificates bag, issued by a second '
            'pinned root that has the receipt root\'s subject name and another key; the receipt\'s own root is '
            + position + '. Each root that issued something used to stay in one store, where OpenSSL\'s issuer '
            'lookup takes the first name match and never tries a second, so with the twin first the chain did not '
            'verify. The path is now validated once per candidate root, each alone: it verifies in either order.',
            roots=roots, tags=pinning))

    # F2 (b): a pinned anchor carrying the intermediate's subject name.
    receipt_intermediate = g.children(g.CERTIFICATES[1])[1][2]
    decoy = _self_signed(_subject(receipt_intermediate), RECEIPT_DECOY_KEY, 0x52_03)
    FILES['core-review-r2-decoy-receipt-intermediate-root'] = decoy
    for position, roots in (('second', ['core-review-r2-decoy-receipt-intermediate-root', root]),
                            ('first', [root, 'core-review-r2-decoy-receipt-intermediate-root'])):
        CASES.append(g.case(
            f'receipt/verify-beside-an-anchor-named-as-the-intermediate-its-root-{position}', 'receipt', None,
            g.OK_BUNDLE,
            'The shared receipt with its root pinned ' + position + ' beside a self-signed anchor that carries '
            'the subject name of the receipt\'s intermediate and another key. Under OpenSSL\'s trusted-first '
            'lookup that anchor was taken as the signer\'s issuer and the path to the real root never verified, in '
            'either order. Each candidate anchor now gets a store of its own: it verifies.',
            roots=roots, tags=pinning))
    decoy_jws = _self_signed(_subject(_transaction_intermediate()), JWS_DECOY_KEY, 0x52_04)
    FILES['core-review-r2-decoy-jws-intermediate-root'] = decoy_jws
    for position, roots in (('second', ['core-review-r2-decoy-jws-intermediate-root', 'jws-root']),
                            ('first', ['jws-root', 'core-review-r2-decoy-jws-intermediate-root'])):
        CASES.append(g.case(
            f'transaction/verify-beside-an-anchor-named-as-the-intermediate-its-root-{position}', 'transaction',
            None, {'status': 'ok', 'fields': {'/bundleId': 'com.example.app'}},
            'The shared transaction with its root pinned ' + position + ' beside a self-signed anchor that '
            'carries the subject name of the x5c intermediate and another key: it verifies, as the receipt does.',
            roots=roots, operation='verifySignedData',
            tags=['transaction', 'jws', 'chain', 'pinning', 'positive', 'core-review', 'core-review-2',
                  'new-in-0-7']))

    # F3: what OpenSSL's ANY decoder refuses on its own, one SEQUENCE deeper.
    refused = [
        ('short-utctime', 'a-short-utctime', b'\x17\x01\x30', 'a UTCTime of one octet (OpenSSL requires 13)'),
        ('short-generalizedtime', 'a-short-generalizedtime', b'\x18\x02\x32\x30',
         'a GeneralizedTime of two octets (OpenSSL requires 15)'),
        ('constructed-integer', 'a-constructed-integer', b'\x22\x03\x02\x01\x05',
         'an INTEGER in constructed form, which OpenSSL refuses for BOOLEAN, INTEGER, NULL, OBJECT IDENTIFIER '
         'and ENUMERATED'),
        ('primitive-sequence', 'a-primitive-sequence', b'\x10\x00', 'a SEQUENCE in primitive form'),
        ('end-of-contents', 'an-end-of-contents', b'\x00\x00', 'an end-of-contents inside a definite length'),
        ('7-level-octet-string', 'a-7-level-octet-string', g.rechunked(7, b'x'),
         'an OCTET STRING of seven constructed levels (OpenSSL joins six, ASN1_MAX_STRING_NEST)'),
    ]
    for slug, phrase, value, what in refused:
        name = f'core-review-r2-fourth-sequence-{slug}'
        add(name, g.minted(g.payload(g.fourth_field(g.seq(value)))),
            g.case(f'receipt/unreadable-fourth-field-sequence-holding-{phrase}', name, mroot,
                   g.error('UNREADABLE_PAYLOAD'),
                   'Signed content whose unknown attribute 9000 carries a fourth field that is a SEQUENCE holding '
                   + what + '. OpenSSL\'s ANY decoder refuses that value as the fourth field itself but keeps a '
                   'SEQUENCE whole without looking inside, so the core read it one level down. The header walk now '
                   'applies the same rule at every depth; the signature verifies: UNREADABLE_PAYLOAD.',
                   fault=f'fourth-field-sequence-holding-{slug}', clock=True,
                   tags=tags + neg + ['payload', 'der', 'verification-order']))
    constructed_time = b'\x37\x11' + g.enc(0x04, b'240101') + g.enc(0x04, b'000000Z')
    add('core-review-r2-fourth-sequence-constructed-utctime',
        g.minted(g.payload(g.fourth_field(g.seq(constructed_time)))),
        g.case('receipt/accept-fourth-field-sequence-holding-a-constructed-utctime',
               'core-review-r2-fourth-sequence-constructed-utctime', mroot,
               {'status': 'ok', 'fields': {'/bundle_id': 'com.example.app',
                                           '/unknown_attributes/9000/0': g.b64(g.integer(1))}},
               'Signed content whose fourth field is a SEQUENCE holding a constructed UTCTime of two OCTET STRING '
               'chunks whose joined octets are 13, as BER allows. OpenSSL decodes it, and so does the walk: the '
               'content reads.', tags=tags + pos + ['payload', 'der']))
    for slug, phrase, value, what in (refused[0], refused[5]):
        name = f'core-review-r2-unsigned-sequence-{slug}'
        add(name, g.respliced(unsigned=g.unsigned_attribute(g.seq(value))),
            g.case(f'receipt/reject-an-unsigned-value-sequence-holding-{phrase}', name, root, g.error('MALFORMED'),
                   'The shared receipt whose SignerInfo gains an unsigned attribute value that is a SEQUENCE '
                   'holding ' + what + '. OpenSSL keeps the SEQUENCE whole and refuses the same value one level up; '
                   'the walk refuses it at every depth, before any decode: MALFORMED.',
                   fault=f'unsigned-value-sequence-holding-{slug}', tags=tags + neg + ['der']))

    # N1: the Xcode wrap in six and seven constructed levels.
    add('core-review-r2-wrap-6-levels', g.minted(g.rechunked(6, g.payload())),
        g.case('receipt/accept-double-wrap-rechunked-into-6-constructed-levels', 'core-review-r2-wrap-6-levels',
               mroot, g.OK_BUNDLE,
               'Signed content in the Xcode double wrap, the wrapping OCTET STRING written in six constructed levels '
               'of OCTET STRING chunks: OpenSSL joins six, and the content reads.',
               tags=tags + pos + ['payload', 'der']))
    add('core-review-r2-wrap-7-levels', g.minted(g.rechunked(7, g.payload())),
        g.case('receipt/unreadable-double-wrap-rechunked-into-7-constructed-levels', 'core-review-r2-wrap-7-levels',
               mroot, g.error('UNREADABLE_PAYLOAD'),
               'The same wrap in seven constructed levels. OpenSSL joins at most six (ASN1_MAX_STRING_NEST), so the '
               'wrap does not decode; 0.7 read it within its depth bound. The signature verifies: '
               'UNREADABLE_PAYLOAD, recorded in docs/rust-core/DECISIONS.md R20.',
               fault='double-wrap-nested-7-levels', clock=True,
               tags=tags + neg + ['payload', 'der', 'limits', 'verification-order']))


def main():
    build()
    for name, der in FILES.items():
        with open(os.path.join(OUT, name + '.der'), 'wb') as handle:
            handle.write(der)
    path = os.path.join(FIXTURES, 'cases.json')
    with open(path, encoding='utf-8') as handle:
        document = json.load(handle)
    for name, der in sorted(FILES.items()):
        document['fixtures'][name] = {
            'path': f'generated-0.7/{name}.der',
            'role': 'trust-anchor' if name.endswith('-root') else 'input',
            'codec': 'raw',
            'contentSha256': hashlib.sha256(der).hexdigest(),
        }
    ids = {entry['id'] for entry in CASES}
    kept = [entry for entry in document['cases'] if entry['id'] not in ids]
    document['cases'] = kept + CASES
    with open(path, 'w', encoding='utf-8') as handle:
        handle.write(json.dumps(document, indent=2, ensure_ascii=False) + '\n')
    for entry in CASES:
        expected = entry['expected']
        print(entry['id'], expected.get('reason', expected['status']))
    print(f'{len(FILES)} fixtures, {len(CASES)} cases')


if __name__ == '__main__':
    main()
