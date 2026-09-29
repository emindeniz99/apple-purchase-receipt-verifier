#!/usr/bin/env python3
"""Evidence only (2026-09-29): the shared cases the third core review's
findings became, and their fixtures.

    python3 gen_fixtures_round3.py [REPO]

REPO defaults to the repository this file sits in. It writes
fixtures/generated-0.7/core-review-r3-*.der and registers them, with their
cases, in fixtures/cases.json (replacing entries of the same id). It reuses
gen_fixtures.py's writer, its minted P-256 PKI (no key identifiers) and its
shared-receipt splicing, and leaves the round-1 and round-2 fixtures as they
are. ECDSA signatures are randomised, so a rerun changes the minted files
and their contentSha256. Needs Python 3.9+ and `cryptography` 41 or later.

Two groups:

- same-named intermediates in the unsigned bag (round-3 F1): a second
  pinned root with an intermediate carrying the minted intermediate's
  subject name, and a second intermediate of that name under the minted
  root, each placed before and after the real one;
- a certificate's signature BIT STRING in two chunks (F2): the shared
  receipt with one certificate's outer signature (outside its signed TBS)
  re-encoded as a constructed BIT STRING of two primitive chunks.
"""

import hashlib
import json
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gen_fixtures as g  # noqa: E402  (the round-1 generator; importing it writes nothing)

FIXTURES, OUT = g.FIXTURES, g.OUT

SECOND_ROOT_NAME = 'Core Review Round 3 Second Root'
SECOND_ROOT_KEY, OTHER_WWDR_KEY, SIBLING_WWDR_KEY = g._key(0x5301), g._key(0x5302), g._key(0x5303)
SECOND_ROOT = g._certificate(SECOND_ROOT_NAME, SECOND_ROOT_KEY, SECOND_ROOT_NAME, SECOND_ROOT_KEY, 0x5301,
                             True, None)
# Both carry the minted intermediate's subject name and another key.
OTHER_ROOT_WWDR = g._certificate('Core Review Test WWDR', OTHER_WWDR_KEY, SECOND_ROOT_NAME, SECOND_ROOT_KEY,
                                 0x5302, True, g.WWDR_MARKER)
SIBLING_WWDR = g._certificate('Core Review Test WWDR', SIBLING_WWDR_KEY, 'Core Review Test Root', g.ROOT_KEY,
                              0x5303, True, g.WWDR_MARKER)


def minted_with_bag(bag):
    """The minted receipt of the default payload, its certificates bag set
    to `bag` in that order; gen_fixtures.minted with the bag as a parameter."""
    signed = g.payload()
    signature = g.SIGNER_KEY.sign(signed, ec.ECDSA(hashes.SHA256()))
    issuer = g.seq(g.set_of(g.seq(g.oid('2.5.4.3'), g.enc(0x0c, b'Core Review Test WWDR'))))
    signer_info = g.seq(g.integer(1), g.seq(issuer, g.integer(3)), g.seq(g.oid(g.OID_SHA256)),
                        g.seq(g.oid(g.OID_ECDSA_SHA256)), g.enc(0x04, signature))
    encap = g.seq(g.oid(g.OID_DATA), g.enc(0xa0, g.enc(0x04, signed)))
    signed_data = g.seq(g.integer(1), g.set_of(g.seq(g.oid(g.OID_SHA256))), encap, g.enc(0xa0, b''.join(bag)),
                        g.set_of(signer_info))
    return g.seq(g.oid(g.OID_SIGNED_DATA), g.enc(0xa0, signed_data))


def signature_in_two_chunks(certificate):
    """The certificate with its outer signature BIT STRING (primitive
    `03 L 00 sig`) written as a constructed BIT STRING of the chunks
    `03 01 00` and `03 L-1 sig`, which OpenSSL joins to the same octets."""
    tbs, algorithm, bits = g.children(g.tlv(certificate, 0)[1])
    assert bits[0] == 0x03 and bits[1][0] == 0
    return g.seq(tbs[2], algorithm[2], g.enc(0x23, g.enc(0x03, b'\x00') + g.enc(0x03, bits[1][1:])))


FILES = {}
CASES = []


def add(name, der, *cases):
    FILES[name] = der
    CASES.extend(cases)


def build():
    mroot, second = 'core-review-receipt-root', 'core-review-r3-second-root'
    pinning = ['receipt', 'pkcs7', 'chain', 'pinning', 'positive', 'core-review', 'core-review-3', 'new-in-0-7']
    FILES[second] = SECOND_ROOT
    real = g.WWDR

    # F1 (a): another pinned root's intermediate with the real one's name.
    for place, bag in (('before', [g.SIGNER, OTHER_ROOT_WWDR, real]), ('after', [g.SIGNER, real, OTHER_ROOT_WWDR])):
        name = f'core-review-r3-other-roots-namesake-{place}'
        FILES[name] = minted_with_bag(bag)
        for position, roots in (('first', [mroot, second]), ('second', [second, mroot])):
            CASES.append(g.case(
                f'receipt/verify-with-another-roots-same-named-intermediate-{place}-the-real-one-own-root-{position}',
                name, None, g.OK_BUNDLE,
                'A receipt signed under the minted PKI (no key identifiers) whose unsigned certificates bag holds, '
                + place + ' the real intermediate, an intermediate of the same subject name issued by a second '
                'pinned root; the receipt\'s own root is pinned ' + position + '. OpenSSL\'s issuer lookup over '
                'the bag takes the first name match and never tries another, so with the namesake first the '
                'genuine receipt was UNTRUSTED_CHAIN once the second root was pinned. The bag is now narrowed to '
                'the certificates that sign the path: it verifies in every order.',
                roots=roots, tags=pinning))

    # F1 (b): a second intermediate of the same name under the same root.
    for place, bag in (('before', [g.SIGNER, SIBLING_WWDR, real]), ('after', [g.SIGNER, real, SIBLING_WWDR])):
        name = f'core-review-r3-sibling-namesake-{place}'
        add(name, minted_with_bag(bag), g.case(
            f'receipt/verify-with-a-same-named-sibling-intermediate-{place}-the-real-one', name, mroot,
            g.OK_BUNDLE,
            'A receipt signed under the minted PKI whose unsigned certificates bag holds, ' + place + ' the real '
            'intermediate, a second intermediate of the same subject name issued by the same root with another '
            'key. Both are vouched for by the root; only the real one signed the leaf. With the sibling first the '
            'core answered UNTRUSTED_CHAIN; it verifies in either order.',
            tags=pinning))

    # F2: a certificate's signature BIT STRING in two chunks.
    certificates = [whole for _, _, whole in g.children(g.CERTIFICATES[1])]
    first_octet = g.children(g.tlv(certificates[0], 0)[1])[2][1][1]
    assert first_octet > 7, 'the case pins the fix only when the signature starts above 7'
    rechunked = [signature_in_two_chunks(certificates[0])] + certificates[1:]
    name = 'core-review-r3-certificate-signature-in-two-chunks'
    signed_data = g.seq(g.VERSION, g.DIGEST_ALGORITHMS, g.ENCAP[2], g.enc(0xa0, b''.join(rechunked)),
                        g.SIGNER_INFOS[2])
    add(name, g.seq(g.oid(g.OID_SIGNED_DATA), g.enc(0xa0, signed_data)), g.case(
        'receipt/accept-a-certificate-whose-signature-bit-string-is-in-two-chunks', name, 'receipt-root',
        g.OK_BUNDLE,
        'The shared receipt with its first embedded certificate\'s outer signature, outside the signed TBS, '
        'written as a constructed BIT STRING of two primitive chunks, 03 01 00 and the signature octets. BER '
        'allows a constructed BIT STRING and OpenSSL joins the chunks to the same signature, so the chain still '
        'verifies. The header walk used to judge each chunk as a value of its own, reading the signature\'s first '
        'octet as an unused-bits count, and answered MALFORMED whenever it was above 7.',
        tags=['receipt', 'pkcs7', 'der', 'positive', 'core-review', 'core-review-3', 'new-in-0-7']))


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
