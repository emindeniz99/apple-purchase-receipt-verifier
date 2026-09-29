#!/usr/bin/env python3
"""Evidence only (2026-09-29): the shared cases the core review's findings
became, and their fixtures.

    python3 gen_fixtures.py [REPO]

REPO defaults to the repository this file sits in. It writes
fixtures/generated-0.7/core-review-*.der and registers them, with their
cases, in fixtures/cases.json (replacing entries of the same id, so a rerun
is idempotent apart from the fresh signatures). Needs Python 3.9+ and the
`cryptography` package (41 or later).

Three kinds of input, all from generated material:

- the shared generated receipt (generated-0.7/receipt.der, under
  receipt-root) respliced: its unsigned parts changed or its eContent
  re-chunked, the SignerInfo kept byte for byte, so the signature still
  holds;
- payloads signed by a PKI minted here (P-256, fixed private scalars, valid
  2024-01-01 to 2050-01-01, creation date 2024-08-06): ECDSA signatures are
  randomised, so each run changes those files and their contentSha256;
- the shared receipt with one byte of the signer's RSA modulus zeroed.
"""

import base64
import datetime
import hashlib
import json
import os
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

REPO = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), '..', '..', '..'))
FIXTURES = os.path.join(REPO, 'fixtures')
OUT = os.path.join(FIXTURES, 'generated-0.7')

OID_DATA = '1.2.840.113549.1.7.1'
OID_SIGNED_DATA = '1.2.840.113549.1.7.2'
OID_SHA256 = '2.16.840.1.101.3.4.2.1'
OID_ECDSA_SHA256 = '1.2.840.10045.4.3.2'
OID_SHA256_RSA = '1.2.840.113549.1.1.11'
WWDR_MARKER = '1.2.840.113635.100.6.2.1'
SIGNER_MARKER = '1.2.840.113635.100.6.11.1'
CREATION_DATE = b'2024-08-06T12:00:00Z'
CLOCK = '2025-01-01T00:00:00Z'


# --- a minimal DER writer and a BER reader -------------------------------

def enc(tag, content):
    """One TLV with a definite, minimal length."""
    n = len(content)
    if n < 0x80:
        return bytes([tag, n]) + content
    octets = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag, 0x80 | len(octets)]) + octets + content


def seq(*parts):
    return enc(0x30, b''.join(parts))


def set_of(*parts):
    return enc(0x31, b''.join(parts))


def integer(value):
    return enc(0x02, value.to_bytes(max(1, (value.bit_length() + 8) // 8), 'big', signed=True))


def oid(dotted):
    arcs = [int(a) for a in dotted.split('.')]
    body = bytearray()
    for arc in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        chunk = [arc & 0x7f]
        arc >>= 7
        while arc:
            chunk.insert(0, 0x80 | (arc & 0x7f))
            arc >>= 7
        body += bytes(chunk)
    return enc(0x06, bytes(body))


def tlv(b, i):
    """(identifier, content, whole encoding, next offset), BER lengths."""
    start = i
    ident = b[i]
    i += 1
    length = b[i]
    i += 1
    if length == 0x80:
        s = i
        while b[i:i + 2] != b'\x00\x00':
            i = tlv(b, i)[3]
        return ident, b[s:i], b[start:i + 2], i + 2
    if length & 0x80:
        count = length & 0x7f
        length = int.from_bytes(b[i:i + count], 'big')
        i += count
    return ident, b[i:i + length], b[start:i + length], i + length


def children(content):
    i, out = 0, []
    while i < len(content):
        ident, body, whole, i = tlv(content, i)
        out.append((ident, body, whole))
    return out


def joined(ident, body):
    """An OCTET STRING's octets, constructed chunks joined."""
    if ident == 0x04:
        return body
    return b''.join(joined(k[0], k[1]) for k in children(body))


def nested(levels, identifier=0x30):
    """`levels` nested constructed values, the innermost empty."""
    value = bytes([identifier, 0])
    for _ in range(levels - 1):
        value = enc(identifier, value)
    return value


# --- the shared receipt, taken apart --------------------------------------

SHARED = open(os.path.join(OUT, 'receipt.der'), 'rb').read()
_ci = children(tlv(SHARED, 0)[1])
_signed = children(_ci[1][1])[0]
_members = children(_signed[1])
VERSION, DIGEST_ALGORITHMS, ENCAP = _members[0][2], _members[1][2], _members[2]
CERTIFICATES, SIGNER_INFOS = _members[3], _members[-1]
assert CERTIFICATES[0] == 0xa0 and SIGNER_INFOS[0] == 0x31 and len(_members) == 5
ECONTENT = children(children(ENCAP[1])[1][1])[0]
PAYLOAD = joined(ECONTENT[0], ECONTENT[1])
SIGNER_INFO = children(SIGNER_INFOS[1])[0]
assert len(children(SIGNER_INFOS[1])) == 1


def respliced(digest_algorithms=DIGEST_ALGORITHMS, econtent=None, extra_choices=b'', crls=None,
              unsigned=None):
    """The shared receipt with its unsigned parts replaced; the SignerInfo's
    fields are kept as they are."""
    encap = ENCAP[2] if econtent is None else seq(oid(OID_DATA), enc(0xa0, econtent))
    signer_info = SIGNER_INFO[2] if unsigned is None else enc(0x30, SIGNER_INFO[1] + unsigned)
    parts = [VERSION, digest_algorithms, encap, enc(0xa0, CERTIFICATES[1] + extra_choices)]
    if crls is not None:
        parts.append(crls)
    parts.append(set_of(signer_info))
    return seq(oid(OID_SIGNED_DATA), enc(0xa0, seq(*parts)))


def rechunked(levels, octets, leaf=0x04):
    """`octets` as an OCTET STRING of `levels` constructed levels."""
    value = enc(leaf, octets)
    for _ in range(levels):
        value = enc(0x24, value)
    return value


def crl(parameters):
    algorithm = seq(oid(OID_SHA256_RSA), parameters)
    issuer = seq(set_of(seq(oid('2.5.4.3'), enc(0x0c, b'CRL Issuer'))))
    tbs = seq(algorithm, issuer, enc(0x17, b'240101000000Z'))
    return seq(tbs, algorithm, enc(0x03, b'\x00\x01\x02\x03'))


def unsigned_attribute(value):
    return enc(0xa1, seq(oid('1.2.3.4'), set_of(value)))


# --- the minted PKI and its receipts --------------------------------------

def _key(scalar):
    return ec.derive_private_key(scalar, ec.SECP256R1())


ROOT_KEY, WWDR_KEY, SIGNER_KEY = _key(0x5101), _key(0x5102), _key(0x5103)


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _certificate(subject, key, issuer, issuer_key, serial, ca, marker):
    builder = (x509.CertificateBuilder()
               .subject_name(_name(subject))
               .issuer_name(_name(issuer))
               .public_key(key.public_key())
               .serial_number(serial)
               .not_valid_before(datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc))
               .not_valid_after(datetime.datetime(2050, 1, 1, tzinfo=datetime.timezone.utc)))
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
    if marker:
        builder = builder.add_extension(
            x509.UnrecognizedExtension(x509.ObjectIdentifier(marker), b'\x05\x00'), critical=False)
    return builder.sign(issuer_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


ROOT = _certificate('Core Review Test Root', ROOT_KEY, 'Core Review Test Root', ROOT_KEY, 1, True, None)
WWDR = _certificate('Core Review Test WWDR', WWDR_KEY, 'Core Review Test Root', ROOT_KEY, 2, True, WWDR_MARKER)
SIGNER = _certificate('Core Review Test Signer', SIGNER_KEY, 'Core Review Test WWDR', WWDR_KEY, 3, False,
                      SIGNER_MARKER)


def minted(signed, econtent=None):
    """A receipt whose eContent octets `signed` the minted signer signs, with
    no signed attributes; `econtent` is the eContent TLV, by default one
    primitive OCTET STRING."""
    signature = SIGNER_KEY.sign(signed, ec.ECDSA(hashes.SHA256()))
    issuer = seq(set_of(seq(oid('2.5.4.3'), enc(0x0c, b'Core Review Test WWDR'))))
    signer_info = seq(integer(1), seq(issuer, integer(3)), seq(oid(OID_SHA256)),
                      seq(oid(OID_ECDSA_SHA256)), enc(0x04, signature))
    encap = seq(oid(OID_DATA), enc(0xa0, econtent if econtent is not None else enc(0x04, signed)))
    signed_data = seq(integer(1), set_of(seq(oid(OID_SHA256))), encap, enc(0xa0, SIGNER + WWDR),
                      set_of(signer_info))
    return seq(oid(OID_SIGNED_DATA), enc(0xa0, signed_data))


def attribute(type_tlv, value_tlv, *more):
    """A ReceiptAttribute: the type TLV, version 1, the value TLV (the whole
    OCTET STRING encoding), and any further fields."""
    return seq(type_tlv, integer(1), value_tlv, *more)


def payload(*extra):
    """A payload SET: bundle id, creation date, then `extra` attributes."""
    return set_of(attribute(integer(2), enc(0x04, enc(0x0c, b'com.example.app'))),
                  attribute(integer(12), enc(0x04, enc(0x16, CREATION_DATE))),
                  *extra)


def fourth_field(field):
    return attribute(integer(9000), enc(0x04, integer(1)), field)


def nested_around(levels, identifier, inner):
    value = inner
    for _ in range(levels):
        value = enc(identifier, value)
    return value


# --- the cases ------------------------------------------------------------

TAGS = ['receipt', 'pkcs7', 'core-review', 'new-in-0-7']


def case(case_id, fixture, root, expected, description, fault=None, clock=False, tags=(), roots=None,
         operation='verifyReceipt'):
    entry = {
        'id': case_id,
        'description': description,
        'operation': operation,
        'input': {'fixture': fixture},
        'config': {'trustedRoots': {'source': 'fixtures', 'fixtures': roots or [root]}},
    }
    if clock:
        entry['clock'] = {'now': CLOCK}
    entry['expected'] = expected
    if fault:
        entry['fault'] = fault
    entry['tags'] = list(tags)
    return entry


OK_BUNDLE = {'status': 'ok', 'fields': {'/bundle_id': 'com.example.app'}}


def error(reason):
    return {'status': 'error', 'reason': reason}


def b64(octets):
    return base64.b64encode(octets).decode()


FILES = {}
CASES = []


def add(name, der, *cases):
    FILES[name] = der
    CASES.extend(cases)


def build():
    root = 'receipt-root'
    mroot = 'core-review-receipt-root'
    FILES[mroot] = ROOT
    neg = ['negative']
    pos = ['positive']

    # Decision 3 (Rust-F1, C-F4, Policy-F4): eContent chunk nesting.
    add('core-review-receipt-econtent-6-levels', respliced(econtent=rechunked(6, PAYLOAD)),
        case('receipt/accept-econtent-rechunked-into-6-constructed-levels', 'core-review-receipt-econtent-6-levels',
             root, OK_BUNDLE,
             'The shared receipt with its eContent re-encoded as an OCTET STRING of six constructed levels, all '
             'chunks OCTET STRINGs (X.690 section 8.7.3). The joined octets, which the signature covers, do not '
             'change, and OpenSSL decodes six levels: it verifies. The core used to stop one level short.',
             tags=TAGS + pos + ['der']))
    add('core-review-receipt-econtent-7-levels', respliced(econtent=rechunked(7, PAYLOAD)),
        case('receipt/reject-econtent-rechunked-into-7-constructed-levels', 'core-review-receipt-econtent-7-levels',
             root, error('MALFORMED'),
             'The same eContent re-encoded as seven constructed levels. OpenSSL, the core\'s decoder, reads at most '
             'six (ASN1_MAX_STRING_NEST), so the envelope does not decode: MALFORMED, failing closed. 0.7 read it '
             'within its depth bound of 32; recorded as a substrate divergence in docs/rust-core/DECISIONS.md R20.',
             fault='econtent-chunks-nested-7-levels', tags=TAGS + neg + ['der', 'limits']))

    # Decision 1 (C-F2, Rust-F3, Policy-F2): the depth bound in every place of the envelope.
    add('core-review-receipt-digest-algorithms-32',
        respliced(digest_algorithms=set_of(seq(oid(OID_SHA256), nested(27)))),
        case('receipt/accept-digest-algorithm-parameters-nested-32-deep', 'core-review-receipt-digest-algorithms-32',
             root, OK_BUNDLE,
             'The shared receipt whose unsigned SignedData.digestAlgorithms entry carries parameters of nested '
             'SEQUENCEs, so the envelope nests 32 constructed values deep counting the ContentInfo as 1 '
             '(ContentInfo, [0], SignedData, the SET, the AlgorithmIdentifier, then 27 levels): at the bound, it '
             'verifies.', tags=TAGS + pos + ['limits']))
    add('core-review-receipt-digest-algorithms-33',
        respliced(digest_algorithms=set_of(seq(oid(OID_SHA256), nested(28)))),
        case('receipt/reject-digest-algorithm-parameters-nested-33-deep', 'core-review-receipt-digest-algorithms-33',
             root, error('MALFORMED'),
             'The same parameters one level deeper: the envelope nests 33 deep, over the ASN.1 depth bound, which '
             'counts every constructed value of the envelope wherever it sits: MALFORMED before any cryptography. '
             'The core used to measure the depth only inside SignerInfo values, and verified this.',
             fault='digest-algorithm-parameters-nested-33-deep', tags=TAGS + neg + ['limits']))
    add('core-review-receipt-unsigned-context-tags-33', respliced(unsigned=unsigned_attribute(nested(25, 0xa0))),
        case('receipt/reject-an-envelope-nested-33-deep-in-context-tags', 'core-review-receipt-unsigned-context-tags-33',
             root, error('MALFORMED'),
             'The shared receipt whose SignerInfo gains an unsigned attribute value of 25 nested [0] context-tagged '
             'constructed values: 33 deep counting the ContentInfo as 1. The depth bound counts constructed values '
             'of every class, not only SEQUENCEs and SETs: MALFORMED.',
             fault='envelope-nested-33-deep-in-context-tags', tags=TAGS + neg + ['limits']))
    add('core-review-receipt-crl-33', respliced(crls=enc(0xa1, crl(nested(26)))),
        case('receipt/reject-a-crls-entry-nested-33-deep', 'core-review-receipt-crl-33', root, error('MALFORMED'),
             'The shared receipt with a crls field holding one CertificateList whose signature algorithm '
             'parameters nest 26 SEQUENCEs deep: 33 deep in the envelope (ContentInfo, [0], SignedData, [1], the '
             'CertificateList, its TBSCertList, the AlgorithmIdentifier, then 26 levels). MALFORMED.',
             fault='crls-entry-nested-33-deep', tags=TAGS + neg + ['limits']))
    intermediate = children(CERTIFICATES[1])[1][2]
    parts = children(tlv(intermediate, 0)[1])
    algorithm_oid = children(parts[1][1])[0][2]
    deep_copy = seq(parts[0][2], seq(algorithm_oid, nested(27)), parts[2][2])
    add('core-review-receipt-certificate-parameters-33', respliced(extra_choices=deep_copy),
        case('receipt/reject-an-embedded-certificate-with-parameters-nested-33-deep',
             'core-review-receipt-certificate-parameters-33', root, error('MALFORMED'),
             'The shared receipt with one more embedded certificate: a copy of its intermediate whose outer '
             'signatureAlgorithm parameters nest 27 SEQUENCEs deep, 33 deep in the envelope. MALFORMED before '
             'any certificate is decoded.',
             fault='embedded-certificate-nested-33-deep', tags=TAGS + neg + ['limits']))

    # C-F5: the crls field is bounded as the certificates are.
    minimal_crl = crl(b'\x05\x00')
    add('core-review-receipt-ten-crls', respliced(crls=enc(0xa1, minimal_crl * 10)),
        case('receipt/accept-ten-embedded-crls', 'core-review-receipt-ten-crls', root, OK_BUNDLE,
             'The shared receipt with ten minimal CertificateLists in its unsigned crls field. Apple\'s receipts '
             'carry none, and nothing reads them; at the bound of ten, which is the certificate bound, it verifies.',
             tags=TAGS + pos + ['limits']))
    add('core-review-receipt-eleven-crls', respliced(crls=enc(0xa1, minimal_crl * 11)),
        case('receipt/reject-eleven-embedded-crls', 'core-review-receipt-eleven-crls', root, error('MALFORMED'),
             'The same receipt with eleven CRLs: one over the bound. Each CRL is decoded in full before anything '
             'is verified, so the count is bounded before a single one is decoded, as the certificates are: '
             'MALFORMED. The 0.7 contract is silent on CRLs; this is the fail-closed answer.',
             fault='eleven-embedded-crls', tags=TAGS + neg + ['limits']))

    # Decision 1 in signed content (C-F2, Rust-F3): the payload's depth in context tags.
    for levels, depth in ((30, 32), (31, 33)):
        field = nested_around(levels, 0xa0, integer(1))
        name = f'core-review-receipt-content-context-tags-{depth}'
        if depth == 32:
            expected = {'status': 'ok', 'fields': {'/bundle_id': 'com.example.app',
                                                   '/unknown_attributes/9000/0': b64(integer(1))}}
            entry = case('receipt/accept-signed-content-nested-32-deep-in-context-tags', name, mroot, expected,
                         'Signed content whose unknown attribute 9000 carries a fourth field of 30 nested [0] '
                         'context-tagged values: the content nests 32 deep counting the SET as 1. At the bound, it '
                         'verifies.', tags=TAGS + pos + ['limits', 'payload'])
        else:
            entry = case('receipt/unreadable-signed-content-nested-33-deep-in-context-tags', name, mroot,
                         error('UNREADABLE_PAYLOAD'),
                         'The same fourth field one level deeper: 33 deep. The depth bound counts constructed '
                         'values of every class; the signature verifies, so the content is UNREADABLE_PAYLOAD. The '
                         'core used to count only SEQUENCEs and SETs, and read it.',
                         fault='signed-content-nested-33-deep-in-context-tags', clock=True,
                         tags=TAGS + neg + ['limits', 'payload', 'verification-order'])
        add(name, minted(payload(fourth_field(field))), entry)

    # Decision 4 (C-F3, Rust-F6, Policy-F5): payload shapes 0.7 refused.
    bundle = enc(0x0c, b'com.example.app')
    date_attribute = attribute(integer(12), enc(0x04, enc(0x16, CREATION_DATE)))
    add('core-review-receipt-value-chunks',
        minted(set_of(attribute(integer(2), rechunked(2, bundle)), date_attribute)),
        case('receipt/accept-attribute-value-as-a-constructed-octet-string', 'core-review-receipt-value-chunks',
             mroot, OK_BUNDLE,
             'Signed content whose bundle id value is an OCTET STRING of two constructed levels, every chunk an '
             'OCTET STRING, as BER allows: the chunks are joined and the bundle id reads.',
             tags=TAGS + pos + ['payload', 'der']))
    add('core-review-receipt-value-foreign-chunk',
        minted(set_of(attribute(integer(2), rechunked(1, bundle, leaf=0x0c)), date_attribute)),
        case('receipt/unreadable-attribute-value-with-a-utf8string-chunk', 'core-review-receipt-value-foreign-chunk',
             mroot, error('UNREADABLE_PAYLOAD'),
             'Signed content whose bundle id value is a constructed OCTET STRING whose chunk is a UTF8String. '
             'X.690 section 8.7.3 allows only OCTET STRING chunks, and 0.7 and Java refuse it; OpenSSL joins '
             'chunks of any tag, and the core used to read com.example.app out of it. The signature verifies: '
             'UNREADABLE_PAYLOAD.', fault='attribute-value-with-a-utf8string-chunk', clock=True,
             tags=TAGS + neg + ['payload', 'der', 'verification-order']))
    wrapped = payload()
    add('core-review-receipt-wrap-foreign-chunk', minted(enc(0x24, enc(0x02, wrapped))),
        case('receipt/unreadable-double-wrap-with-a-foreign-chunk', 'core-review-receipt-wrap-foreign-chunk', mroot,
             error('UNREADABLE_PAYLOAD'),
             'Signed content in the Xcode double wrap, written as a constructed OCTET STRING whose one chunk is an '
             'INTEGER holding the attribute SET. The wrap is an OCTET STRING, and its chunks must be too: '
             'UNREADABLE_PAYLOAD, as in 0.7 and Java.', fault='double-wrap-with-an-integer-chunk', clock=True,
             tags=TAGS + neg + ['payload', 'der', 'verification-order']))
    constructed_utf8 = b'\x2c\x80' + enc(0x04, b'com.example.app') + b'\x00\x00'
    add('core-review-receipt-constructed-utf8',
        minted(set_of(attribute(integer(2), enc(0x04, constructed_utf8)), date_attribute)),
        case('receipt/bundle-id-as-a-constructed-utf8string-is-kept-raw', 'core-review-receipt-constructed-utf8',
             mroot, {'status': 'ok', 'fields': {'/bundle_id': None, '/bundle_id_bytes': b64(constructed_utf8)}},
             'Signed content whose bundle id is a constructed, indefinite-length UTF8String (BER, never DER). '
             'The value does not decode as a string, so bundle_id is null and bundle_id_bytes keeps the octets, as '
             'in 0.7; OpenSSL would join the chunks.', tags=TAGS + pos + ['payload', 'der', 'unparseable-attribute']))
    high_tag_type = bytes([0x1f, 0x02, 0x01, 0x02])
    add('core-review-receipt-high-tag-type',
        minted(set_of(attribute(high_tag_type, enc(0x04, bundle)), date_attribute)),
        case('receipt/unreadable-attribute-type-in-high-tag-form', 'core-review-receipt-high-tag-type', mroot,
             error('UNREADABLE_PAYLOAD'),
             'Signed content whose first attribute type is the INTEGER 2 written with its tag in high-tag-number '
             'form (1F 02). DER forbids that form for a tag below 31, and 0.7 refused it anywhere in the payload; '
             'OpenSSL reads it. The signature verifies: UNREADABLE_PAYLOAD.', fault='attribute-type-in-high-tag-form',
             clock=True, tags=TAGS + neg + ['payload', 'der', 'verification-order']))
    high_tag_value = bytes([0x1f, 0x02, 0x01, 0x05])
    add('core-review-receipt-high-tag-value',
        minted(payload(attribute(integer(1), enc(0x04, high_tag_value)))),
        case('receipt/app-item-id-in-high-tag-form-is-kept-raw', 'core-review-receipt-high-tag-value', mroot,
             {'status': 'ok', 'fields': {'/bundle_id': 'com.example.app', '/app_item_id': None,
                                         '/unknown_attributes/1/0': b64(high_tag_value)}},
             'Signed content whose app item id value is the INTEGER 5 with its tag in high-tag-number form. The '
             'value does not decode, so the attribute is kept raw, as in 0.7.',
             tags=TAGS + pos + ['payload', 'der', 'unparseable-attribute']))
    five_octets = bytes([0x0c, 0x85, 0, 0, 0, 0, 15]) + b'com.example.app'
    add('core-review-receipt-five-octet-length',
        minted(set_of(attribute(integer(2), enc(0x04, five_octets)), date_attribute)),
        case('receipt/bundle-id-with-a-five-octet-length-is-kept-raw', 'core-review-receipt-five-octet-length', mroot,
             {'status': 'ok', 'fields': {'/bundle_id': None, '/bundle_id_bytes': b64(five_octets)}},
             'Signed content whose bundle id UTF8String states its length in five octets. 0.7 read lengths of at '
             'most four octets and DER needs one; OpenSSL reads it. The value does not decode: bundle_id is null.',
             tags=TAGS + pos + ['payload', 'der', 'unparseable-attribute']))
    add('core-review-receipt-fourth-boolean', minted(payload(fourth_field(bytes([0x01, 0x02, 0x00, 0x00])))),
        case('receipt/unreadable-fourth-field-boolean-of-two-octets', 'core-review-receipt-fourth-boolean', mroot,
             error('UNREADABLE_PAYLOAD'),
             'Signed content whose unknown attribute 9000 carries a fourth field that is a BOOLEAN of two octets. '
             'OpenSSL decodes every field by its tag and refuses it; 0.7 kept fields after the value opaque and '
             'verified. Matching 0.7 would take decoding by hand (R21), so the refusal stands, recorded in '
             'docs/rust-core/DECISIONS.md R20: UNREADABLE_PAYLOAD.', fault='fourth-field-boolean-of-two-octets',
             clock=True, tags=TAGS + neg + ['payload', 'der', 'verification-order']))
    add('core-review-receipt-fourth-sequence', minted(payload(fourth_field(seq(bytes([0x02, 0x02, 0x00, 0x01]))))),
        case('receipt/unreadable-fourth-field-sequence-holding-a-padded-integer', 'core-review-receipt-fourth-sequence',
             mroot, error('UNREADABLE_PAYLOAD'),
             'Signed content whose fourth field is a SEQUENCE holding an INTEGER with a redundant leading octet, '
             'which X.690 section 8.3.2 forbids in BER as in DER: the attribute SET is not valid ASN.1, at any '
             'depth, so the signature verifies and the content is UNREADABLE_PAYLOAD, as in Java. 0.7\'s Rust '
             'reader did not look inside the field.', fault='fourth-field-sequence-holding-a-padded-integer',
             clock=True, tags=TAGS + neg + ['payload', 'der', 'verification-order']))
    add('core-review-receipt-value-6-levels',
        minted(set_of(attribute(integer(2), rechunked(6, bundle)), date_attribute)),
        case('receipt/accept-attribute-value-rechunked-into-6-constructed-levels', 'core-review-receipt-value-6-levels',
             mroot, OK_BUNDLE,
             'Signed content whose bundle id value is an OCTET STRING of six constructed levels of OCTET STRING '
             'chunks: OpenSSL decodes six, and the bundle id reads.', tags=TAGS + pos + ['payload', 'der']))
    add('core-review-receipt-value-7-levels',
        minted(set_of(attribute(integer(2), rechunked(7, bundle)), date_attribute)),
        case('receipt/unreadable-attribute-value-rechunked-into-7-constructed-levels',
             'core-review-receipt-value-7-levels', mroot, error('UNREADABLE_PAYLOAD'),
             'The same value in seven constructed levels. OpenSSL reads at most six (ASN1_MAX_STRING_NEST), so '
             'the content does not decode; the signature verifies: UNREADABLE_PAYLOAD. 0.7 read it within its '
             'depth bound; recorded in docs/rust-core/DECISIONS.md R20.',
             fault='attribute-value-chunks-nested-7-levels', clock=True,
             tags=TAGS + neg + ['payload', 'der', 'verification-order']))

    # The Swift host's G1 run: two pinned roots sharing a subject name.
    for position, roots in (('second', ['api-receipt-root', 'receipt-root']),
                            ('first', ['receipt-root', 'api-receipt-root'])):
        CASES.append(case(
            f'receipt/verify-under-the-{position}-of-two-roots-sharing-a-subject', 'receipt', None, OK_BUNDLE,
            'The shared receipt with two pinned roots of the same subject name, its own ' + position + ': a chain '
            'verifies when its root is anywhere in the configured set, in any order. OpenSSL\'s issuer lookup '
            'takes the first root whose name matches, and the core answered UNTRUSTED_CHAIN with its own root '
            'second. Apple\'s three roots have distinct names.',
            roots=roots, tags=['receipt', 'pkcs7', 'chain', 'pinning', 'positive', 'core-review', 'new-in-0-7']))
    for position, roots in (('second', ['api-jws-root', 'jws-root']), ('first', ['jws-root', 'api-jws-root'])):
        CASES.append(case(
            f'transaction/verify-under-the-{position}-of-two-roots-sharing-a-subject', 'transaction', None,
            {'status': 'ok', 'fields': {'/bundleId': 'com.example.app'}},
            'The shared transaction with two pinned roots of the same subject name, its own ' + position + ': it '
            'verifies in either order.', roots=roots, operation='verifySignedData',
            tags=['transaction', 'jws', 'chain', 'pinning', 'positive', 'core-review', 'new-in-0-7']))

    # The Swift host's G1 run: an even RSA modulus in the signer.
    modulus_end = SHARED.index(bytes.fromhex('0282010100')) + 4 + 256
    even = bytearray(SHARED)
    even[modulus_end] = 0
    add('core-review-receipt-even-modulus', bytes(even),
        case('receipt/reject-signer-with-an-even-rsa-modulus', 'core-review-receipt-even-modulus', root,
             error('UNTRUSTED_CHAIN'),
             'The shared receipt with the last octet of its signer certificate\'s RSA modulus zeroed, so the '
             'modulus is even. The certificate still decodes, but its intermediate\'s signature over it no longer '
             'holds, so no path reaches the pinned root: UNTRUSTED_CHAIN, before the key is used. A port whose '
             'RSA decoder refuses an even modulus at decode time answers INVALID_CERTIFICATE instead.',
             fault='signer-rsa-modulus-even', tags=['receipt', 'pkcs7', 'chain', 'negative', 'core-review',
                                                    'new-in-0-7']))


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
