// Hostile receipts built at run time, through both builds. The signed
// attributes, the certificate bag and the creation date are all read before
// any signature has verified, so an attacker reaches those decoders with
// whatever bytes they like. Three things must hold for every such input:
// nothing escapes as a throw, the answer is a verdict the unauthenticated
// input can earn (never INTERNAL_ERROR or UNREADABLE_PAYLOAD), and the two
// builds agree. The shared cases pin single vectors; what stays here is the
// generated corpora no case file holds.
// oxlint-disable no-await-in-loop -- one verification at a time on purpose: the corpora hold 1000+ inputs, and firing every RSA check at once is not the bounded run this is meant to be
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { X509Certificate, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { Tag, parse } from '../dist/der.js';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';
import { mintReceiptPki, tlv } from './support/test-pki.js';

const read = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
const publicReceipt = (name) =>
  Buffer.from(read(`fixtures/public-receipts/${name}.b64`).toString('ascii').trim(), 'base64');

// The donor is the public sandbox receipt, so the chain and purpose checks
// pass against the real pinned roots and the decoders behind them are
// actually reached. Its chain is judged at its own creation date.
const GENUINE = publicReceipt('receipt-sandbox-g5');
const LEGACY = publicReceipt('receipt-sandbox-legacy');
const SHARED = read('fixtures/generated-0.7/receipt.der');
const SHARED_ROOT = read('fixtures/generated-0.7/receipt-root.der');
// Inside the donor leaf's validity window; a forgery must pin a creation
// date, or the chain is judged at the clock.
const SIGNING_TIME = '2025-12-26T17:43:07Z';

const PRE_SIGNATURE_REASONS = new Set([
  'MALFORMED',
  'TOO_LARGE',
  'INVALID_SIGNATURE',
  'UNTRUSTED_CHAIN',
  'INVALID_CERTIFICATE',
  'INVALID_CERTIFICATE_PURPOSE',
]);

const SEQUENCE = 0x30;
const SET = 0x31;
const CONTEXT_0 = 0xa0;
const INTEGER = 0x02;
const OCTET_STRING = 0x04;
const OID = 0x06;
const IA5_STRING = 0x16;

const OID_SIGNED_DATA = Buffer.from('2a864886f70d010702', 'hex');
const OID_DATA = Buffer.from('2a864886f70d010701', 'hex');
const OID_MESSAGE_DIGEST = Buffer.from('2a864886f70d010904', 'hex');

const donorSignedData = parse(GENUINE).children[1].children[0].children;
const donorCertificates = Buffer.concat(
  donorSignedData
    .slice(3, donorSignedData.length - 1)
    .find((n) => n.tag === Tag.CONTEXT_0)
    .children.map((n) => Buffer.from(n.raw)),
);
const donorSignerInfo = donorSignedData[donorSignedData.length - 1].children[0].children;
// issuerAndSerialNumber of the real leaf, so the signer lookup picks it out.
const donorSid = Buffer.from(donorSignerInfo[1].raw);
const donorDigestAlgorithm = Buffer.from(donorSignerInfo[2].raw);
const donorSignature = Buffer.from(donorSignerInfo[donorSignerInfo.length - 1].raw);

function forge({ certificates = donorCertificates, payload, signedAttrs = null }) {
  const signerFields = [tlv(INTEGER, Buffer.from([1])), donorSid, donorDigestAlgorithm];
  if (signedAttrs !== null) {
    signerFields.push(signedAttrs);
  }
  signerFields.push(tlv(SEQUENCE), donorSignature);
  return tlv(
    SEQUENCE,
    tlv(OID, OID_SIGNED_DATA),
    tlv(
      CONTEXT_0,
      tlv(
        SEQUENCE,
        tlv(INTEGER, Buffer.from([1])),
        tlv(SET),
        tlv(SEQUENCE, tlv(OID, OID_DATA), tlv(CONTEXT_0, tlv(OCTET_STRING, payload))),
        tlv(CONTEXT_0, certificates),
        tlv(SET, tlv(SEQUENCE, ...signerFields)),
      ),
    ),
  );
}

/** Receipt payload carrying just attribute 12 (creation date). */
const payloadDated = (text) =>
  tlv(
    SET,
    tlv(
      SEQUENCE,
      tlv(INTEGER, Buffer.from([12])),
      tlv(INTEGER, Buffer.from([1])),
      tlv(OCTET_STRING, tlv(IA5_STRING, Buffer.from(text, 'ascii'))),
    ),
  );

const messageDigestAttribute = (value) => tlv(SEQUENCE, tlv(OID, OID_MESSAGE_DIGEST), value);

// Signed-attribute shapes whose walk runs off the end of a child list.
const DEGENERATE_SIGNED_ATTRS = [
  ['[0] wrapping a primitive', tlv(CONTEXT_0, tlv(INTEGER, Buffer.from([0])))],
  ['attribute carrying only the OID', tlv(CONTEXT_0, tlv(SEQUENCE, tlv(OID, OID_MESSAGE_DIGEST)))],
  [
    'primitive attribute value',
    tlv(CONTEXT_0, messageDigestAttribute(tlv(INTEGER, Buffer.from([0])))),
  ],
  ['empty attribute value SET', tlv(CONTEXT_0, messageDigestAttribute(tlv(SET)))],
];

function* mutations(label, receipt, step) {
  for (let cut = 1; cut < receipt.length; cut += 64) {
    yield [`${label} truncated to ${cut} bytes`, receipt.subarray(0, cut), receipt];
  }
  for (let at = 0; at < receipt.length; at += step) {
    const flipped = Buffer.from(receipt);
    flipped[at] ^= 0xff;
    yield [`${label} byte ${at} flipped`, flipped, receipt];
  }
}

function* forgedCorpus() {
  yield ['empty', Buffer.alloc(0)];
  yield ['four bytes', Buffer.from([1, 2, 3, 4])];
  yield ['bare indefinite length', Buffer.from([0x30, 0x80])];
  yield [
    'unparseable embedded certificate',
    forge({
      certificates: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]),
      payload: payloadDated(SIGNING_TIME),
    }),
  ];
  yield [
    'creation date without a designator',
    forge({ payload: payloadDated('2025-12-26T17:43:07') }),
  ];
  for (const [what, signedAttrs] of DEGENERATE_SIGNED_ATTRS) {
    yield [
      `signed attributes: ${what}`,
      forge({ payload: payloadDated(SIGNING_TIME), signedAttrs }),
    ];
  }
}

const nodeVerifier = node.createVerifier(
  node.createConfig({ roots: [...node.defaultConfig().roots.map((r) => r.raw), SHARED_ROOT] }),
);
const webVerifier = web.createVerifier(
  await web.createConfig({
    roots: [...(await web.defaultConfig()).roots.map((r) => r.raw), new Uint8Array(SHARED_ROOT)],
  }),
);

test('a forged receipt never earns more than a pre-signature verdict, in either build', async () => {
  let checked = 0;
  for (const [what, input] of forgedCorpus()) {
    const base64 = input.toString('base64');
    for (const [name, verifier] of [
      ['node', nodeVerifier],
      ['web', webVerifier],
    ]) {
      const result = await verifier.verifyReceipt(base64);
      assert.equal(result.verified, false, `${name}: ${what} verified`);
      assert.ok(
        PRE_SIGNATURE_REASONS.has(result.failure.reason),
        `${name}: ${what} answered ${result.failure.reason}: ${result.failure.message}`,
      );
      const body = JSON.stringify({ 'receipt-data': base64 });
      const status = JSON.parse(
        await verifier.verifyReceiptEndpoint(node.Environment.SANDBOX, body),
      ).status;
      assert.notEqual(status, 21009, `${name}: ${what} answered 21009 at the endpoint`);
    }
    checked += 1;
  }
  assert.ok(checked >= 9, `only ${checked} inputs`);
});

/**
 * The one tolerated disagreement between the builds: a certificate corrupted
 * somewhere the two parsers look at differently. OpenSSL decodes the whole
 * X.509 template at parse time; the repo's DER reader decodes only the
 * fields verification needs. Neither build ever accepts such a receipt, and
 * the count is asserted so a new class of divergence, or a growing one,
 * fails this test.
 */
const CORRUPT_CERTIFICATE_REASONS = new Set([
  'MALFORMED',
  'UNTRUSTED_CHAIN',
  'INVALID_CERTIFICATE',
]);
const MAX_TOLERATED_DIVERGENCES = 5;

test('web and Node builds agree over a corpus of mutated receipts', async () => {
  let checked = 0;
  const divergences = [];
  const corpus = [
    ...mutations('genuine sandbox receipt', GENUINE, 97),
    ...mutations('shared receipt fixture', SHARED, 97),
    // The 79 KB legacy receipt is sampled coarsely: it is here for its SHA-1
    // chain, and a 97-byte stride over it would be 800 more RSA checks.
    ...mutations('genuine legacy receipt', LEGACY, 997),
  ];
  const original = new Map();
  for (const [what, input, source] of corpus) {
    const base64 = input.toString('base64');
    const fromNode = nodeVerifier.verifyReceipt(base64);
    const fromWeb = await webVerifier.verifyReceipt(base64);
    // A flip inside a stranger certificate, which the unsigned bag may
    // carry and verification ignores, leaves the
    // receipt genuine. Then both builds must accept it and return the same
    // payload; otherwise both must refuse it.
    assert.equal(
      fromWeb.verified,
      fromNode.verified,
      `${what}: the builds disagree on accepting it`,
    );
    if (fromNode.verified) {
      assert.equal(fromWeb.payload.toJson(), fromNode.payload.toJson(), what);
      // And the payload is exactly what the unmutated receipt carries.
      if (!original.has(source)) {
        original.set(
          source,
          nodeVerifier.verifyReceipt(source.toString('base64')).payload.toJson(),
        );
      }
      assert.equal(fromNode.payload.toJson(), original.get(source), what);
      checked += 1;
      continue;
    }
    for (const [name, result] of [
      ['node', fromNode],
      ['web', fromWeb],
    ]) {
      assert.notEqual(result.failure.reason, 'INTERNAL_ERROR', `${name}: ${what}`);
    }
    if (
      fromWeb.failure.reason !== fromNode.failure.reason ||
      fromWeb.failure.message !== fromNode.failure.message
    ) {
      assert.ok(
        CORRUPT_CERTIFICATE_REASONS.has(fromWeb.failure.reason) &&
          CORRUPT_CERTIFICATE_REASONS.has(fromNode.failure.reason),
        `${what}: node ${fromNode.failure.reason} vs web ${fromWeb.failure.reason}`,
      );
      divergences.push(`${what}: node ${fromNode.failure.reason} vs web ${fromWeb.failure.reason}`);
    }
    checked += 1;
  }
  // The corpus is generated, so a bug that emptied it would otherwise pass.
  assert.ok(checked > 1000, `only ${checked} inputs`);
  assert.ok(
    divergences.length <= MAX_TOLERATED_DIVERGENCES,
    `${divergences.length} divergent verdicts:\n${divergences.join('\n')}`,
  );
});

// --- attribute types a trusted signer signed --------------------------------

// The payload grammar is read only after the chain and the signature pass, so
// these payloads are signed for real under a PKI minted here.
const PKI = mintReceiptPki();

const payloadWithAttributeType = (typeBytes) =>
  tlv(
    SET,
    tlv(
      SEQUENCE,
      tlv(INTEGER, Buffer.from([12])),
      tlv(INTEGER, Buffer.from([1])),
      tlv(OCTET_STRING, tlv(IA5_STRING, Buffer.from(SIGNING_TIME, 'ascii'))),
    ),
    tlv(
      SEQUENCE,
      tlv(INTEGER, Buffer.from(typeBytes)),
      tlv(INTEGER, Buffer.from([1])),
      tlv(OCTET_STRING),
    ),
  );

// 0x80 is the smallest leading byte of a negative two's-complement INTEGER,
// and nine octets is past any 64-bit value. Neither is an attribute type, so
// Apple-signed content carrying one does not parse. The shared cases cover
// 2^31 and a type that truncates onto a modelled one.
for (const [label, typeBytes] of [
  ['a negative INTEGER', [0x80]],
  ['nine octets', [0, 0, 0, 0, 0, 0, 0, 0, 1]],
]) {
  test(`an attribute type of ${label} makes signed content UNREADABLE_PAYLOAD in both builds`, async () => {
    const base64 = PKI.sign(payloadWithAttributeType(typeBytes)).toString('base64');
    const fromNode = node
      .createVerifier(node.createConfig({ roots: [PKI.root] }))
      .verifyReceipt(base64);
    const fromWeb = await web
      .createVerifier(await web.createConfig({ roots: [new Uint8Array(PKI.root)] }))
      .verifyReceipt(base64);
    for (const [name, result] of [
      ['node', fromNode],
      ['web', fromWeb],
    ]) {
      assert.equal(
        result.failure?.reason,
        'UNREADABLE_PAYLOAD',
        `${name}: ${result.failure?.message}`,
      );
      // The parser's own error explains what Apple signed that did not parse.
      assert.ok(result.failure.cause !== undefined, `${name}: no cause`);
    }
    assert.equal(fromWeb.failure.message, fromNode.failure.message);
  });
}

// --- the certificate bound -----------------------------------------------------

test('the certificate bound is above every genuine receipt', () => {
  // Read rather than asserted: the bound (10, docs/design/0.7-api.md) is
  // only safe while it stays above the largest bag Apple actually ships.
  const BOUND = 10;
  for (const fixture of [
    'receipt-sandbox-g5',
    'receipt-sandbox-legacy',
    'receipt-xcode-with-purchases',
  ]) {
    // The library's own reader: the Xcode receipt is BER with indefinite lengths.
    const signedData = parse(publicReceipt(fixture)).children[1].children[0].children;
    const count = signedData.slice(3, signedData.length - 1).find((n) => n.tag === Tag.CONTEXT_0)
      .children.length;
    assert.ok(count > 0 && count < BOUND, `${fixture} embeds ${count} certificates`);
  }
});

// --- key types WebCrypto cannot import ---------------------------------------

const b64url = (buffer) => Buffer.from(buffer).toString('base64url');
const dsaKey = () => generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 });
const ecKey = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });

// A v3 certificate signed with ECDSA P-256, for the JWS below.
const BOOLEAN = 0x01;
const BIT_STRING = 0x03;
const NULL = 0x05;
const UTF8_STRING = 0x0c;
const UTC_TIME = 0x17;
const CONTEXT_3 = 0xa3;
const oid = (hex) => tlv(OID, Buffer.from(hex, 'hex'));
const SHA256_ECDSA = tlv(SEQUENCE, oid('2a8648ce3d040302'));
const nameOf = (commonName) =>
  tlv(SEQUENCE, tlv(SET, tlv(SEQUENCE, oid('550403'), tlv(UTF8_STRING, Buffer.from(commonName)))));
const VALIDITY = tlv(
  SEQUENCE,
  tlv(UTC_TIME, Buffer.from('240101000000Z', 'ascii')),
  tlv(UTC_TIME, Buffer.from('491231235959Z', 'ascii')),
);
const CA_TRUE = tlv(
  SEQUENCE,
  oid('551d13'),
  tlv(BOOLEAN, Buffer.from([0xff])),
  tlv(OCTET_STRING, tlv(SEQUENCE, tlv(BOOLEAN, Buffer.from([0xff])))),
);
const marker = (hex) => tlv(SEQUENCE, oid(hex), tlv(OCTET_STRING, tlv(NULL)));
const LEAF_OID = '2a864886f76364060b01';
const WWDR_OID = '2a864886f76364060201';
let serial = 1;
function ecCertificate({ subject, issuer, subjectKey, issuerKey, extensions }) {
  const tbs = tlv(
    SEQUENCE,
    tlv(CONTEXT_0, tlv(INTEGER, Buffer.from([2]))),
    tlv(INTEGER, Buffer.from([serial++])),
    SHA256_ECDSA,
    nameOf(issuer),
    VALIDITY,
    nameOf(subject),
    subjectKey.export({ type: 'spki', format: 'der' }),
    tlv(CONTEXT_3, tlv(SEQUENCE, ...extensions)),
  );
  return tlv(
    SEQUENCE,
    tbs,
    SHA256_ECDSA,
    tlv(BIT_STRING, Buffer.from([0]), cryptoSign('sha256', tbs, issuerKey)),
  );
}

test('a JWS whose x5c[2] carries a key WebCrypto cannot import verifies in both builds', async () => {
  // x5c[2] is never used for anything: the chain ends at the caller's
  // pinned root. A web build that tried to import its key (here DSA, which
  // WebCrypto has no algorithm for) would refuse a genuine JWS.
  const [root, intermediate, leaf] = [ecKey(), ecKey(), ecKey()];
  const stranger = dsaKey();
  const rootDer = ecCertificate({
    subject: 'Key Types Root',
    issuer: 'Key Types Root',
    subjectKey: root.publicKey,
    issuerKey: root.privateKey,
    extensions: [CA_TRUE],
  });
  const chain = [
    ecCertificate({
      subject: 'Key Types Leaf',
      issuer: 'Key Types CA',
      subjectKey: leaf.publicKey,
      issuerKey: intermediate.privateKey,
      extensions: [marker(LEAF_OID)],
    }),
    ecCertificate({
      subject: 'Key Types CA',
      issuer: 'Key Types Root',
      subjectKey: intermediate.publicKey,
      issuerKey: root.privateKey,
      extensions: [CA_TRUE, marker(WWDR_OID)],
    }),
    ecCertificate({
      subject: 'Key Types Stranger Root',
      issuer: 'Key Types Root',
      subjectKey: stranger.publicKey,
      issuerKey: root.privateKey,
      extensions: [CA_TRUE],
    }),
  ];
  // The premise: the third entry really carries a DSA key.
  assert.equal(new X509Certificate(chain[2]).publicKey.asymmetricKeyType, 'dsa');
  const header = b64url(
    JSON.stringify({ alg: 'ES256', x5c: chain.map((der) => der.toString('base64')) }),
  );
  const claims = b64url(
    JSON.stringify({ transactionId: '1', signedDate: Date.parse(SIGNING_TIME) }),
  );
  const signature = cryptoSign('sha256', Buffer.from(`${header}.${claims}`), {
    key: leaf.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  const jws = `${header}.${claims}.${b64url(signature)}`;

  const fromNode = node
    .createVerifier(node.createConfig({ roots: [rootDer] }))
    .verifySignedData(jws);
  const fromWeb = await web
    .createVerifier(await web.createConfig({ roots: [new Uint8Array(rootDer)] }))
    .verifySignedData(jws);
  assert.equal(fromNode.verified, true, fromNode.failure?.message);
  assert.equal(fromWeb.verified, true, fromWeb.failure?.message);
  assert.equal(JSON.parse(fromWeb.payload.json).transactionId, '1');
});

test('a receipt signer with a key WebCrypto cannot import gets one verdict from both builds', async () => {
  // Any signer algorithm is allowed (#160), but
  // WebCrypto has no DSA. The key is used only after its chain and markers
  // pass, and the signature here is empty, so the honest verdict in both
  // builds is INVALID_SIGNATURE, never a throw or a certificate verdict.
  const [root, intermediate] = [ecKey(), ecKey()];
  const signer = dsaKey();
  const rootDer = ecCertificate({
    subject: 'DSA Signer Root',
    issuer: 'DSA Signer Root',
    subjectKey: root.publicKey,
    issuerKey: root.privateKey,
    extensions: [CA_TRUE],
  });
  const intermediateDer = ecCertificate({
    subject: 'DSA Signer CA',
    issuer: 'DSA Signer Root',
    subjectKey: intermediate.publicKey,
    issuerKey: root.privateKey,
    extensions: [CA_TRUE, marker(WWDR_OID)],
  });
  const leafSerial = serial;
  const leafDer = ecCertificate({
    subject: 'DSA Signer',
    issuer: 'DSA Signer CA',
    subjectKey: signer.publicKey,
    issuerKey: intermediate.privateKey,
    extensions: [marker(LEAF_OID)],
  });
  assert.equal(new X509Certificate(leafDer).publicKey.asymmetricKeyType, 'dsa');
  const sid = tlv(SEQUENCE, nameOf('DSA Signer CA'), tlv(INTEGER, Buffer.from([leafSerial])));
  const receipt = tlv(
    SEQUENCE,
    tlv(OID, OID_SIGNED_DATA),
    tlv(
      CONTEXT_0,
      tlv(
        SEQUENCE,
        tlv(INTEGER, Buffer.from([1])),
        tlv(SET),
        tlv(
          SEQUENCE,
          tlv(OID, OID_DATA),
          tlv(CONTEXT_0, tlv(OCTET_STRING, payloadDated(SIGNING_TIME))),
        ),
        tlv(CONTEXT_0, leafDer, intermediateDer),
        tlv(
          SET,
          tlv(
            SEQUENCE,
            tlv(INTEGER, Buffer.from([1])),
            sid,
            tlv(SEQUENCE, oid('608648016503040201'), tlv(NULL)),
            tlv(SEQUENCE, oid('2a8648ce380403')),
            tlv(OCTET_STRING),
          ),
        ),
      ),
    ),
  ).toString('base64');

  const fromNode = node
    .createVerifier(node.createConfig({ roots: [rootDer] }))
    .verifyReceipt(receipt);
  const fromWeb = await web
    .createVerifier(await web.createConfig({ roots: [new Uint8Array(rootDer)] }))
    .verifyReceipt(receipt);
  assert.equal(fromNode.failure?.reason, 'INVALID_SIGNATURE', fromNode.failure?.message);
  assert.equal(fromWeb.failure?.reason, 'INVALID_SIGNATURE', fromWeb.failure?.message);
});
