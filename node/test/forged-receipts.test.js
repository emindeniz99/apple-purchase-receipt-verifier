import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  ReceiptVerifier, VerificationError, VerifyReceiptEndpoint, appleReceiptRoots,
} from '../dist/index.js';

// Forged CMS blobs built from a genuine receipt's certificates and SignerInfo
// identifier: everything an attacker can reach without a private key. The
// donor is the public sandbox receipt, so the chain and purpose checks pass
// against the real pinned roots and the crash sites below are actually
// reached.
const GENUINE = Buffer.from(readFileSync(fileURLToPath(
  new URL('../../fixtures/public-receipts/receipt-sandbox-g5.b64', import.meta.url)),
'ascii').trim(), 'base64');
const BUNDLE = 'dev.bonzer.weeka.app';
// Inside the donor leaf's validity window (Jul 2024 - Aug 2026); the chain is
// judged at the receipt's creation date, so a forgery must pin one.
const SIGNING_TIME = '2025-12-26T17:43:07Z';

// --- minimal DER reader/writer (definite lengths, as the donor uses) ----

function readTlv(buf, off) {
  const tag = buf[off];
  let pos = off + 1;
  let length = buf[pos];
  pos += 1;
  if (length >= 0x80) {
    const count = length & 0x7f;
    length = 0;
    for (let i = 0; i < count; i++) {
      length = length * 256 + buf[pos + i];
    }
    pos += count;
  }
  return { contents: buf.subarray(pos, pos + length), raw: buf.subarray(off, pos + length), end: pos + length };
}

function items(buf) {
  const nodes = [];
  let pos = 0;
  while (pos < buf.length) {
    const node = readTlv(buf, pos);
    nodes.push(node);
    pos = node.end;
  }
  return nodes;
}

function tlv(tag, ...parts) {
  const contents = Buffer.concat(parts);
  const n = contents.length;
  const length = n < 0x80 ? [n] : n < 0x100 ? [0x81, n] : [0x82, n >> 8, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...length]), contents]);
}

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

const donorSignedData = items(readTlv(items(readTlv(GENUINE, 0).contents)[1].contents, 0).contents);
const donorCertificates = donorSignedData[3].contents;
const donorSignerInfo = items(readTlv(donorSignedData[4].contents, 0).contents);
// issuerAndSerialNumber of the real leaf, so findSignerCert picks it out.
const donorSid = donorSignerInfo[1].raw;
const donorDigestAlgorithm = donorSignerInfo[2].raw;
const donorSignature = donorSignerInfo[4].raw;

function forge({ certificates = donorCertificates, payload, signedAttrs = null }) {
  const signerFields = [tlv(INTEGER, Buffer.from([1])), donorSid, donorDigestAlgorithm];
  if (signedAttrs !== null) {
    signerFields.push(signedAttrs);
  }
  signerFields.push(tlv(SEQUENCE), donorSignature);
  return tlv(SEQUENCE,
    tlv(OID, OID_SIGNED_DATA),
    tlv(CONTEXT_0, tlv(SEQUENCE,
      tlv(INTEGER, Buffer.from([1])),
      tlv(SET),
      tlv(SEQUENCE, tlv(OID, OID_DATA), tlv(CONTEXT_0, tlv(OCTET_STRING, payload))),
      tlv(CONTEXT_0, certificates),
      tlv(SET, tlv(SEQUENCE, ...signerFields)))));
}

/** Receipt payload carrying just attribute 12 (creation date). */
function payloadDated(text) {
  return tlv(SET, tlv(SEQUENCE,
    tlv(INTEGER, Buffer.from([12])),
    tlv(INTEGER, Buffer.from([1])),
    tlv(OCTET_STRING, tlv(IA5_STRING, Buffer.from(text, 'ascii')))));
}

const messageDigestAttribute = (value) => tlv(SEQUENCE, tlv(OID, OID_MESSAGE_DIGEST), value);

// Signed-attribute shapes whose walk runs off the end of a child list.
const DEGENERATE_SIGNED_ATTRS = [
  ['[0] wrapping a primitive', tlv(CONTEXT_0, tlv(INTEGER, Buffer.from([0])))],
  ['attribute carrying only the OID', tlv(CONTEXT_0, tlv(SEQUENCE, tlv(OID, OID_MESSAGE_DIGEST)))],
  ['primitive attribute value', tlv(CONTEXT_0, messageDigestAttribute(tlv(INTEGER, Buffer.from([0]))))],
  ['empty attribute value SET', tlv(CONTEXT_0, messageDigestAttribute(tlv(SET)))],
];

const UNPARSEABLE_CERTIFICATE = forge({
  certificates: Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]),
  payload: payloadDated(SIGNING_TIME),
});
const NAIVE_CREATION_DATE = forge({ payload: payloadDated('2025-12-26T17:43:07') });

const verifier = () => new ReceiptVerifier({ trustedRoots: appleReceiptRoots(), bundleId: BUNDLE });

test('reports an unparseable embedded certificate as INVALID_RECEIPT_FORMAT', () => {
  // An OpenSSL Error carries a `.reason` of its own ('no start line'), so
  // letting one escape hands the attacker a foreign value on the property the
  // whole public contract is discriminated on.
  assert.throws(() => verifier().verify(UNPARSEABLE_CERTIFICATE), (e) => {
    assert.ok(e instanceof VerificationError, `escaped as ${e.name}: ${e.message}`);
    assert.equal(e.reason, 'INVALID_RECEIPT_FORMAT');
    return true;
  });
  // COMPARISON.md promises 21002 for malformed input; 21009 would say the
  // endpoint hit an exception it did not expect.
  const endpoint = new VerifyReceiptEndpoint({
    trustedRoots: appleReceiptRoots(), environment: 'Sandbox',
  });
  assert.equal(endpoint.verifyReceipt({
    'receipt-data': UNPARSEABLE_CERTIFICATE.toString('base64'),
  }).status, 21002);
});

test('reports degenerate signed attributes as INVALID_RECEIPT_FORMAT', () => {
  for (const [what, signedAttrs] of DEGENERATE_SIGNED_ATTRS) {
    const forged = forge({ payload: payloadDated(SIGNING_TIME), signedAttrs });
    assert.throws(() => verifier().verify(forged), (e) => {
      assert.ok(e instanceof VerificationError, `${what} escaped as ${e.name}: ${e.message}`);
      assert.equal(e.reason, 'INVALID_RECEIPT_FORMAT', what);
      return true;
    }, what);
  }
});

test('rejects a receipt date with no timezone designator', () => {
  // Without a designator the instant depends on the server's local timezone,
  // so the same receipt would verify on one host and fail on another; Java and
  // Swift reject it, and this keeps all four implementations in agreement.
  assert.throws(() => verifier().verify(NAIVE_CREATION_DATE), (e) => {
    assert.equal(e.reason, 'INVALID_RECEIPT_FORMAT');
    assert.match(e.message, /unparseable receipt date: 2025-12-26T17:43:07$/);
    return true;
  });
});

function* hostileCorpus() {
  yield ['empty', Buffer.alloc(0)];
  yield ['four bytes', Buffer.from([1, 2, 3, 4])];
  yield ['bare indefinite length', Buffer.from([0x30, 0x80])];
  yield ['unparseable embedded certificate', UNPARSEABLE_CERTIFICATE];
  yield ['naive creation date', NAIVE_CREATION_DATE];
  for (const [what, signedAttrs] of DEGENERATE_SIGNED_ATTRS) {
    yield [`signed attributes: ${what}`, forge({ payload: payloadDated(SIGNING_TIME), signedAttrs })];
  }
  for (let cut = 1; cut < GENUINE.length; cut += 64) {
    yield [`truncated to ${cut} bytes`, GENUINE.subarray(0, cut)];
  }
  for (let at = 0; at < GENUINE.length; at += 97) {
    const flipped = Buffer.from(GENUINE);
    flipped[at] ^= 0xff;
    yield [`byte ${at} flipped`, flipped];
  }
}

test('nothing but VerificationError escapes verify() over a hostile corpus', () => {
  const receiptVerifier = verifier();
  const endpoint = new VerifyReceiptEndpoint({
    trustedRoots: appleReceiptRoots(), environment: 'Sandbox',
  });
  for (const [what, input] of hostileCorpus()) {
    try {
      receiptVerifier.verify(input);
    } catch (e) {
      assert.ok(e instanceof VerificationError, `${what} escaped as ${e.name}: ${e.message}`);
    }
    assert.notEqual(endpoint.verifyReceipt({ 'receipt-data': input.toString('base64') }).status,
      21009, what);
  }
});
