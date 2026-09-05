// Key-type parity between the two builds. The Node build reads a public key
// with OpenSSL, which builds far more key types than the web build's SPKI →
// JWK converter does, so every place the web build converts a key is a place
// it can refuse a certificate its twin accepts. Both cases here are keys
// OpenSSL reads perfectly well and WebCrypto has no import for at all:
//
//   - a DSA-keyed receipt SIGNER, which is a readable key of the wrong kind
//     and therefore a verdict about the SIGNATURE (INVALID_SIGNATURE), not
//     about the certificate — the reading dotnet, go and php already share
//     (receipt/reject-signer-on-an-unimplemented-curve turns on the
//     distinction: an unbuildable key is INVALID_CERTIFICATE, a readable
//     non-RSA one is not);
//   - a DSA-keyed x5c[2], which must verify, because the third entry is
//     never trusted and never compared: it has to BE a certificate and
//     nothing more (transaction/reject-x5c-root-that-is-not-a-certificate).
//
// DSA is the vehicle for both because Node mints it (`generateKeyPairSync`)
// and the web build converts neither DSA nor anything else outside RSA and
// EC, so it is the shortest input that separates "unreadable" from "not
// ours".
import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate, generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

// --- minimal DER writer (definite lengths), as certificate-flood.test.js uses

function tlv(tag, ...parts) {
  const contents = Buffer.concat(parts);
  const n = contents.length;
  const length =
    n < 0x80
      ? [n]
      : n < 0x100
        ? [0x81, n]
        : n < 0x10000
          ? [0x82, n >> 8, n & 0xff]
          : [0x83, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from([tag, ...length]), contents]);
}

const BOOLEAN = 0x01;
const INTEGER = 0x02;
const BIT_STRING = 0x03;
const OCTET_STRING = 0x04;
const NULL = 0x05;
const OID = 0x06;
const UTF8_STRING = 0x0c;
const IA5_STRING = 0x16;
const UTC_TIME = 0x17;
const SEQUENCE = 0x30;
const SET = 0x31;
const CONTEXT_0 = 0xa0;
const CONTEXT_3 = 0xa3;

const oid = (dotted) => tlv(OID, encodeOid(dotted));

/** Dotted decimal → DER OID contents. */
function encodeOid(dotted) {
  const parts = dotted.split('.').map(Number);
  const bytes = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [part & 0x7f];
    let rest = part >>> 7;
    while (rest > 0) {
      chunk.unshift((rest & 0x7f) | 0x80);
      rest >>>= 7;
    }
    bytes.push(...chunk);
  }
  return Buffer.from(bytes);
}

const SHA256_RSA = tlv(SEQUENCE, oid('1.2.840.113549.1.1.11'), tlv(NULL));
// ecdsa-with-SHA256 takes no parameters at all, absent rather than NULL.
const SHA256_ECDSA = tlv(SEQUENCE, oid('1.2.840.10045.4.3.2'));

const name = (commonName) =>
  tlv(
    SEQUENCE,
    tlv(SET, tlv(SEQUENCE, oid('2.5.4.3'), tlv(UTF8_STRING, Buffer.from(commonName, 'utf8')))),
  );

// Covers both the receipt creation date below and "now", so a chain judged
// at either instant is inside it.
const VALIDITY = tlv(
  SEQUENCE,
  tlv(UTC_TIME, Buffer.from('200101000000Z', 'ascii')),
  tlv(UTC_TIME, Buffer.from('491231235959Z', 'ascii')),
);

const CA_TRUE = tlv(
  SEQUENCE,
  oid('2.5.29.19'),
  tlv(BOOLEAN, Buffer.from([0xff])),
  tlv(OCTET_STRING, tlv(SEQUENCE, tlv(BOOLEAN, Buffer.from([0xff])))),
);
/** An Apple marker extension: the OID, and a DER NULL for a value. */
const marker = (dotted) => tlv(SEQUENCE, oid(dotted), tlv(OCTET_STRING, tlv(NULL)));

let nextSerial = 1;

/**
 * A v3 certificate, signed for real: both builds check this signature while
 * walking the chain, so a hand-waved one would fail as INVALID_CHAIN and
 * never reach the checks these tests are about.
 */
function certificate({ subject, issuer, subjectKey, issuerKey, signatureAlgorithm, extensions }) {
  const serial = Buffer.from([nextSerial++]);
  const tbs = tlv(
    SEQUENCE,
    tlv(CONTEXT_0, tlv(INTEGER, Buffer.from([2]))),
    tlv(INTEGER, serial),
    signatureAlgorithm,
    name(issuer),
    VALIDITY,
    name(subject),
    subjectKey.export({ type: 'spki', format: 'der' }),
    tlv(CONTEXT_3, tlv(SEQUENCE, ...extensions)),
  );
  return {
    der: tlv(
      SEQUENCE,
      tbs,
      signatureAlgorithm,
      tlv(BIT_STRING, Buffer.from([0]), cryptoSign('sha256', tbs, issuerKey)),
    ),
    // issuerAndSerialNumber, which is how a SignerInfo names its signer.
    sid: tlv(SEQUENCE, name(issuer), tlv(INTEGER, serial)),
  };
}

const rsaKey = () => generateKeyPairSync('rsa', { modulusLength: 2048 });
const ecKey = () => generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const dsaKey = () => generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 });

// --- the receipt: a signer whose key reads and is not RSA -----------------

const RECEIPT_SIGNER_OID = '1.2.840.113635.100.6.11.1';
const CREATED = '2025-12-26T17:43:07Z';

/** A receipt payload carrying the two attributes these tests need. */
const payload = () =>
  tlv(
    SET,
    tlv(
      SEQUENCE,
      tlv(INTEGER, Buffer.from([2])),
      tlv(INTEGER, Buffer.from([1])),
      tlv(OCTET_STRING, tlv(UTF8_STRING, Buffer.from('com.example.app', 'utf8'))),
    ),
    tlv(
      SEQUENCE,
      tlv(INTEGER, Buffer.from([12])),
      tlv(INTEGER, Buffer.from([1])),
      tlv(OCTET_STRING, tlv(IA5_STRING, Buffer.from(CREATED, 'ascii'))),
    ),
  );

/**
 * A CMS SignedData carrying `certificates` and naming `sid` as its signer.
 * The signature bytes are empty: every check these tests make happens before
 * the signature is examined, and the point of the receipt case is that the
 * verdict arrives WITHOUT the signature ever being checkable.
 */
function receipt(certificates, sid) {
  return tlv(
    SEQUENCE,
    oid('1.2.840.113549.1.7.2'),
    tlv(
      CONTEXT_0,
      tlv(
        SEQUENCE,
        tlv(INTEGER, Buffer.from([1])),
        tlv(SET),
        tlv(SEQUENCE, oid('1.2.840.113549.1.7.1'), tlv(CONTEXT_0, tlv(OCTET_STRING, payload()))),
        tlv(CONTEXT_0, Buffer.concat(certificates)),
        tlv(
          SET,
          tlv(
            SEQUENCE,
            tlv(INTEGER, Buffer.from([1])),
            sid,
            tlv(SEQUENCE, oid('2.16.840.1.101.3.4.2.1'), tlv(NULL)),
            tlv(SEQUENCE),
            tlv(OCTET_STRING, Buffer.alloc(0)),
          ),
        ),
      ),
    ),
  );
}

/** Root, intermediate and a signer leaf whose key is the DSA one. */
function dsaSignerReceipt() {
  const root = rsaKey();
  const intermediateKey = rsaKey();
  const signerKey = dsaKey();
  const rootCert = certificate({
    subject: 'Key Types Root',
    issuer: 'Key Types Root',
    subjectKey: root.publicKey,
    issuerKey: root.privateKey,
    signatureAlgorithm: SHA256_RSA,
    extensions: [CA_TRUE],
  });
  const intermediate = certificate({
    subject: 'Key Types CA',
    issuer: 'Key Types Root',
    subjectKey: intermediateKey.publicKey,
    issuerKey: root.privateKey,
    signatureAlgorithm: SHA256_RSA,
    extensions: [CA_TRUE],
  });
  const signer = certificate({
    subject: 'Key Types Signer',
    issuer: 'Key Types CA',
    subjectKey: signerKey.publicKey,
    issuerKey: intermediateKey.privateKey,
    signatureAlgorithm: SHA256_RSA,
    extensions: [marker(RECEIPT_SIGNER_OID)],
  });
  return {
    der: receipt([signer.der, intermediate.der], signer.sid),
    root: rootCert.der,
    signer: signer.der,
  };
}

async function verdict(run) {
  try {
    const value = await run();
    return { ok: true, value };
  } catch (error) {
    return { name: error?.constructor?.name, reason: error?.reason, message: error?.message };
  }
}

test('a receipt signer with a readable non-RSA key is a signature verdict in both builds', async () => {
  const { der, root, signer } = dsaSignerReceipt();

  // The premise: OpenSSL really does read this key, so "unreadable" is not
  // an available verdict for either build to arrive at honestly. Without
  // this the assertions below could be agreeing for the wrong reason.
  assert.equal(new X509Certificate(signer).publicKey.asymmetricKeyType, 'dsa');

  const fromNode = await verdict(() => node.verifyReceiptCore(der, [root]));
  const fromWeb = await verdict(() =>
    web.verifyReceiptCore(new Uint8Array(der), [new Uint8Array(root)]),
  );

  assert.deepEqual(fromNode, fromWeb);
  assert.equal(fromNode.reason, 'INVALID_SIGNATURE');
  assert.match(fromNode.message, /receipt signer key is not RSA/);
});

// --- the JWS: a third x5c entry whose key is not one this build builds ----

const LEAF_OID = '1.2.840.113635.100.6.11.1';
const INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

const b64url = (buffer) => Buffer.from(buffer).toString('base64url');

/** A JWS whose x5c[2] is a certificate carrying a DSA key. */
function dsaRootJws() {
  const rootKeyPair = ecKey();
  const intermediateKeyPair = ecKey();
  const leafKeyPair = ecKey();
  const strangerKey = dsaKey();
  const rootCert = certificate({
    subject: 'JWS Key Types Root',
    issuer: 'JWS Key Types Root',
    subjectKey: rootKeyPair.publicKey,
    issuerKey: rootKeyPair.privateKey,
    signatureAlgorithm: SHA256_ECDSA,
    extensions: [CA_TRUE],
  });
  const intermediate = certificate({
    subject: 'JWS Key Types CA',
    issuer: 'JWS Key Types Root',
    subjectKey: intermediateKeyPair.publicKey,
    issuerKey: rootKeyPair.privateKey,
    signatureAlgorithm: SHA256_ECDSA,
    extensions: [CA_TRUE, marker(INTERMEDIATE_OID)],
  });
  const leaf = certificate({
    subject: 'JWS Key Types Leaf',
    issuer: 'JWS Key Types CA',
    subjectKey: leafKeyPair.publicKey,
    issuerKey: intermediateKeyPair.privateKey,
    signatureAlgorithm: SHA256_ECDSA,
    extensions: [marker(LEAF_OID)],
  });
  // The third entry: a certificate in every structural respect, carrying a
  // key neither build ever uses, because the third entry's key is never used
  // for anything at all.
  const stranger = certificate({
    subject: 'JWS Key Types Stranger Root',
    issuer: 'JWS Key Types Root',
    subjectKey: strangerKey.publicKey,
    issuerKey: rootKeyPair.privateKey,
    signatureAlgorithm: SHA256_ECDSA,
    extensions: [CA_TRUE],
  });

  const header = b64url(
    Buffer.from(
      JSON.stringify({
        alg: 'ES256',
        x5c: [leaf.der, intermediate.der, stranger.der].map((der) => der.toString('base64')),
      }),
      'utf8',
    ),
  );
  const claims = b64url(
    Buffer.from(
      JSON.stringify({
        bundleId: 'com.example.app',
        environment: 'Sandbox',
        transactionId: '1',
        signedDate: Date.parse(CREATED),
      }),
      'utf8',
    ),
  );
  const signature = cryptoSign('sha256', Buffer.from(`${header}.${claims}`, 'ascii'), {
    key: leafKeyPair.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return { jws: `${header}.${claims}.${b64url(signature)}`, root: rootCert.der };
}

test('a JWS whose x5c[2] carries a key neither build imports verifies in both', async () => {
  const { jws, root } = dsaRootJws();
  const options = {
    bundleId: 'com.example.app',
    acceptedEnvironments: ['Sandbox'],
  };
  const fromNode = await verdict(() =>
    new node.JwsVerifier({ ...options, trustedRoots: [root] }).verifyTransaction(jws),
  );
  const fromWeb = await verdict(() =>
    new web.JwsVerifier({ ...options, trustedRoots: [new Uint8Array(root)] }).verifyTransaction(
      jws,
    ),
  );

  assert.deepEqual(fromNode.reason, fromWeb.reason);
  assert.equal(fromNode.ok, true, `Node build rejected it: ${fromNode.message}`);
  assert.equal(fromWeb.ok, true, `web build rejected it: ${fromWeb.message}`);
  assert.equal(fromNode.value.transactionId, '1');
  assert.equal(fromWeb.value.transactionId, '1');
});
