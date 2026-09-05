import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { generateKeyPairSync, sign as cryptoSign } from 'node:crypto';
import { ReceiptVerifier, appleReceiptRoots } from '../dist/index.js';
// The DER reader the library itself uses; the Xcode receipt is BER, not DER.
import { Tag, parse } from '../dist/der.js';

// Mirrors MAX_EMBEDDED_CERTIFICATES in src/receipt.ts.
const LIMIT = 10;

// --- minimal DER writer (definite lengths), as forged-receipts.test.js uses --

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

const OID_SIGNED_DATA = Buffer.from('2a864886f70d010702', 'hex');
const OID_DATA = Buffer.from('2a864886f70d010701', 'hex');
const OID_SHA256_RSA = Buffer.from('2a864886f70d01010b', 'hex');
const OID_SHA256 = Buffer.from('608648016503040201', 'hex');
const OID_COMMON_NAME = Buffer.from('550403', 'hex');
const OID_BASIC_CONSTRAINTS = Buffer.from('551d13', 'hex');

const SHA256_RSA = tlv(SEQUENCE, tlv(OID, OID_SHA256_RSA), tlv(NULL));
const name = (commonName) =>
  tlv(
    SEQUENCE,
    tlv(
      SET,
      tlv(SEQUENCE, tlv(OID, OID_COMMON_NAME), tlv(UTF8_STRING, Buffer.from(commonName, 'utf8'))),
    ),
  );
// Covers the receipt creation date below, which is what chain validity is judged at.
const VALIDITY = tlv(
  SEQUENCE,
  tlv(UTC_TIME, Buffer.from('200101000000Z', 'ascii')),
  tlv(UTC_TIME, Buffer.from('300101000000Z', 'ascii')),
);
const CA_TRUE = tlv(
  CONTEXT_3,
  tlv(
    SEQUENCE,
    tlv(
      SEQUENCE,
      tlv(OID, OID_BASIC_CONSTRAINTS),
      tlv(BOOLEAN, Buffer.from([0xff])),
      tlv(OCTET_STRING, tlv(SEQUENCE, tlv(BOOLEAN, Buffer.from([0xff])))),
    ),
  ),
);

let nextSerial = 1;

/** A v3 certificate, signed for real so the path walk runs the RSA check on it. */
function certificate({ subject, issuer, subjectKey, issuerKey, ca }) {
  const serial = Buffer.from([nextSerial++]);
  const tbs = tlv(
    SEQUENCE,
    tlv(CONTEXT_0, tlv(INTEGER, Buffer.from([2]))),
    tlv(INTEGER, serial),
    SHA256_RSA,
    name(issuer),
    VALIDITY,
    name(subject),
    subjectKey.publicKey.export({ type: 'spki', format: 'der' }),
    ...(ca ? [CA_TRUE] : []),
  );
  return {
    der: tlv(
      SEQUENCE,
      tbs,
      SHA256_RSA,
      tlv(BIT_STRING, Buffer.from([0]), cryptoSign('sha256', tbs, issuerKey.privateKey)),
    ),
    // issuerAndSerialNumber, which is how the SignerInfo names its signer.
    sid: tlv(SEQUENCE, name(issuer), tlv(INTEGER, serial)),
  };
}

/** A CMS SignedData carrying `certificates`; the signature is never reached. */
function receipt(certificates, sid) {
  const payload = tlv(
    SET,
    tlv(
      SEQUENCE,
      tlv(INTEGER, Buffer.from([12])),
      tlv(INTEGER, Buffer.from([1])),
      tlv(OCTET_STRING, tlv(IA5_STRING, Buffer.from('2025-12-26T17:43:07Z', 'ascii'))),
    ),
  );
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
        tlv(CONTEXT_0, Buffer.concat(certificates)),
        tlv(
          SET,
          tlv(
            SEQUENCE,
            tlv(INTEGER, Buffer.from([1])),
            sid,
            tlv(SEQUENCE, tlv(OID, OID_SHA256), tlv(NULL)),
            tlv(SEQUENCE),
            tlv(OCTET_STRING, Buffer.alloc(0)),
          ),
        ),
      ),
    ),
  );
}

const rsaKey = () => generateKeyPairSync('rsa', { modulusLength: 2048 });
// Two issuer keys for the mesh to branch over, and a stranger's, which
// certifies nothing the walk is looking for.
const [left, right, stranger] = [rsaKey(), rsaKey(), rsaKey()];

/**
 * A receipt whose certificates are a cross-signed mesh: `layers` levels, each
 * holding both keys certified by both keys of the level above, so a path
 * builder that walks every partial chain sees 2^layers of them. `decoys` more
 * certificates carry the leaf's issuer name without its key, so each one is a
 * candidate issuer the walk must run a full RSA check on before rejecting it.
 */
function meshReceipt(layers, decoys = 0) {
  const leaf = certificate({
    subject: 'Mesh Leaf',
    issuer: 'Mesh CA 1',
    subjectKey: stranger,
    issuerKey: left,
    ca: false,
  });
  const certificates = [leaf.der];
  const decoy = certificate({
    subject: 'Mesh CA 1',
    issuer: 'Mesh CA 99',
    subjectKey: stranger,
    issuerKey: stranger,
    ca: true,
  });
  // Ahead of the mesh, where an attacker would put them: the walk scans in order.
  for (let i = 0; i < decoys; i++) {
    certificates.push(decoy.der);
  }
  for (let layer = 1; layer <= layers; layer++) {
    for (const subjectKey of [left, right]) {
      for (const issuerKey of [left, right]) {
        certificates.push(
          certificate({
            subject: `Mesh CA ${layer}`,
            issuer: `Mesh CA ${layer + 1}`,
            subjectKey,
            issuerKey,
            ca: true,
          }).der,
        );
      }
    }
  }
  return receipt(certificates, leaf.sid);
}

// Any bundle id: none of these receipts reaches the claim checks.
const verifier = new ReceiptVerifier({ trustedRoots: appleReceiptRoots(), bundleId: '*' });

function elapsed(work) {
  const started = performance.now();
  work();
  return performance.now() - started;
}

test('rejects a receipt embedding more certificates than a chain can hold', () => {
  const oneTooMany = [];
  for (let i = 0; i < LIMIT; i++) {
    oneTooMany.push(
      certificate({
        subject: 'Mesh CA 1',
        issuer: 'Mesh CA 2',
        subjectKey: left,
        issuerKey: right,
        ca: true,
      }).der,
    );
  }
  const leaf = certificate({
    subject: 'Mesh Leaf',
    issuer: 'Mesh CA 1',
    subjectKey: stranger,
    issuerKey: left,
    ca: false,
  });
  oneTooMany.push(leaf.der);
  assert.throws(
    () => verifier.verify(receipt(oneTooMany, leaf.sid)),
    (e) => {
      assert.equal(e.reason, 'INVALID_CHAIN');
      // Names the bound, so a caller that trips it learns what it is.
      assert.ok(e.message.includes(`more than ${LIMIT} certificates`), e.message);
      return true;
    },
  );
});

test('rejects a cross-signed certificate mesh without walking it', () => {
  // The shape that costs an unbounded path builder exponential work: 14 layers
  // of two cross-signed keys, here with 1000 decoy issuers ahead of them, in
  // 722 KB. MAX_PATH_LENGTH already bounds the depth, so what this bound
  // removes is the per-certificate work — converting each one and running an
  // RSA check on it as a candidate issuer — which measured 122-172 ms, 26 to
  // 45 times the cost of verifying the genuine 79 KB legacy receipt. Bounded,
  // the same input costs 3.5 to 6 of those, all of it the DER parse that runs
  // before any certificate is looked at. The budget is 20 verifications of
  // that receipt, measured here so it follows the machine rather than assuming
  // one, which leaves the bounded path a factor of 3 inside it and puts the
  // unbounded path outside.
  const genuine = readFileSync(
    fileURLToPath(
      new URL('../../fixtures/public-receipts/receipt-sandbox-legacy.b64', import.meta.url),
    ),
    'ascii',
  ).trim();
  const genuineVerifier = new ReceiptVerifier({
    trustedRoots: appleReceiptRoots(),
    bundleId: 'com.nutcall.alert',
  });
  // Fastest of five: the slow runs are this process's own warm-up and GC.
  const unit = Math.min(
    ...[1, 2, 3, 4, 5].map(() => elapsed(() => genuineVerifier.verify(genuine))),
  );

  const mesh = meshReceipt(14, 1000);
  const spent = elapsed(() =>
    assert.throws(
      () => verifier.verify(mesh),
      (e) => e.reason === 'INVALID_CHAIN',
    ),
  );
  assert.ok(
    spent < 20 * unit,
    `rejected the mesh in ${spent.toFixed(0)} ms, budget ${(20 * unit).toFixed(0)} ms`,
  );
});

/**
 * The bound where the implementation states it — in the rejection it raises —
 * rather than LIMIT, which is a copy in this file that no change to
 * src/receipt.ts can move. 64 certificates is above any bound that could
 * still admit a genuine three-certificate chain, so the rejection fires
 * wherever the bound is set.
 */
function reportedBound(leaf) {
  const flood = Array.from({ length: 64 }, () => leaf.der);
  let rejection;
  try {
    verifier.verify(receipt(flood, leaf.sid));
  } catch (e) {
    rejection = e;
  }
  assert.ok(rejection, 'a receipt embedding 64 certificates was not rejected');
  assert.equal(rejection.reason, 'INVALID_CHAIN');
  const reported = /more than (\d+) certificates/.exec(rejection.message);
  assert.ok(reported, rejection.message);
  return Number(reported[1]);
}

test('a receipt embedding exactly the bound is examined, not rejected by it', () => {
  // Exactly `bound` certificates, the last of them unparseable: reaching it
  // shows as the parse error, stopping at the count guard as INVALID_CHAIN.
  const leaf = certificate({
    subject: 'Mesh Leaf',
    issuer: 'Mesh CA 1',
    subjectKey: stranger,
    issuerKey: left,
    ca: false,
  });
  const exactly = Array.from({ length: reportedBound(leaf) - 1 }, () => leaf.der);
  exactly.push(Buffer.from([0x30, 0x03, 0x02, 0x01, 0x00]));
  assert.throws(
    () => verifier.verify(receipt(exactly, leaf.sid)),
    (e) => e.reason === 'INVALID_RECEIPT_FORMAT',
  );
});

test('the certificate limit is above every genuine receipt', () => {
  // The bound is only safe while it stays above the largest chain Apple
  // actually ships.
  const leaf = certificate({
    subject: 'Mesh Leaf',
    issuer: 'Mesh CA 1',
    subjectKey: stranger,
    issuerKey: left,
    ca: false,
  });
  const bound = reportedBound(leaf);

  for (const fixture of [
    'receipt-sandbox-g5',
    'receipt-sandbox-legacy',
    'receipt-xcode-with-purchases',
  ]) {
    const der = Buffer.from(
      readFileSync(
        fileURLToPath(new URL(`../../fixtures/public-receipts/${fixture}.b64`, import.meta.url)),
        'ascii',
      ).trim(),
      'base64',
    );
    const count = countCertificates(der);
    assert.ok(
      count > 0 && count < bound,
      `${fixture} embeds ${count} certificates, bound is ${bound}`,
    );
  }
});

/**
 * Counts the certificates a CMS SignedData embeds, with the library's own
 * reader — the Xcode receipt is BER with indefinite lengths.
 */
function countCertificates(der) {
  const signedData = parse(der).children[1].children[0].children;
  const certificates = signedData
    .slice(3, signedData.length - 1)
    .find((node) => node.tag === Tag.CONTEXT_0);
  return certificates.children.length;
}
