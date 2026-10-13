#!/usr/bin/env node
/**
 * Writes fixtures/public-receipts/signer-infos/, genuine Apple receipts whose
 * SignerInfos SET carries one more SignerInfo beside Apple's, and
 * fixtures/public-receipts/certificates/, genuine Apple receipts whose
 * certificate bag carries one more entry beside Apple's three.
 *
 *   node tools/generate-signer-info-fixtures.mjs
 *
 * Every byte outside the SignerInfos SET, or the certificate bag, is kept as
 * Apple wrote it; only the length headers of the containers around it are
 * rewritten. An
 * ASN.1 library is not used to re-encode: BouncyCastle sorts the certificates
 * SET into DER order, which changes bytes Apple wrote for no reason of the
 * case's (docs/evidence/2026-10-06-verifyreceipt-two-signerinfos.md). The
 * script checks that the splice reproduces the original receipt from its one
 * SignerInfo before it writes anything.
 *
 * Deterministic (no clock, no randomness); it rewrites every file on each
 * run. After a run, `node tools/lint-cases.mjs` must still pass, and the
 * script prints the digests to copy into cases.json.
 *
 *   unknown-digest-alone.der            Apple's SignerInfo with its digest
 *                                       algorithm set to 1.2.3.4, alone
 *   unknown-digest-then-genuine.der     that SignerInfo, then Apple's
 *   refused-digest-alone.der            Apple's SignerInfo with its digest
 *                                       algorithm set to MD2
 *                                       (1.2.840.113549.2.2), alone
 *   malformed-unsigned-attrs-then-genuine.der
 *                                       Apple's SignerInfo with unsignedAttrs
 *                                       [1] { INTEGER 5 } appended, then Apple's
 *   md2-with-rsa-label-alone.der        Apple's SignerInfo with its signature
 *                                       algorithm set to md2WithRSAEncryption
 *                                       (1.2.840.113549.1.1.2), alone
 *   rsa-pss-huge-salt-label-alone.der   Apple's SignerInfo with its signature
 *                                       algorithm set to RSASSA-PSS (SHA-256,
 *                                       MGF1 with SHA-256, saltLength
 *                                       1,000,000,000), alone
 *
 *   certificates/rsa-pss-huge-salt-stranger.der
 *                                       the receipt with one more bag entry
 *                                       naming Apple Root CA as its issuer,
 *                                       labelled RSASSA-PSS (SHA-256, MGF1 with
 *                                       SHA-256, saltLength 2,147,483,647),
 *                                       with the receipt signer's key and 256
 *                                       zero octets as its signature
 *   certificates/rsa-pss-negative-salt-stranger.der
 *                                       the same entry with saltLength
 *                                       -3,294,967,296, whose low 32 bits are
 *                                       1,000,000,000
 *   certificates/thousand-and-one-extensions-stranger.der
 *                                       the receipt with one more bag entry
 *                                       naming Apple Root CA as its issuer,
 *                                       labelled sha256WithRSAEncryption, with
 *                                       the receipt signer's key, 1,001
 *                                       non-critical extensions under the OIDs
 *                                       1.3.6.1.4.1.99999.1.0 to .1000, each
 *                                       with an empty extnValue, and 256 zero
 *                                       octets as its signature
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = join(REPO, 'fixtures');
const OUT = join(FIXTURES, 'public-receipts');

/** [header length, content length] of the definite-length value at off. */
function tlv(buf, off) {
  const first = buf[off + 1];
  if (first < 0x80) return [2, first];
  const n = first & 0x7f;
  if (n === 0) throw new Error(`indefinite length at ${off}`);
  return [2 + n, buf.readUIntBE(off + 2, n)];
}

/** The values inside the constructed value at off, as [offset, total length]. */
function children(buf, off) {
  const [hl, cl] = tlv(buf, off);
  const out = [];
  for (let pos = off + hl; pos < off + hl + cl; ) {
    const [h, c] = tlv(buf, pos);
    out.push([pos, h + c]);
    pos += h + c;
  }
  return out;
}

function wrap(tag, content) {
  const len = content.length;
  if (len < 0x80) return Buffer.concat([Buffer.from([tag, len]), content]);
  const body = [];
  for (let n = len; n > 0; n >>= 8) body.unshift(n & 0xff);
  return Buffer.concat([Buffer.from([tag, 0x80 | body.length, ...body]), content]);
}

const slice = (buf, [off, len]) => buf.subarray(off, off + len);

const der = Buffer.from(readFileSync(join(FIXTURES, 'public-receipts/receipt-sandbox-g5.b64'), 'ascii').trim(), 'base64');
const contentInfo = children(der, 0); // contentType, [0]
const signedData = children(der, contentInfo[1][0])[0][0];
const fields = children(der, signedData); // version, digestAlgorithms, encapContentInfo, [0] certificates, SignerInfos
const set = fields[fields.length - 1];
if (der[set[0]] !== 0x31 || set[0] + set[1] !== der.length) throw new Error('the SignerInfos SET is not last');
const bag = fields[fields.length - 2];
if (der[bag[0]] !== 0xa0) throw new Error('the certificate bag is not before the SignerInfos SET');
const infos = children(der, set[0]);
if (infos.length !== 1) throw new Error(`expected one SignerInfo, found ${infos.length}`);
const genuine = slice(der, infos[0]);
const beforeSet = der.subarray(signedData + tlv(der, signedData)[0], set[0]);

function receipt(...signerInfos) {
  const sd = wrap(0x30, Buffer.concat([beforeSet, wrap(0x31, Buffer.concat(signerInfos))]));
  return wrap(0x30, Buffer.concat([slice(der, contentInfo[0]), wrap(0xa0, sd)]));
}

function withBagEntry(entry) {
  const head = der.subarray(signedData + tlv(der, signedData)[0], bag[0]);
  const certificates = der.subarray(bag[0] + tlv(der, bag[0])[0], bag[0] + bag[1]);
  const sd = wrap(0x30, Buffer.concat([head, wrap(0xa0, Buffer.concat([certificates, entry])), slice(der, set)]));
  return wrap(0x30, Buffer.concat([slice(der, contentInfo[0]), wrap(0xa0, sd)]));
}

if (!receipt(genuine).equals(der)) throw new Error('the splice does not reproduce the original bytes');
if (!withBagEntry(Buffer.alloc(0)).equals(der)) throw new Error('the bag splice does not reproduce the original bytes');

// SignerInfo: version, sid, digestAlgorithm, [[0] signedAttrs,] signatureAlgorithm, signature.
const parts = children(genuine, 0).map((p) => slice(genuine, p));
if (parts.length < 5 || parts[2][0] !== 0x30 || parts[parts.length - 1][0] !== 0x04) {
  throw new Error('unexpected SignerInfo shape');
}
const withDigest = (algorithm) =>
  wrap(0x30, Buffer.concat([parts[0], parts[1], wrap(0x30, Buffer.from(algorithm, 'hex')), ...parts.slice(3)]));
const unknownDigest = withDigest('06032a03040500');
const md2Digest = withDigest('06082a864886f70d02020500');
const withSignature = (algorithm) =>
  wrap(0x30, Buffer.concat([...parts.slice(0, -2), wrap(0x30, algorithm), parts[parts.length - 1]]));
const md2WithRsa = withSignature(Buffer.from('06092a864886f70d0101020500', 'hex'));
const sha256 = wrap(0x30, Buffer.from('0609608648016503040201' + '0500', 'hex'));
// RSASSA-PSS, SHA-256, MGF1 with SHA-256, the given saltLength INTEGER.
const pss = (saltLength) => Buffer.concat([
  Buffer.from('06092a864886f70d01010a', 'hex'),
  wrap(0x30, Buffer.concat([
    wrap(0xa0, sha256),
    wrap(0xa1, wrap(0x30, Buffer.concat([Buffer.from('06092a864886f70d010108', 'hex'), sha256]))),
    wrap(0xa2, saltLength),
  ])),
]);
const pssHugeSalt = withSignature(pss(Buffer.from('02043b9aca00', 'hex'))); // INTEGER 1,000,000,000

// Certificate: TBSCertificate, signatureAlgorithm, signature. TBSCertificate:
// [0] version, serialNumber, signature, issuer, validity, subject, key, ...
const tbsOf = (certificate) => children(certificate, children(certificate, 0)[0][0]).map((p) => slice(certificate, p));
const [leafCert, , rootCert] = children(der, bag[0]).map((p) => slice(der, p));
const rootTbs = tbsOf(rootCert);
const strangerWithSalt = (saltLength) => {
  const strangerLabel = wrap(0x30, pss(saltLength));
  return wrap(0x30, Buffer.concat([
    wrap(0x30, Buffer.concat([
      Buffer.from('a003020102', 'hex'), // v3
      Buffer.from('02021092', 'hex'), // serial 4242
      strangerLabel,
      rootTbs[5], // issuer: Apple Root CA's subject
      rootTbs[4], // Apple Root CA's validity
      wrap(0x30, wrap(0x31, wrap(0x30, Buffer.concat([Buffer.from('0603550403', 'hex'), wrap(0x0c, Buffer.from('Stranger'))])))),
      tbsOf(leafCert)[6], // the receipt signer's key
    ])),
    strangerLabel,
    wrap(0x03, Buffer.alloc(257)), // no unused bits, 256 zero octets
  ]));
};
const stranger = strangerWithSalt(Buffer.from('02047fffffff', 'hex')); // INTEGER 2,147,483,647
// INTEGER -3,294,967,296: two's complement in 5 octets, low 32 bits 0x3b9aca00.
const negativeSaltStranger = strangerWithSalt(Buffer.from('0205ff3b9aca00', 'hex'));
/** The OID 1.3.6.1.4.1.99999.1.n: each arc after 1.3 in base 128, high octets marked. */
const fillerOid = (n) =>
  wrap(0x06, Buffer.from([0x2b, ...[6, 1, 4, 1, 99999, 1, n].flatMap((arc) => {
    const octets = [arc & 0x7f];
    for (let rest = arc >> 7; rest > 0; rest >>= 7) octets.unshift(0x80 | (rest & 0x7f));
    return octets;
  })]));
const sha256WithRsa = wrap(0x30, Buffer.from('06092a864886f70d01010b0500', 'hex'));
const crowded = wrap(0x30, Buffer.concat([
  wrap(0x30, Buffer.concat([
    Buffer.from('a003020102', 'hex'), // v3
    Buffer.from('02021093', 'hex'), // serial 4243
    sha256WithRsa,
    rootTbs[5], // issuer: Apple Root CA's subject
    rootTbs[4], // Apple Root CA's validity
    wrap(0x30, wrap(0x31, wrap(0x30, Buffer.concat([Buffer.from('0603550403', 'hex'), wrap(0x0c, Buffer.from('Stranger'))])))),
    tbsOf(leafCert)[6], // the receipt signer's key
    // [3] Extensions: one more than the 1,000 Java parses.
    wrap(0xa3, wrap(0x30, Buffer.concat(Array.from({ length: 1001 }, (_, n) =>
      wrap(0x30, Buffer.concat([fillerOid(n), Buffer.from('0400', 'hex')])))))),
  ])),
  sha256WithRsa,
  wrap(0x03, Buffer.alloc(257)), // no unused bits, 256 zero octets
]));
const malformedUnsigned = wrap(0x30, Buffer.concat([...parts, Buffer.from('a103020105', 'hex')]));

const files = {
  'signer-infos/unknown-digest-alone.der': receipt(unknownDigest),
  'signer-infos/unknown-digest-then-genuine.der': receipt(unknownDigest, genuine),
  'signer-infos/malformed-unsigned-attrs-then-genuine.der': receipt(malformedUnsigned, genuine),
  'signer-infos/refused-digest-alone.der': receipt(md2Digest),
  'signer-infos/md2-with-rsa-label-alone.der': receipt(md2WithRsa),
  'signer-infos/rsa-pss-huge-salt-label-alone.der': receipt(pssHugeSalt),
  'certificates/rsa-pss-huge-salt-stranger.der': withBagEntry(stranger),
  'certificates/rsa-pss-negative-salt-stranger.der': withBagEntry(negativeSaltStranger),
  'certificates/thousand-and-one-extensions-stranger.der': withBagEntry(crowded),
};
for (const [name, bytes] of Object.entries(files)) {
  mkdirSync(dirname(join(OUT, name)), { recursive: true });
  writeFileSync(join(OUT, name), bytes);
  console.log(`${createHash('sha256').update(bytes).digest('hex')}  public-receipts/${name}`);
}
