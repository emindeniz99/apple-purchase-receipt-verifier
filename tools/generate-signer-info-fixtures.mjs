#!/usr/bin/env node
/**
 * Writes fixtures/public-receipts/signer-infos/, genuine Apple receipts whose
 * SignerInfos SET carries one more SignerInfo beside Apple's.
 *
 *   node tools/generate-signer-info-fixtures.mjs
 *
 * Every byte outside the SignerInfos SET is kept as Apple wrote it; only the
 * length headers of the three containers around that SET are rewritten. An
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
 *   malformed-unsigned-attrs-then-genuine.der
 *                                       Apple's SignerInfo with unsignedAttrs
 *                                       [1] { INTEGER 5 } appended, then Apple's
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = join(REPO, 'fixtures');
const OUT = join(FIXTURES, 'public-receipts', 'signer-infos');

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
const infos = children(der, set[0]);
if (infos.length !== 1) throw new Error(`expected one SignerInfo, found ${infos.length}`);
const genuine = slice(der, infos[0]);
const beforeSet = der.subarray(signedData + tlv(der, signedData)[0], set[0]);

function receipt(...signerInfos) {
  const sd = wrap(0x30, Buffer.concat([beforeSet, wrap(0x31, Buffer.concat(signerInfos))]));
  return wrap(0x30, Buffer.concat([slice(der, contentInfo[0]), wrap(0xa0, sd)]));
}

if (!receipt(genuine).equals(der)) throw new Error('the splice does not reproduce the original bytes');

// SignerInfo: version, sid, digestAlgorithm, [[0] signedAttrs,] signatureAlgorithm, signature.
const parts = children(genuine, 0).map((p) => slice(genuine, p));
if (parts.length < 5 || parts[2][0] !== 0x30 || parts[parts.length - 1][0] !== 0x04) {
  throw new Error('unexpected SignerInfo shape');
}
const unknownDigest = wrap(
  0x30,
  Buffer.concat([parts[0], parts[1], wrap(0x30, Buffer.from('06032a03040500', 'hex')), ...parts.slice(3)]),
);
const malformedUnsigned = wrap(0x30, Buffer.concat([...parts, Buffer.from('a103020105', 'hex')]));

const files = {
  'unknown-digest-alone.der': receipt(unknownDigest),
  'unknown-digest-then-genuine.der': receipt(unknownDigest, genuine),
  'malformed-unsigned-attrs-then-genuine.der': receipt(malformedUnsigned, genuine),
};
mkdirSync(OUT, { recursive: true });
for (const [name, bytes] of Object.entries(files)) {
  writeFileSync(join(OUT, name), bytes);
  console.log(`${createHash('sha256').update(bytes).digest('hex')}  public-receipts/signer-infos/${name}`);
}
