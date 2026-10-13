#!/usr/bin/env node
/**
 * tools/generate-signer-info-fixtures.mjs with another list of files: the
 * genuine G5 sandbox receipt with its one SignerInfo's digestAlgorithm set
 * to each of the eight digests Java refuses: GOST R 34.11-94, MD2,
 * Whirlpool, GOST R 34.11-2012 (Streebog) 256 and 512, and DSTU 7564 256,
 * 384 and 512, every other byte as Apple wrote it. md2.der is byte-identical to the shared
 * fixture public-receipts/signer-infos/refused-digest-alone.der.
 *
 *   node variants.mjs "$REPO" "$SCRATCH/variants"
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

const REPO = resolve(process.argv[2]);
const FIXTURES = join(REPO, 'fixtures');
const OUT = resolve(process.argv[3]);

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
const withDigest = (algorithm) =>
  wrap(0x30, Buffer.concat([parts[0], parts[1], wrap(0x30, Buffer.from(algorithm, 'hex')), ...parts.slice(3)]));
// Each AlgorithmIdentifier as DER: the OID, then NULL parameters where the
// digest's specification has them.
const files = {
  'gost94.der': receipt(withDigest('06062a85030202090500')), // 1.2.643.2.2.9
  'md2.der': receipt(withDigest('06082a864886f70d02020500')), // 1.2.840.113549.2.2
  'whirlpool.der': receipt(withDigest('060628cf060300370500')), // 1.0.10118.3.0.55
  'streebog256.der': receipt(withDigest('06082a85030701010202')), // 1.2.643.7.1.1.2.2
  'streebog512.der': receipt(withDigest('06082a85030701010203')), // 1.2.643.7.1.1.2.3
  'dstu256.der': receipt(withDigest('060b2a86240201010101020201')), // 1.2.804.2.1.1.1.1.2.2.1
  'dstu384.der': receipt(withDigest('060b2a86240201010101020202')), // 1.2.804.2.1.1.1.1.2.2.2
  'dstu512.der': receipt(withDigest('060b2a86240201010101020203')), // 1.2.804.2.1.1.1.1.2.2.3
};
mkdirSync(OUT, { recursive: true });
for (const [name, bytes] of Object.entries(files)) {
  writeFileSync(join(OUT, name), bytes);
  console.log(`${createHash('sha256').update(bytes).digest('hex')}  ${name}`);
}
