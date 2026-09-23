#!/usr/bin/env node
/**
 * Writes fixtures/limits/, the inputs of the resource-bounds vectors in
 * fixtures/cases.json.
 *
 *   node tools/generate-limit-fixtures.mjs
 *
 * The limits are Apple's own (measured 2026-09-23 against both verifyReceipt
 * endpoints): a request body of 3,145,728 bytes is answered and one of
 * 3,145,729 bytes gets HTTP 413, counted in UTF-8 bytes. The receipt cap is
 * the same 3,145,728 bytes and the JWS cap 262,144 bytes. A vector that holds
 * a limit from both sides needs an input exactly at it and one byte over, so
 * these files are megabytes of padding around a small genuine input.
 *
 * They are committed rather than generated at test time so that all nine
 * ports, and the C ABI harnesses, read identical bytes with no generation
 * logic of their own. Git stores blobs zlib-compressed, so the padding costs
 * the repository a few kilobytes. This script exists only to make the files
 * reproducible: it is deterministic (no clock, no randomness), reads nothing
 * but registered fixtures, and rewrites every file on each run. After a run,
 * `node tools/lint-cases.mjs` must still pass; if a file changed, its
 * contentSha256 in cases.json has to change with it, and the script prints
 * the digests to copy.
 *
 * Every file is built from one genuine input plus padding the input's own
 * format allows, so the limit is the only thing that can refuse the file
 * that is one byte over:
 *
 *   receipt-b64-*.txt      the genuine sandbox receipt string, then LF
 *   receipt-der-*.der      the shared generated receipt, then zero bytes
 *   body-ascii-*.json      {"receipt-data":"<genuine>"<spaces>}
 *   body-2byte-*.json      {"receipt-data":"<genuine>","password":"<U+00E9...>"}
 *   body-nested-*.json     {"receipt-data":"<genuine>","deep":[[...1...]]}
 *   jws-*.jws              Apple's mock renewal info, signature padded with 'A'
 *
 * None contains a lone surrogate or any character outside the Basic
 * Multilingual Plane, so no port has to agree on how those are counted.
 */

import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const FIXTURES = join(REPO, 'fixtures');
const OUT = join(FIXTURES, 'limits');

const CAP = 3145728;
const JWS_CAP = 262144;

const read = (path) => readFileSync(join(FIXTURES, path));

// The genuine sandbox receipt as a client sends it: canonical base64, one line.
const receiptText = read('generated/receipt-b64/01-genuine.txt');
// The shared generated receipt, as DER.
const receiptDer = read('generated/receipt.der');
// Apple's mock renewal-info JWS, trimmed like the utf8 codec trims it.
const jws = Buffer.from(read('apple-official/mock_signed_data/renewalInfo').toString('utf8').trim(), 'utf8');

function padded(prefix, unit, suffix, length) {
  const room = length - prefix.length - suffix.length;
  const unitBytes = Buffer.from(unit, 'utf8');
  if (room < 0 || room % unitBytes.length !== 0) {
    throw new Error(`cannot pad to ${length} bytes with ${JSON.stringify(unit)}`);
  }
  const out = Buffer.concat([prefix, Buffer.alloc(room, unitBytes), suffix]);
  if (out.length !== length) throw new Error(`built ${out.length} bytes, wanted ${length}`);
  return out;
}

const text = (s) => Buffer.from(s, 'utf8');
const bodyStart = text(`{"receipt-data":"${receiptText.toString('ascii')}`);

function nested(arrays) {
  return Buffer.concat([bodyStart, text(`","deep":${'['.repeat(arrays)}1${']'.repeat(arrays)}}`)]);
}

const files = {
  'receipt-b64-at-cap.txt': padded(receiptText, '\n', text(''), CAP),
  'receipt-b64-over-cap.txt': padded(receiptText, '\n', text(''), CAP + 1),
  'receipt-der-over-cap.der': padded(receiptDer, '\u0000', text(''), CAP + 1),
  'body-ascii-at-cap.json': padded(Buffer.concat([bodyStart, text('"')]), ' ', text('}'), CAP),
  'body-ascii-over-cap.json': padded(Buffer.concat([bodyStart, text('"')]), ' ', text('}'), CAP + 1),
  // One space after the comma in the at-cap body only: U+00E9 is two bytes,
  // so the space is what lets both bodies land on their exact length.
  'body-2byte-at-cap.json': padded(Buffer.concat([bodyStart, text('", "password":"')]), 'é', text('"}'), CAP),
  'body-2byte-over-cap.json': padded(Buffer.concat([bodyStart, text('","password":"')]), 'é', text('"}'), CAP + 1),
  // The body object plus 63 arrays is 64 containers open at once; plus 64 is 65.
  'body-nested-64.json': nested(63),
  'body-nested-65.json': nested(64),
  'jws-at-cap.jws': padded(jws, 'A', text(''), JWS_CAP),
  'jws-over-cap.jws': padded(jws, 'A', text(''), JWS_CAP + 1),
};

mkdirSync(OUT, { recursive: true });
for (const [name, bytes] of Object.entries(files)) {
  writeFileSync(join(OUT, name), bytes);
  const digest = createHash('sha256').update(bytes).digest('hex');
  const characters = bytes.toString('utf8').length;
  console.log(`limits/${name}\t${bytes.length} bytes\t${characters} UTF-16 units\t${digest}`);
}
