// The fuzz targets' seed corpora, run without the fuzzer.
//
// node/fuzz/ is a separate npm project so that `npm ci` here does not pull a
// native fuzzing addon (fuzz/README.md, "Why this is a separate npm project"),
// which means the targets' invariants would otherwise only be checked on the
// one CI job that installs it. The targets themselves are plain ESM functions
// with no dependency on the fuzzer, so this file calls them directly over the
// fixtures that seed them plus a deterministic mutation sweep — the same thing
// `go test` does with its seed corpora on every run.
//
// A reduced crasher belongs here too: add its bytes to CRASHERS and the case
// runs on every Node line in the matrix, not only when someone runs jazzer.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { fuzz as fuzzParseDer } from '../fuzz/targets/parse-der.mjs';
import { fuzz as fuzzParseCms } from '../fuzz/targets/parse-cms.mjs';
import { fuzz as fuzzVerifyReceipt } from '../fuzz/targets/verify-receipt.mjs';
import { fuzz as fuzzVerifyReceiptBase64 } from '../fuzz/targets/verify-receipt-base64.mjs';
import { fuzz as fuzzVerifyTransaction } from '../fuzz/targets/verify-transaction.mjs';
import { fuzz as fuzzEndpointJson } from '../fuzz/targets/endpoint-json.mjs';

const fixtureDir = (relative) =>
  fileURLToPath(new URL(`../../fixtures/${relative}`, import.meta.url));

/** Every regular file directly under the given fixture directories. */
function seedsFrom(...directories) {
  const seeds = [];
  for (const directory of directories) {
    const base = fixtureDir(directory);
    for (const entry of readdirSync(base, { withFileTypes: true })) {
      if (entry.isFile()) {
        seeds.push([`${directory}/${entry.name}`, readFileSync(`${base}/${entry.name}`)]);
      }
    }
  }
  return seeds;
}

// The degenerate inputs every port's seed list carries, plus the two shapes
// the DER reader has its own branches for.
const DEGENERATE = [
  ['empty', Buffer.alloc(0)],
  ['one byte', Buffer.of(0x30)],
  ['bare indefinite length', Buffer.of(0x30, 0x80)],
  ['unterminated sequence', Buffer.of(0x30, 0x82, 0xff, 0xff)],
  ['not base64', Buffer.from('!!!!not base64!!!!', 'ascii')],
  ['three empty jws segments', Buffer.from('a.b.c', 'ascii')],
  ['nesting past the depth cap', Buffer.from(Array.from({ length: 200 }, () => 0x30).concat([0]))],
];

/**
 * A small deterministic sweep per seed: truncations and single-byte flips at
 * a prime stride, so the same bytes are exercised on every run and on every
 * Node line. This is not fuzzing — it is the regression floor under it.
 */
function* mutationsOf(label, bytes) {
  yield [label, bytes];
  for (const cut of [1, 2, 8, 64, Math.floor(bytes.length / 2)]) {
    if (cut > 0 && cut < bytes.length) {
      yield [`${label} truncated to ${cut}`, bytes.subarray(0, cut)];
    }
  }
  for (let at = 0; at < bytes.length; at += 1021) {
    const flipped = Buffer.from(bytes);
    flipped[at] ^= 0xff;
    yield [`${label} byte ${at} flipped`, flipped];
  }
}

/** Reduced crashers found by the fuzzer. Empty is the honest state today. */
const CRASHERS = [];

function runTarget(name, fuzz, seeds) {
  let checked = 0;
  for (const [label, bytes] of [...DEGENERATE, ...CRASHERS, ...seeds]) {
    for (const [what, input] of mutationsOf(label, bytes)) {
      // The target itself asserts the invariants — a typed error is caught
      // inside it, and anything else is rethrown as a plain Error. So a
      // throw reaching here is a finding, and its message says which one.
      try {
        fuzz(input);
      } catch (error) {
        assert.fail(`${name}: ${what}: ${error.message}`);
      }
      checked += 1;
    }
  }
  // The corpus is read off disk, so a fixture directory that moved would
  // otherwise quietly turn this into an assertion about nothing.
  assert.ok(checked > 50, `${name} only ran ${checked} inputs`);
}

test('parse-der holds its invariants over the fixture corpus', () => {
  runTarget('parse-der', fuzzParseDer, seedsFrom('generated', 'apple-official/certs'));
});

test('parse-cms holds its invariants over the fixture corpus', () => {
  runTarget('parse-cms', fuzzParseCms, seedsFrom('generated', 'apple-official/certs'));
});

test('verify-receipt holds its invariants over the fixture corpus', () => {
  runTarget('verify-receipt', fuzzVerifyReceipt, seedsFrom('generated'));
});

test('verify-receipt-base64 holds its invariants over the fixture corpus', () => {
  runTarget(
    'verify-receipt-base64',
    fuzzVerifyReceiptBase64,
    seedsFrom('generated/receipt-b64', 'apple-official/xcode'),
  );
});

test('verify-transaction holds its invariants over the fixture corpus', () => {
  runTarget(
    'verify-transaction',
    fuzzVerifyTransaction,
    seedsFrom('generated', 'apple-official/mock_signed_data'),
  );
});

test('endpoint-json holds its invariants over the fixture corpus', () => {
  const seeds = readdirSync(fileURLToPath(new URL('../fuzz/seeds/endpoint-json', import.meta.url)))
    .map((name) => [
      `seeds/${name}`,
      readFileSync(fileURLToPath(new URL(`../fuzz/seeds/endpoint-json/${name}`, import.meta.url))),
    ])
    .concat(
      seedsFrom('public-receipts').map(([n, b]) => [
        n,
        Buffer.from(JSON.stringify({ 'receipt-data': b.toString('ascii').replace(/\s+/g, '') })),
      ]),
    );
  runTarget('endpoint-json', fuzzEndpointJson, seeds);
});
