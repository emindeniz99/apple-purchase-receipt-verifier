import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ReceiptVerifier, appleReceiptRoots } from '../dist/index.js';

const receipt = (name) =>
  readFileSync(
    fileURLToPath(new URL(`../../fixtures/public-receipts/${name}.b64`, import.meta.url)),
    'ascii',
  ).trim();

// The verdicts for all three public receipts live in fixtures/cases.json and
// run from conformance.test.js. What stays here is the input form: the
// conformance adapter always hands `verify` decoded bytes, so nothing there
// exercises the base64-string overload a client actually posts.
test('verifies a genuine Apple sandbox receipt handed over as base64 text', () => {
  const verifier = new ReceiptVerifier({
    trustedRoots: appleReceiptRoots(),
    bundleId: 'dev.bonzer.weeka.app',
  });
  assert.equal(verifier.verify(receipt('receipt-sandbox-g5')).receiptType, 'ProductionSandbox');
});
