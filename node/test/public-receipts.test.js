import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { ReceiptVerifier, appleReceiptRoots } from '../dist/index.js';

const receipt = (name) => readFileSync(fileURLToPath(
  new URL(`../../fixtures/public-receipts/${name}.b64`, import.meta.url)), 'ascii').trim();

test('verifies a genuine Apple sandbox receipt against the real pinned root', () => {
  const verifier = new ReceiptVerifier({
    trustedRoots: appleReceiptRoots(), bundleId: 'dev.bonzer.weeka.app',
  });
  assert.equal(verifier.verify(receipt('receipt-sandbox-g5')).receiptType, 'ProductionSandbox');
});

test('verifies a genuine legacy SHA-1-chain receipt (187 purchases)', () => {
  const verifier = new ReceiptVerifier({
    trustedRoots: appleReceiptRoots(), bundleId: 'com.nutcall.alert',
  });
  assert.equal(verifier.verify(receipt('receipt-sandbox-legacy')).inAppPurchases.length, 187);
});

test('rejects the Xcode-signed public receipt', () => {
  const verifier = new ReceiptVerifier({ trustedRoots: appleReceiptRoots(), bundleId: '*' });
  assert.throws(() => verifier.verify(receipt('receipt-xcode-with-purchases')),
    (e) => e.reason === 'INVALID_CHAIN');
});
