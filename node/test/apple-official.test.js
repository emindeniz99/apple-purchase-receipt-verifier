import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { JwsVerifier, ReceiptVerifier, appleReceiptRoots } from '../src/index.js';

const BUNDLE = 'com.example';
const XCODE_BUNDLE = 'com.example.naturelab.backyardbirds.example';

function fixture(...segments) {
  return readFileSync(fileURLToPath(
    new URL(`../../fixtures/apple-official/${segments.join('/')}`, import.meta.url)));
}

const text = (...segments) => fixture(...segments).toString('ascii').trim();

function appleTestCaVerifier() {
  return new JwsVerifier({
    trustedRoots: [fixture('certs', 'testCA.der')],
    bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'],
  });
}

test("verifies Apple's official transactionInfo fixture", () => {
  const payload = appleTestCaVerifier().verifyTransaction(text('mock_signed_data', 'transactionInfo'));
  assert.equal(payload.bundleId, BUNDLE);
  assert.equal(payload.environment, 'Sandbox');
  assert.equal(payload.signedDate, 1672956154000);
});

test("verifies Apple's official renewalInfo fixture", () => {
  const claims = appleTestCaVerifier().verifyRaw(text('mock_signed_data', 'renewalInfo'));
  assert.equal(claims.environment, 'Sandbox');
});

test("verifies Apple's official testNotification fixture", () => {
  const claims = appleTestCaVerifier().verifyRaw(text('mock_signed_data', 'testNotification'));
  assert.equal(claims.notificationType, 'TEST');
});

test("rejects Apple's wrongBundleId fixture", () => {
  assert.throws(() => appleTestCaVerifier().verifyTransaction(text('mock_signed_data', 'wrongBundleId')),
    (e) => e.reason === 'WRONG_BUNDLE_ID');
});

test("rejects Apple's missingX5CHeaderClaim fixture", () => {
  assert.throws(() => appleTestCaVerifier().verifyTransaction(text('mock_signed_data', 'missingX5CHeaderClaim')),
    (e) => e.reason === 'INVALID_JWS_FORMAT');
});

test('rejects the Xcode-signed transaction (1-cert local chain)', () => {
  assert.throws(() => appleTestCaVerifier().verifyTransaction(text('xcode', 'xcode-signed-transaction')),
    (e) => e.reason === 'INVALID_JWS_FORMAT');
});

test('rejects a genuine Xcode receipt against real Apple roots', () => {
  const verifier = new ReceiptVerifier({
    trustedRoots: appleReceiptRoots(), bundleId: XCODE_BUNDLE,
  });
  assert.throws(() => verifier.verify(text('xcode', 'xcode-app-receipt-empty')),
    (e) => e.reason === 'INVALID_CHAIN');
});
