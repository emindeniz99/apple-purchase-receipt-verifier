import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { JwsVerifier, ReceiptVerifier } from '../src/index.js';

const BUNDLE = 'com.example.app';

function fixture(name) {
  return readFileSync(fileURLToPath(new URL(`../../fixtures/generated/${name}`, import.meta.url)));
}

const text = (name) => fixture(name).toString('ascii').trim();

test('verifies shared transaction fixture', () => {
  const verifier = new JwsVerifier({
    trustedRoots: [fixture('jws-root.der')], bundleId: BUNDLE, acceptedEnvironments: ['Sandbox'],
  });
  const payload = verifier.verifyTransaction(text('transaction.jws'));
  assert.equal(payload.productId, `${BUNDLE}.pro`);
  assert.equal(payload.transactionId, '2000000000000001');
  assert.equal(payload.signedDate, 1722945600000);
});

test('verifies shared AppTransaction fixture', () => {
  const verifier = new JwsVerifier({
    trustedRoots: [fixture('jws-root.der')], bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'], appAppleId: 123456789,
  });
  const payload = verifier.verifyAppTransaction(text('app-transaction.jws'));
  assert.equal(payload.appAppleId, 123456789);
  assert.equal(payload.applicationVersion, '1.2.3');
});

test('shared expired-chain fixtures behave as manifested', () => {
  const verifier = new JwsVerifier({
    trustedRoots: [fixture('jws-expired-root.der')], bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'],
  });
  assert.equal(verifier.verifyTransaction(text('expired-cert-historical.jws')).signedDate,
    1590969600000);
  assert.throws(() => verifier.verifyTransaction(text('expired-cert-fresh.jws')),
    (e) => e.reason === 'INVALID_CHAIN');
});

test('verifies shared receipt fixture with device hash', () => {
  const verifier = new ReceiptVerifier({
    trustedRoots: [fixture('receipt-root.der')], bundleId: BUNDLE,
  });
  const guid = Buffer.from(text('device-guid.hex'), 'hex');
  const receipt = verifier.verify(fixture('receipt.der'), guid);
  assert.equal(receipt.appVersion, '1.2.3');
  assert.equal(receipt.creationDate.toISOString(), '2024-08-06T12:00:00.000Z');
  assert.equal(receipt.inAppPurchases.length, 2);
  const vip = receipt.inAppPurchases.find((p) => p.productId === `${BUNDLE}.vip`);
  assert.equal(vip.expiresDate.toISOString(), '2030-02-01T09:30:00.000Z');
  assert.equal(vip.webOrderLineItemId, 42);
});

test('rejects shared foreign-root receipt fixture', () => {
  const verifier = new ReceiptVerifier({
    trustedRoots: [fixture('receipt-root.der')], bundleId: BUNDLE,
  });
  assert.throws(() => verifier.verify(fixture('receipt-foreign.der')),
    (e) => e.reason === 'INVALID_CHAIN');
});
