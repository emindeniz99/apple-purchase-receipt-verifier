import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { JwsVerifier, ReceiptVerifier } from '../dist/index.js';

const BUNDLE = 'com.example.app';
const fx = (n) => readFileSync(fileURLToPath(new URL(`../../fixtures/generated/${n}`, import.meta.url)));
const txt = (n) => fx(n).toString('ascii').trim();

test('rejects a receipt whose signer lacks the Apple receipt-signing OID', () => {
  const v = new ReceiptVerifier({ trustedRoots: [fx('receipt-no-signer-oid-root.der')], bundleId: BUNDLE });
  assert.throws(() => v.verify(fx('receipt-no-signer-oid.der')),
    (e) => e.reason === 'INVALID_CERTIFICATE_PURPOSE');
});

test('rejects a JWS whose leaf lacks the Apple marker OID', () => {
  const v = new JwsVerifier({ trustedRoots: [fx('jws-no-leaf-oid-root.der')], bundleId: BUNDLE, acceptedEnvironments: ['Sandbox'] });
  assert.throws(() => v.verifyTransaction(txt('transaction-no-leaf-oid.jws')),
    (e) => e.reason === 'INVALID_CERTIFICATE_PURPOSE');
});

test('rejects a JWS whose intermediate lacks the WWDR marker OID', () => {
  const v = new JwsVerifier({ trustedRoots: [fx('jws-no-intermediate-oid-root.der')], bundleId: BUNDLE, acceptedEnvironments: ['Sandbox'] });
  assert.throws(() => v.verifyTransaction(txt('transaction-no-intermediate-oid.jws')),
    (e) => e.reason === 'INVALID_CERTIFICATE_PURPOSE');
});

test('Production AppTransaction enforces appAppleId', () => {
  const good = new JwsVerifier({ trustedRoots: [fx('jws-root.der')], bundleId: BUNDLE, acceptedEnvironments: ['Production'], appAppleId: 123456789 });
  assert.equal(good.verifyAppTransaction(txt('app-transaction-production.jws')).appAppleId, 123456789);
  const bad = new JwsVerifier({ trustedRoots: [fx('jws-root.der')], bundleId: BUNDLE, acceptedEnvironments: ['Production'], appAppleId: 999 });
  assert.throws(() => bad.verifyAppTransaction(txt('app-transaction-production.jws')),
    (e) => e.reason === 'WRONG_APP_APPLE_ID');
});

test('receipt signing-time cert validity behaves as manifested', () => {
  const v = new ReceiptVerifier({ trustedRoots: [fx('receipt-expired-root.der')], bundleId: BUNDLE });
  assert.equal(v.verify(fx('receipt-expired-historical.der')).appVersion, '1.2.3');
  assert.throws(() => v.verify(fx('receipt-expired-fresh.der')), (e) => e.reason === 'INVALID_CHAIN');
});
