import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { JwsVerifier, ReceiptVerifier, appleJwsRoots, appleReceiptRoots } from '../src/index.js';

const BUNDLE = 'com.example.app';

function fixture(name) {
  return readFileSync(fileURLToPath(new URL(`../../fixtures/generated/${name}`, import.meta.url)));
}

const text = (name) => fixture(name).toString('ascii').trim();

function verifier(options = {}) {
  return new JwsVerifier({
    trustedRoots: [fixture('jws-root.der')],
    bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'],
    ...options,
  });
}

test('rejects a tampered payload segment', () => {
  const [header, payload, signature] = text('transaction.jws').split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  claims.productId = `${BUNDLE}.premium_forever`;
  const forged = Buffer.from(JSON.stringify(claims)).toString('base64url');
  assert.throws(() => verifier().verifyTransaction(`${header}.${forged}.${signature}`),
    (e) => e.reason === 'INVALID_SIGNATURE');
});

test('rejects a bundle id mismatch', () => {
  assert.throws(() => verifier({ bundleId: 'com.other.app' }).verifyTransaction(text('transaction.jws')),
    (e) => e.reason === 'WRONG_BUNDLE_ID');
});

test('rejects an environment outside the accept set', () => {
  assert.throws(() => verifier({ acceptedEnvironments: ['Production'] }).verifyTransaction(text('transaction.jws')),
    (e) => e.reason === 'WRONG_ENVIRONMENT');
});

test('rejects a stale payload when maxSignedAgeMillis is set', () => {
  assert.throws(() => verifier({ maxSignedAgeMillis: 60_000 }).verifyTransaction(text('transaction.jws')),
    (e) => e.reason === 'STALE_PAYLOAD');
});

test('rejects garbage JWS input', () => {
  assert.throws(() => verifier().verifyTransaction('not-a-jws'),
    (e) => e.reason === 'INVALID_JWS_FORMAT');
});

test('rejects a chain from a foreign root (real Apple root as verifier anchor)', () => {
  const pinned = new JwsVerifier({
    trustedRoots: appleJwsRoots(), bundleId: BUNDLE, acceptedEnvironments: ['Sandbox'],
  });
  assert.throws(() => pinned.verifyTransaction(text('transaction.jws')),
    (e) => e.reason === 'INVALID_CHAIN');
});

test('verifyRaw skips claim checks but not the signature', () => {
  const claims = verifier({ bundleId: 'com.whatever.else' }).verifyRaw(text('transaction.jws'));
  assert.equal(claims.bundleId, BUNDLE);
});

test('rejects a tampered receipt payload byte', () => {
  const tampered = Buffer.from(fixture('receipt.der'));
  const index = tampered.indexOf(Buffer.from(BUNDLE, 'utf8'));
  assert.ok(index > 0);
  tampered[index] ^= 0x01;
  const receiptVerifier = new ReceiptVerifier({
    trustedRoots: [fixture('receipt-root.der')], bundleId: BUNDLE,
  });
  assert.throws(() => receiptVerifier.verify(tampered),
    (e) => e.reason === 'INVALID_SIGNATURE');
});

test('rejects a wrong device GUID', () => {
  const receiptVerifier = new ReceiptVerifier({
    trustedRoots: [fixture('receipt-root.der')], bundleId: BUNDLE,
  });
  const guid = Buffer.from(text('device-guid.hex'), 'hex');
  guid[0] ^= 0x01;
  assert.throws(() => receiptVerifier.verify(fixture('receipt.der'), guid),
    (e) => e.reason === 'DEVICE_HASH_MISMATCH');
});

test('rejects garbage receipt bytes', () => {
  const receiptVerifier = new ReceiptVerifier({
    trustedRoots: [fixture('receipt-root.der')], bundleId: BUNDLE,
  });
  assert.throws(() => receiptVerifier.verify(Buffer.from([1, 2, 3, 4])),
    (e) => e.reason === 'INVALID_RECEIPT_FORMAT');
});

test('bundled Apple roots load and look right', () => {
  assert.match(appleJwsRoots()[0].subject, /Apple Root CA - G3/);
  assert.match(appleReceiptRoots()[0].subject, /Apple Root CA/);
});
