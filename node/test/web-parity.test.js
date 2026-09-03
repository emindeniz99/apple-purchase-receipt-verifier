// Verdict parity: every fixture the Node suite verifies, run through BOTH
// builds, asserting the same verdict — the same payload field for field, or
// the same VerificationError reason AND message. A web build that merely
// "works" is not the goal; a web build that ever disagrees with the Node one
// about a receipt is the failure this file exists to catch.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const BUNDLE = 'com.example.app';

const read = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
const gen = (name) => read(`fixtures/generated/${name}`);
const genText = (name) => gen(name).toString('ascii').trim();
const publicReceipt = (name) => read(`fixtures/public-receipts/${name}.b64`).toString('ascii').trim();
const official = (...parts) => read(`fixtures/apple-official/${parts.join('/')}`);
const officialText = (...parts) => official(...parts).toString('ascii').trim();

// --- verdict capture -----------------------------------------------------

/** Structural form of a value, identical whether bytes arrive as Buffer or Uint8Array. */
function canon(value) {
  if (value === undefined) {
    return '<undefined>';
  }
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (value instanceof Date) {
    return `date:${value.toISOString()}`;
  }
  if (ArrayBuffer.isView(value)) {
    return `bytes:${Buffer.from(value.buffer, value.byteOffset, value.byteLength).toString('hex')}`;
  }
  if (value instanceof Map) {
    return { map: [...value].map(([k, v]) => [k, canon(v)]).sort((a, b) => (a[0] > b[0] ? 1 : -1)) };
  }
  if (Array.isArray(value)) {
    return value.map(canon);
  }
  const out = {};
  for (const key of Object.keys(value).sort()) {
    out[key] = canon(value[key]);
  }
  return out;
}

async function outcome(run) {
  try {
    const value = await run();
    return { verdict: { ok: canon(value) }, value };
  } catch (error) {
    if (typeof error?.reason === 'string' && error.name === 'VerificationError') {
      return { verdict: { reason: error.reason, message: error.message } };
    }
    return { verdict: { threw: error?.constructor?.name, message: error?.message } };
  }
}

// --- the cases -----------------------------------------------------------

/**
 * Each case names the two verifier factories and the call. Both sides get
 * the same bytes: Buffers for the Node build (its documented input), the
 * same bytes as a Uint8Array view for the web build.
 */
const bytes = (buffer) => new Uint8Array(buffer);

function jwsCase(name, { roots, options = {}, jws, method = 'verifyTransaction',
  expect = null, check = null }) {
  return {
    name,
    expect,
    check,
    node: () => new node.JwsVerifier({
      trustedRoots: roots.map((r) => (typeof r === 'string' ? r : Buffer.from(r))),
      bundleId: BUNDLE, acceptedEnvironments: ['Sandbox'], ...options,
    })[method](jws),
    web: () => new web.JwsVerifier({
      trustedRoots: roots.map((r) => (typeof r === 'string' ? r : bytes(r))),
      bundleId: BUNDLE, acceptedEnvironments: ['Sandbox'], ...options,
    })[method](jws),
  };
}

function receiptCase(name, { roots, bundleId = BUNDLE, receipt, guid = null, builtin = false,
  expect = null, check = null }) {
  const nodeRoots = () => (builtin ? node.appleReceiptRoots()
    : roots.map((r) => (typeof r === 'string' ? r : Buffer.from(r))));
  const webRoots = () => (builtin ? web.appleReceiptRoots()
    : roots.map((r) => (typeof r === 'string' ? r : bytes(r))));
  return {
    name,
    expect,
    check,
    node: () => new node.ReceiptVerifier({ trustedRoots: nodeRoots(), bundleId })
      .verify(typeof receipt === 'string' ? receipt : Buffer.from(receipt),
        guid === null ? null : Buffer.from(guid)),
    web: () => new web.ReceiptVerifier({ trustedRoots: webRoots(), bundleId })
      .verify(typeof receipt === 'string' ? receipt : bytes(receipt),
        guid === null ? null : bytes(guid)),
  };
}

const JWS_ROOT = gen('jws-root.der');
const RECEIPT_ROOT = gen('receipt-root.der');
const DEVICE_GUID = Buffer.from(genText('device-guid.hex'), 'hex');

// A payload segment re-encoded with a different productId: the signature no
// longer covers it (negative.test.js).
const TAMPERED_JWS = (() => {
  const [header, payload, signature] = genText('transaction.jws').split('.');
  const claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  claims.productId = `${BUNDLE}.premium_forever`;
  return `${header}.${Buffer.from(JSON.stringify(claims)).toString('base64url')}.${signature}`;
})();

const TAMPERED_RECEIPT = (() => {
  const copy = Buffer.from(gen('receipt.der'));
  copy[copy.indexOf(Buffer.from(BUNDLE, 'utf8'))] ^= 0x01;
  return copy;
})();

const WRONG_GUID = (() => {
  const copy = Buffer.from(DEVICE_GUID);
  copy[0] ^= 0x01;
  return copy;
})();

const cases = [
  // shared-fixtures.test.js
  jwsCase('shared transaction fixture', {
    roots: [JWS_ROOT], jws: genText('transaction.jws'),
    check: (p) => {
      assert.equal(p.productId, `${BUNDLE}.pro`);
      assert.equal(p.transactionId, '2000000000000001');
      assert.equal(p.signedDate, 1722945600000);
    },
  }),
  jwsCase('shared AppTransaction fixture', {
    roots: [JWS_ROOT], options: { appAppleId: 123456789 },
    jws: genText('app-transaction.jws'), method: 'verifyAppTransaction',
    check: (p) => {
      assert.equal(p.appAppleId, 123456789);
      assert.equal(p.applicationVersion, '1.2.3');
    },
  }),
  jwsCase('expired chain, historical signing date', {
    roots: [gen('jws-expired-root.der')], jws: genText('expired-cert-historical.jws'),
    check: (p) => assert.equal(p.signedDate, 1590969600000),
  }),
  jwsCase('expired chain, fresh signing date', {
    roots: [gen('jws-expired-root.der')], jws: genText('expired-cert-fresh.jws'),
    expect: 'INVALID_CHAIN',
  }),
  receiptCase('shared receipt fixture with device hash', {
    roots: [RECEIPT_ROOT], receipt: gen('receipt.der'), guid: DEVICE_GUID,
    check: (r) => {
      assert.equal(r.appVersion, '1.2.3');
      assert.equal(r.creationDate.toISOString(), '2024-08-06T12:00:00.000Z');
      assert.equal(r.inAppPurchases.length, 2);
      const vip = r.inAppPurchases.find((purchase) => purchase.productId === `${BUNDLE}.vip`);
      assert.equal(vip.expiresDate.toISOString(), '2030-02-01T09:30:00.000Z');
      assert.equal(vip.webOrderLineItemId, 42);
    },
  }),
  receiptCase('shared receipt fixture without device hash', {
    roots: [RECEIPT_ROOT], receipt: gen('receipt.der'),
    // Forward compatibility: an attribute type the library does not model
    // still reaches the caller, byte for byte (PLAN D10).
    check: (r) => assert.deepEqual([...r.unknownAttributes.get(9999)]
      .map((v) => [...v]), [[1, 2, 3]]),
  }),
  receiptCase('foreign-root receipt fixture', {
    roots: [RECEIPT_ROOT], receipt: gen('receipt-foreign.der'),
    expect: 'INVALID_CHAIN',
  }),
  receiptCase('double-wrapped (Xcode-style) receipt payload', {
    roots: [RECEIPT_ROOT], receipt: gen('receipt-double-wrapped.der'),
    check: (r) => assert.equal(r.appVersion, '1.2.3'),
  }),

  // parity.test.js
  receiptCase('receipt signer without the Apple receipt-signing OID', {
    roots: [gen('receipt-no-signer-oid-root.der')], receipt: gen('receipt-no-signer-oid.der'),
    expect: 'INVALID_CERTIFICATE_PURPOSE',
  }),
  jwsCase('JWS leaf without the Apple marker OID', {
    roots: [gen('jws-no-leaf-oid-root.der')], jws: genText('transaction-no-leaf-oid.jws'),
    expect: 'INVALID_CERTIFICATE_PURPOSE',
  }),
  jwsCase('JWS intermediate without the WWDR marker OID', {
    roots: [gen('jws-no-intermediate-oid-root.der')],
    jws: genText('transaction-no-intermediate-oid.jws'),
    expect: 'INVALID_CERTIFICATE_PURPOSE',
  }),
  jwsCase('Production AppTransaction with the right appAppleId', {
    roots: [JWS_ROOT], options: { acceptedEnvironments: ['Production'], appAppleId: 123456789 },
    jws: genText('app-transaction-production.jws'), method: 'verifyAppTransaction',
    check: (p) => assert.equal(p.appAppleId, 123456789),
  }),
  jwsCase('Production AppTransaction with the wrong appAppleId', {
    roots: [JWS_ROOT], options: { acceptedEnvironments: ['Production'], appAppleId: 999 },
    jws: genText('app-transaction-production.jws'), method: 'verifyAppTransaction',
    expect: 'WRONG_APP_APPLE_ID',
  }),
  receiptCase('receipt with a historical creation date and an expired chain', {
    roots: [gen('receipt-expired-root.der')], receipt: gen('receipt-expired-historical.der'),
    check: (r) => assert.equal(r.appVersion, '1.2.3'),
  }),
  receiptCase('receipt with a fresh creation date and an expired chain', {
    roots: [gen('receipt-expired-root.der')], receipt: gen('receipt-expired-fresh.der'),
    expect: 'INVALID_CHAIN',
  }),

  // negative.test.js
  jwsCase('tampered payload segment', {
    roots: [JWS_ROOT], jws: TAMPERED_JWS, expect: 'INVALID_SIGNATURE',
  }),
  jwsCase('bundle id mismatch', {
    roots: [JWS_ROOT], options: { bundleId: 'com.other.app' }, jws: genText('transaction.jws'),
    expect: 'WRONG_BUNDLE_ID',
  }),
  jwsCase('environment outside the accept set', {
    roots: [JWS_ROOT], options: { acceptedEnvironments: ['Production'] },
    jws: genText('transaction.jws'), expect: 'WRONG_ENVIRONMENT',
  }),
  jwsCase('stale payload', {
    roots: [JWS_ROOT], options: { maxSignedAgeMillis: 60_000 }, jws: genText('transaction.jws'),
    expect: 'STALE_PAYLOAD',
  }),
  // clock.test.js proves the seam per build; this proves the two builds read
  // it the same way — the same payload flips to fresh in both.
  jwsCase('stale payload judged by an injected clock', {
    roots: [JWS_ROOT], jws: genText('transaction.jws'),
    // transaction.jws is signed at 2024-08-06T12:00:00Z; 30s later.
    options: { maxSignedAgeMillis: 60_000, clock: () => new Date(1722945630000) },
    check: (payload) => assert.equal(payload.signedDate, 1722945600000),
  }),
  jwsCase('garbage JWS input', {
    roots: [JWS_ROOT], jws: 'not-a-jws', expect: 'INVALID_JWS_FORMAT',
  }),
  jwsCase('two-segment JWS input', {
    roots: [JWS_ROOT], jws: 'aaa.bbb', expect: 'INVALID_JWS_FORMAT',
  }),
  jwsCase('verifyRaw skips the claim checks', {
    roots: [JWS_ROOT], options: { bundleId: 'com.whatever.else' },
    jws: genText('transaction.jws'), method: 'verifyRaw',
    check: (claims) => assert.equal(claims.bundleId, BUNDLE),
  }),
  receiptCase('tampered receipt payload byte', {
    roots: [RECEIPT_ROOT], receipt: TAMPERED_RECEIPT, expect: 'INVALID_SIGNATURE',
  }),
  receiptCase('receipt whose bundle id is not the configured one', {
    roots: [RECEIPT_ROOT], bundleId: 'com.other.app', receipt: gen('receipt.der'),
    expect: 'WRONG_BUNDLE_ID',
  }),
  receiptCase('wrong device GUID', {
    roots: [RECEIPT_ROOT], receipt: gen('receipt.der'), guid: WRONG_GUID,
    expect: 'DEVICE_HASH_MISMATCH',
  }),
  receiptCase('garbage receipt bytes', {
    roots: [RECEIPT_ROOT], receipt: Buffer.from([1, 2, 3, 4]),
    expect: 'INVALID_RECEIPT_FORMAT',
  }),
  receiptCase('empty receipt bytes', {
    roots: [RECEIPT_ROOT], receipt: Buffer.alloc(0), expect: 'INVALID_RECEIPT_FORMAT',
  }),
  receiptCase('trailing bytes after the CMS blob', {
    roots: [RECEIPT_ROOT],
    receipt: Buffer.concat([gen('receipt.der'), Buffer.from([0, 0xde, 0xad, 0xbe])]),
    expect: 'INVALID_RECEIPT_FORMAT',
  }),

  // public-receipts.test.js — genuine Apple receipts, built-in Apple roots
  receiptCase('genuine sandbox receipt (SHA-256 chain), built-in roots', {
    builtin: true, bundleId: 'dev.bonzer.weeka.app', receipt: publicReceipt('receipt-sandbox-g5'),
    check: (r) => assert.equal(r.receiptType, 'ProductionSandbox'),
  }),
  receiptCase('genuine legacy receipt (SHA-1 chain, 187 purchases), built-in roots', {
    builtin: true, bundleId: 'com.nutcall.alert', receipt: publicReceipt('receipt-sandbox-legacy'),
    check: (r) => assert.equal(r.inAppPurchases.length, 187),
  }),
  receiptCase('Xcode-signed public receipt, built-in roots', {
    builtin: true, bundleId: '*', receipt: publicReceipt('receipt-xcode-with-purchases'),
    expect: 'INVALID_CHAIN',
  }),
  receiptCase('genuine sandbox receipt against the real Apple root as DER', {
    roots: [read('node/certs/AppleIncRootCertificate.cer')], bundleId: 'dev.bonzer.weeka.app',
    receipt: publicReceipt('receipt-sandbox-g5'),
    check: (r) => assert.equal(r.bundleId, 'dev.bonzer.weeka.app'),
  }),

  // apple-official.test.js — Apple's own fixtures, PEM and DER trust roots
  jwsCase("Apple's official transactionInfo fixture", {
    roots: [official('certs', 'testCA.der')], options: { bundleId: 'com.example' },
    jws: officialText('mock_signed_data', 'transactionInfo'),
    check: (p) => {
      assert.equal(p.bundleId, 'com.example');
      assert.equal(p.environment, 'Sandbox');
      assert.equal(p.signedDate, 1672956154000);
    },
  }),
  jwsCase("Apple's official transactionInfo fixture, PEM root", {
    roots: [officialText('certs', 'testCA.pem')], options: { bundleId: 'com.example' },
    jws: officialText('mock_signed_data', 'transactionInfo'),
    check: (p) => assert.equal(p.signedDate, 1672956154000),
  }),
  jwsCase("Apple's official renewalInfo fixture", {
    roots: [official('certs', 'testCA.der')], options: { bundleId: 'com.example' },
    jws: officialText('mock_signed_data', 'renewalInfo'), method: 'verifyRaw',
    check: (claims) => assert.equal(claims.environment, 'Sandbox'),
  }),
  jwsCase("Apple's official testNotification fixture", {
    roots: [official('certs', 'testCA.der')], options: { bundleId: 'com.example' },
    jws: officialText('mock_signed_data', 'testNotification'), method: 'verifyRaw',
    check: (claims) => assert.equal(claims.notificationType, 'TEST'),
  }),
  jwsCase("Apple's wrongBundleId fixture", {
    roots: [official('certs', 'testCA.der')], options: { bundleId: 'com.example' },
    jws: officialText('mock_signed_data', 'wrongBundleId'), expect: 'WRONG_BUNDLE_ID',
  }),
  jwsCase("Apple's missingX5CHeaderClaim fixture", {
    roots: [official('certs', 'testCA.der')], options: { bundleId: 'com.example' },
    jws: officialText('mock_signed_data', 'missingX5CHeaderClaim'),
    expect: 'INVALID_JWS_FORMAT',
  }),
  jwsCase("Apple's legacyTransaction fixture", {
    roots: [official('certs', 'testCA.der')], options: { bundleId: 'com.example' },
    jws: officialText('mock_signed_data', 'legacyTransaction'), expect: 'INVALID_JWS_FORMAT',
  }),
  jwsCase('Xcode-signed transaction (1-cert local chain)', {
    roots: [official('certs', 'testCA.der')], options: { bundleId: 'com.example' },
    jws: officialText('xcode', 'xcode-signed-transaction'), expect: 'INVALID_JWS_FORMAT',
  }),
  receiptCase('genuine Xcode receipt against the real Apple roots', {
    builtin: true, bundleId: 'com.example.naturelab.backyardbirds.example',
    receipt: officialText('xcode', 'xcode-app-receipt-empty'), expect: 'INVALID_CHAIN',
  }),
  receiptCase('Xcode receipt with a transaction, real Apple roots', {
    builtin: true, bundleId: 'com.example.naturelab.backyardbirds.example',
    receipt: officialText('xcode', 'xcode-app-receipt-with-transaction'), expect: 'INVALID_CHAIN',
  }),
];

for (const { name, expect, check, node: runNode, web: runWeb } of cases) {
  test(`web build agrees with the Node build: ${name}`, async () => {
    const fromNode = await outcome(runNode);
    const fromWeb = await outcome(runWeb);
    assert.deepEqual(fromWeb.verdict, fromNode.verdict);
    // Two builds that both threw a foreign error would compare equal while
    // proving nothing, and so would two that agreed on the wrong verdict:
    // every case states what the answer has to be.
    assert.equal(fromNode.verdict.threw, undefined,
      `Node build threw ${fromNode.verdict.threw}: ${fromNode.verdict.message}`);
    if (expect !== null) {
      assert.equal(fromWeb.verdict.reason, expect,
        `expected ${expect}, got ${JSON.stringify(fromWeb.verdict).slice(0, 200)}`);
    } else {
      assert.ok(fromWeb.value !== undefined,
        `expected a verified payload, got ${JSON.stringify(fromWeb.verdict).slice(0, 200)}`);
      check(fromWeb.value);
    }
  });
}

test('both builds bundle the same three Apple roots', () => {
  const fromWeb = web.appleReceiptRoots();
  const fromNode = node.appleReceiptRoots();
  assert.equal(fromWeb.length, 3);
  assert.equal(fromNode.length, 3);
  for (let i = 0; i < 3; i++) {
    assert.deepEqual(Buffer.from(fromWeb[i]), Buffer.from(fromNode[i].raw));
  }
  assert.deepEqual(web.appleJwsRoots().map((r) => Buffer.from(r).toString('hex')),
    fromWeb.map((r) => Buffer.from(r).toString('hex')));
});

test('both builds expose the same Reason vocabulary and Environment set', () => {
  assert.deepEqual(web.Reason, node.Reason);
  assert.deepEqual(web.Environment, node.Environment);
});
