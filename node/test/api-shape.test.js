// The public surface is the 0.7 API (docs/design/0.7-api.md), and the two
// entry points are one product: the same names, the same vocabulary, the
// same module underneath. A name added to or dropped from either entry
// point fails here first.
// oxlint-disable no-await-in-loop -- two entry points, one after the other, so a failure names its entry point
import test from 'node:test';
import assert from 'node:assert/strict';
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const EXPORTS = [
  'AppleStatus',
  'Environment',
  'Reason',
  'VerificationError',
  'createConfig',
  'createInAppPurchase',
  'createJsonPayload',
  'createReceiptPayload',
  'createVerifier',
  'defaultConfig',
  'environmentFromJwsEnvironment',
  'environmentFromReceiptType',
];

const gen = (name) =>
  readFileSync(fileURLToPath(new URL(`../../fixtures/generated-0.7/${name}`, import.meta.url)));

test('both entry points export exactly the 0.7 names', () => {
  assert.deepEqual(Object.keys(node).toSorted(), EXPORTS);
  assert.deepEqual(Object.keys(web).toSorted(), EXPORTS);
});

test('Reason is the eight 0.7 reasons, named as the module names them', () => {
  // docs/rust-core/SURFACE.md §3 and §7 ("Reason parity").
  assert.deepEqual(Object.values(node.Reason), [
    'MALFORMED',
    'TOO_LARGE',
    'INVALID_SIGNATURE',
    'UNTRUSTED_CHAIN',
    'INVALID_CERTIFICATE',
    'INVALID_CERTIFICATE_PURPOSE',
    'UNREADABLE_PAYLOAD',
    'INTERNAL_ERROR',
  ]);
  for (const [key, value] of Object.entries(node.Reason)) {
    assert.equal(key, value);
  }
});

test('both entry points share the vocabulary objects', () => {
  assert.equal(web.Reason, node.Reason);
  assert.equal(web.Environment, node.Environment);
  assert.equal(web.AppleStatus, node.AppleStatus);
  assert.deepEqual(node.Environment, { PRODUCTION: 'Production', SANDBOX: 'Sandbox' });
});

test('/web returns Promises where the default entry point returns values', async () => {
  const config = web.createConfig();
  assert.ok(config instanceof Promise);
  assert.ok(web.defaultConfig() instanceof Promise);
  const verifier = web.createVerifier(await config);
  const pending = [
    verifier.verifyReceipt('AQIDBA=='),
    verifier.verifySignedData('a.b'),
    verifier.verifyReceiptEndpoint(web.Environment.SANDBOX, '{}'),
  ];
  for (const p of pending) {
    assert.ok(p instanceof Promise);
  }
  await Promise.all(pending);
  const sync = node.createVerifier(node.defaultConfig());
  assert.equal(typeof sync.verifyReceiptEndpoint(node.Environment.SANDBOX, '{}'), 'string');
});

test('a result carries exactly one of payload and failure, in both entry points', async () => {
  for (const [name, build] of [
    ['node', node],
    ['web', web],
  ]) {
    const verifier = build.createVerifier(
      await build.createConfig({ roots: [new Uint8Array(gen('receipt-root.der'))] }),
    );
    const results = {
      verified: await verifier.verifyReceipt(gen('receipt.der').toString('base64')),
      malformed: await verifier.verifyReceipt('AQIDBA=='),
      'not a string': await verifier.verifyReceipt(undefined),
      'untrusted chain': await verifier.verifyReceipt(
        gen('receipt-foreign.der').toString('base64'),
      ),
      'malformed jws': await verifier.verifySignedData('a.b'),
    };
    for (const [label, result] of Object.entries(results)) {
      const at = `${name}: ${label}`;
      assert.notEqual(result.payload === undefined, result.failure === undefined, at);
      assert.equal(result.verified, result.payload !== undefined, at);
    }
  }
});

test('defaultConfig() names no roots: Apple roots are pinned inside the module', () => {
  const config = node.defaultConfig();
  assert.equal(config.roots, null);
  assert.equal(typeof config.clock(), 'number');
  assert.ok(Object.isFrozen(config));
});

test('createConfig copies DER roots', () => {
  const der = new Uint8Array(gen('receipt-root.der'));
  const config = node.createConfig({ roots: [der, Buffer.from(der)] });
  assert.deepEqual(config.roots, [der, der]);
  assert.notEqual(config.roots[0], der, 'the caller keeps their buffer; the config holds a copy');
  assert.throws(() => node.createConfig({ roots: [42] }), TypeError);
});

// Roots are DER in every package (DECISIONS.md R38). A PEM string is refused
// with a message that names the one-line fix, rather than unwrapped here.
test('createConfig refuses a PEM string root and names the DER it wants', async () => {
  const der = new Uint8Array(
    readFileSync(fileURLToPath(new URL('../../certs/AppleRootCA-G3.cer', import.meta.url))),
  );
  const pem = `-----BEGIN CERTIFICATE-----\n${Buffer.from(der)
    .toString('base64')
    .replace(/(.{64})/g, '$1\n')}\n-----END CERTIFICATE-----\n`;
  const fix = /new X509Certificate\(pem\)\.raw \(X509Certificate is in node:crypto\)/;
  assert.throws(() => node.createConfig({ roots: [pem] }), { name: 'TypeError', message: fix });
  assert.throws(() => node.createConfig({ roots: [der, 'not a certificate'] }), {
    name: 'TypeError',
    message: fix,
  });
  await assert.rejects(web.createConfig({ roots: [pem] }), { name: 'TypeError', message: fix });
  // The fix it names works: X509Certificate's raw bytes are the same DER.
  assert.deepEqual(node.createConfig({ roots: [new X509Certificate(pem).raw] }).roots, [der]);
});

test('createReceiptPayload and friends build what a caller mocks with', () => {
  const purchase = node.createInAppPurchase({ productId: 'p', webOrderLineItemId: '9' });
  const payload = node.createReceiptPayload({
    bundleId: 'b',
    bundleIdBytes: new Uint8Array([1, 2]),
    inApp: [purchase],
    unknownAttributes: new Map([[13, [new Uint8Array([255])]]]),
  });
  assert.equal(payload.receiptType, null);
  assert.equal(payload.inApp[0].quantity, null);
  assert.deepEqual(JSON.parse(payload.toJson()).bundle_id_bytes, 'AQI=');
  assert.deepEqual(JSON.parse(payload.toJson()).unknown_attributes, { 13: ['/w=='] });
  assert.equal(JSON.parse(payload.toJson()).in_app[0].web_order_line_item_id, '9');
  assert.deepEqual(node.createJsonPayload('{"a":1}'), { json: '{"a":1}' });
});
