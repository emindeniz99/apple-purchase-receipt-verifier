// The public surface is the 0.7 API (docs/design/0.7-api.md) without the
// two environment helpers, which 0.8 replaced with the payloads'
// `environment` (DECISIONS.md R42), and the two entry points are one product: the same names, the same vocabulary, the
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
  'createConfig',
  'createInAppPurchase',
  'createJsonPayload',
  'createReceiptPayload',
  'createVerifier',
];

const gen = (name) =>
  readFileSync(fileURLToPath(new URL(`../../fixtures/generated-0.7/${name}`, import.meta.url)));

test('both entry points export exactly the same names', () => {
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
  const sync = node.createVerifier(node.createConfig());
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

test('createConfig() names no roots: Apple roots are pinned inside the module', () => {
  const config = node.createConfig();
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

// A root is the bytes a caller holds, DER or PEM (DECISIONS.md R39, amended):
// the module tells them apart, so a PEM certificate passed as its bytes
// verifies exactly as its DER does, and nothing here reads either format. A
// string is still not a root: text reaches the module only as bytes.
test('a PEM root passed as bytes verifies the same as its DER', async () => {
  const der = new Uint8Array(gen('receipt-root.der'));
  const pem = new X509Certificate(der).toString();
  assert.match(pem, /^-----BEGIN CERTIFICATE-----\n/);
  const receipt = gen('receipt.der').toString('base64');
  for (const [name, build, pemBytes] of [
    ['node', node, Buffer.from(pem)],
    ['web', web, new TextEncoder().encode(pem)],
  ]) {
    const config = await build.createConfig({ roots: [pemBytes] });
    assert.deepEqual(config.roots, [new Uint8Array(pemBytes)], `${name}: passed on as given`);
    const underPem = await build.createVerifier(config).verifyReceipt(receipt);
    const underDer = await build
      .createVerifier(await build.createConfig({ roots: [der] }))
      .verifyReceipt(receipt);
    assert.equal(underDer.verified, true, name);
    assert.equal(underPem.verified, true, name);
    // toJson is a closure per payload, so the payloads compare by their JSON.
    assert.equal(underPem.payload.toJson(), underDer.payload.toJson(), name);
  }
  const fix =
    /Uint8Array of DER or PEM bytes; pass a PEM string as new TextEncoder\(\)\.encode\(pem\) \(see README, custom roots\)/;
  assert.throws(() => node.createConfig({ roots: [pem] }), { name: 'TypeError', message: fix });
  assert.throws(() => node.createConfig({ roots: [der, 'not a certificate'] }), {
    name: 'TypeError',
    message: fix,
  });
  await assert.rejects(web.createConfig({ roots: [pem] }), { name: 'TypeError', message: fix });
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
  assert.equal(payload.environment, null);
  assert.deepEqual(node.createJsonPayload('{"a":1}'), { json: '{"a":1}', environment: null });
  assert.deepEqual(node.createJsonPayload('{"a":1}', node.Environment.SANDBOX), {
    json: '{"a":1}',
    environment: 'Sandbox',
  });
});

test('a hand-built payload states the environment it is given, outside toJson', () => {
  const payload = node.createReceiptPayload({
    receiptType: 'Xcode',
    environment: node.Environment.PRODUCTION,
  });
  assert.equal(payload.environment, 'Production', 'nothing derives it from receiptType');
  assert.ok(!('environment' in JSON.parse(payload.toJson())));
  assert.equal(
    node.createJsonPayload('{"environment":"Sandbox"}').environment,
    null,
    'nothing reads it from the JSON',
  );
});

test('a verified payload carries the environment the module states, outside toJson', () => {
  const verifier = node.createVerifier(
    node.createConfig({ roots: [new Uint8Array(gen('receipt-root.der'))] }),
  );
  const result = verifier.verifyReceipt(gen('receipt.der').toString('base64'));
  assert.equal(result.verified, true);
  assert.equal(result.payload.environment, node.Environment.SANDBOX);
  assert.ok(!('environment' in JSON.parse(result.payload.toJson())));
});
