// How the facade reads the module's answers (the aprv-wire JSON of
// docs/rust-core/ARCHITECTURE.md §4) into the 0.7 types. The receipt
// payloads come from fixtures/cases.json's own expected toJson values,
// which are the 0.7 "Our JSON" every port writes, so these hold whichever
// module is loaded.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { jwsAnswer, receiptAnswer } from '../dist/verifier.js';
import { Reason } from '../dist/index.js';

const CASES = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../fixtures/cases.json', import.meta.url)), 'utf8'),
).cases;
const WITH_TO_JSON = CASES.filter(
  (c) => c.operation === 'verifyReceipt' && c.expected.toJson !== undefined,
);

test('cases.json pins toJson for some verified receipts', () => {
  assert.ok(WITH_TO_JSON.length >= 10, `${WITH_TO_JSON.length}`);
});

for (const kase of WITH_TO_JSON) {
  test(`${kase.id}: the module's payload JSON becomes a ReceiptPayload with the same toJson`, () => {
    const result = receiptAnswer(`{"verified":true,"payload":${kase.expected.toJson}}`);
    assert.equal(result.verified, true);
    assert.equal(result.failure, undefined);
    const payload = result.payload;
    assert.deepEqual(JSON.parse(payload.toJson()), JSON.parse(kase.expected.toJson));
    const wire = JSON.parse(kase.expected.toJson);
    for (const [key, field] of [
      ['bundle_id_bytes', 'bundleIdBytes'],
      ['opaque_value', 'opaqueValue'],
      ['sha1_hash', 'sha1Hash'],
    ]) {
      if (wire[key] === null) {
        assert.equal(payload[field], null);
      } else {
        assert.ok(payload[field] instanceof Uint8Array, field);
        assert.equal(Buffer.from(payload[field]).toString('base64'), wire[key]);
      }
    }
    for (const [key, field] of [
      ['app_item_id', 'appItemId'],
      ['download_id', 'downloadId'],
      ['version_external_identifier', 'versionExternalIdentifier'],
    ]) {
      assert.equal(payload[field], wire[key], field);
    }
    assert.ok(payload.unknownAttributes instanceof Map);
    for (const [type, values] of payload.unknownAttributes) {
      assert.equal(typeof type, 'number');
      assert.ok(values.every((v) => v instanceof Uint8Array));
    }
    assert.equal(payload.inApp.length, wire.in_app.length);
  });
}

test('a verified JWS payload is the signed JSON text, exactly', () => {
  const signed = '{ "b":1,\n"a":"\\u00e9" }';
  const result = jwsAnswer(JSON.stringify({ verified: true, payload: signed }));
  assert.deepEqual(result, { verified: true, payload: { json: signed } });
});

test('each of the eight reasons comes back as a failure with its message and no cause', () => {
  for (const reason of Object.values(Reason)) {
    for (const read of [receiptAnswer, jwsAnswer]) {
      const result = read(JSON.stringify({ verified: false, reason, message: 'why' }));
      assert.deepEqual(result, { verified: false, failure: { reason, message: 'why' } });
    }
  }
});

test('an answer that is not the 0.7 wire format throws, for the facade to report', () => {
  const bad = [
    'not json',
    '[]',
    '{"verified":false,"reason":"INVALID_CHAIN","message":"a 0.6 reason"}',
    '{"verified":false,"reason":"MALFORMED"}',
    '{"verified":"true","payload":{}}',
    '{"verified":true,"payload":{"bundleId":"a 0.6 payload"}}',
  ];
  for (const text of bad) {
    assert.throws(() => receiptAnswer(text), text);
  }
  assert.throws(() => jwsAnswer('{"verified":true,"payload":{"a":1}}'));
  const receipt = JSON.parse(WITH_TO_JSON[0].expected.toJson);
  for (const mutate of [
    (r) => delete r.bundle_id,
    (r) => (r.app_item_id = 1),
    (r) => (r.in_app = {}),
    (r) => (r.unknown_attributes = { x: ['AA=='] }),
    (r) => (r.unknown_attributes = { 1: [1] }),
  ]) {
    const copy = structuredClone(receipt);
    mutate(copy);
    assert.throws(() => receiptAnswer(JSON.stringify({ verified: true, payload: copy })));
  }
});
