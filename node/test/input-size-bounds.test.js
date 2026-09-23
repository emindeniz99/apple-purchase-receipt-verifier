// Input size caps: every input an attacker controls is measured before the
// step that would allocate in proportion to it (base64 decode, CMS parse,
// JSON parse, JWS split), because all of those run before any signature has
// been checked. The receipt and request caps are Apple's own limit, fixed in
// every port by fixtures/cases.json, so the same input gets the same answer
// everywhere.
//
// For each cap: one unit over is refused with the exact reason and message,
// and the step it guards provably did not run; exactly at the cap is not
// refused by the cap. Both builds run the same table.
// oxlint-disable no-await-in-loop -- one call at a time on purpose: the JSON.parse spy is global, so overlapping calls would count each other's parses
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';

const BUILDS = [
  ['node', node],
  ['web', web],
];

const MAX_RECEIPT_BYTES = 3145728;
const MAX_REQUEST_BYTES = 3145728;
const MAX_JWS_BYTES = 262144;
const MAX_DEPTH = 64;
const BUNDLE = 'com.example.app';

const gen = (name) =>
  readFileSync(fileURLToPath(new URL(`../../fixtures/generated/${name}`, import.meta.url)));
const receiptB64 = gen('receipt.der').toString('base64');

async function failureOf(call) {
  try {
    await call();
  } catch (error) {
    return error;
  }
  assert.fail('expected a VerificationError');
}

// Counts calls to a global method made on (or with) an oversized input while
// `call` runs, so a test can show the guarded step never saw it.
async function countingCalls(owner, name, isOversized, call) {
  const original = owner[name];
  let calls = 0;
  owner[name] = function (...args) {
    if (isOversized(this, args)) {
      calls++;
    }
    return original.apply(this, args);
  };
  try {
    await call();
  } finally {
    owner[name] = original;
  }
  return calls;
}

// A genuine receipt followed by spaces. receipt-data is canonical base64
// only, so this is refused with or without the cap: the over-cap tests show
// the cap fired by its message and by the shape check never running.
const paddedReceipt = (length) => receiptB64 + ' '.repeat(length - receiptB64.length);

// Canonical base64 admits nothing around the data, so the string AT the cap
// is a genuinely signed receipt whose base64 is exactly the cap
// (ReceiptBase64CapFixture), under a root of its own.
const atCapReceipt = readFileSync(
  fileURLToPath(new URL('../../fixtures/limits/receipt-b64-at-cap.txt', import.meta.url)),
  'ascii',
);

// A verifyReceipt body of exactly `bytes` UTF-8 bytes: the genuine receipt
// plus an extra member whose value fills the rest with `unit`.
function bodyOfBytes(bytes, unit = ' ') {
  const head = `{"receipt-data":"${receiptB64}","pad":"`;
  const tail = '"}';
  const unitBytes = Buffer.byteLength(unit);
  const room = bytes - Buffer.byteLength(head + tail);
  const body = head + unit.repeat(Math.floor(room / unitBytes)) + ' '.repeat(room % unitBytes);
  const out = body + tail;
  assert.equal(Buffer.byteLength(out), bytes);
  return out;
}

// The genuine receipt body with an extra member nesting `depth - 1` arrays,
// so the whole document has `depth` containers open at its deepest point.
const bodyOfDepth = (depth) =>
  `{"receipt-data":"${receiptB64}","x":${'['.repeat(depth - 1)}${']'.repeat(depth - 1)}}`;

// A header that parses and fails the alg check, padded out with payload
// characters: that verdict is what the split and header parse produce, so
// seeing it proves they ran and not seeing it proves they did not.
const jwsOfLength = (length) => {
  const header = Buffer.from('{"alg":"none"}').toString('base64url');
  return `${header}.${'A'.repeat(length - header.length - 2)}.`;
};

// `depth - 1` nested arrays: inside a JSON object, `depth` containers open.
const nested = (depth) => `${'['.repeat(depth - 1)}${']'.repeat(depth - 1)}`;
const b64url = (text) => Buffer.from(text).toString('base64url');

for (const [name, build] of BUILDS) {
  const receiptVerifier = () =>
    new build.ReceiptVerifier({ trustedRoots: [gen('receipt-root.der')], bundleId: BUNDLE });
  const endpoint = () =>
    new build.VerifyReceiptEndpoint({
      trustedRoots: [gen('receipt-root.der')],
      environment: 'Sandbox',
    });
  const jwsVerifier = () =>
    new build.JwsVerifier({
      trustedRoots: [gen('jws-root.der')],
      bundleId: BUNDLE,
      acceptedEnvironments: ['Sandbox'],
    });

  // Apple's verifyReceipt answers a 3,145,728-byte request body and refuses a
  // 3,145,729-byte one with HTTP 413 (measured 2026-09-23), and no receipt it
  // accepts can be larger than the body that carries it.
  test(`${name}: the caps are public and are Apple's numbers`, () => {
    assert.equal(build.ReceiptVerifier.MAX_RECEIPT_BYTES, MAX_RECEIPT_BYTES);
    assert.equal(build.VerifyReceiptEndpoint.MAX_REQUEST_BYTES, MAX_REQUEST_BYTES);
    assert.equal(build.JwsVerifier.MAX_JWS_BYTES, MAX_JWS_BYTES);
  });

  // --- receipt base64 string ------------------------------------------------

  const atCapRoots = [gen('receipt-b64-cap-root.der')];

  test(`${name}: a receipt string at the cap still verifies`, async () => {
    assert.equal(atCapReceipt.length, MAX_RECEIPT_BYTES);
    const verifier = new build.ReceiptVerifier({ trustedRoots: atCapRoots, bundleId: BUNDLE });
    const receipt = await verifier.verify(atCapReceipt);
    assert.equal(receipt.bundleId, BUNDLE);
  });

  test(`${name}: a receipt string one over the cap is refused before decoding`, async () => {
    const input = paddedReceipt(MAX_RECEIPT_BYTES + 1);
    let error;
    // The decode starts with the shape check, a RegExp test over the whole
    // string; the oversized string must never get that far.
    const shapeChecks = await countingCalls(
      RegExp.prototype,
      'test',
      (_self, args) => typeof args[0] === 'string' && args[0].length > MAX_RECEIPT_BYTES,
      async () => {
        error = await failureOf(() => receiptVerifier().verify(input));
      },
    );
    assert.equal(error.reason, build.Reason.INVALID_RECEIPT_FORMAT);
    assert.equal(
      error.message,
      'INVALID_RECEIPT_FORMAT: receipt exceeds the maximum accepted size of 3145728 bytes',
    );
    assert.equal(shapeChecks, 0);
  });

  // --- receipt DER -----------------------------------------------------------

  test(`${name}: DER at the cap reaches the parser; one over does not`, async () => {
    // A Buffer, which both builds take. Zeros are not ASN.1, so the
    // parser's own verdict (a different message) is what shows the at-cap
    // input got past the cap.
    const atCap = await failureOf(() => receiptVerifier().verify(Buffer.alloc(MAX_RECEIPT_BYTES)));
    assert.equal(atCap.reason, build.Reason.INVALID_RECEIPT_FORMAT);
    assert.doesNotMatch(atCap.message, /maximum accepted size/);

    const over = await failureOf(() =>
      receiptVerifier().verify(Buffer.alloc(MAX_RECEIPT_BYTES + 1)),
    );
    assert.equal(over.reason, build.Reason.INVALID_RECEIPT_FORMAT);
    assert.equal(
      over.message,
      'INVALID_RECEIPT_FORMAT: receipt exceeds the maximum accepted size of 3145728 bytes',
    );
  });

  // --- endpoint receipt-data -------------------------------------------------

  test(`${name}: endpoint receipt-data at the cap verifies, one over is 21002`, async () => {
    const atCap = await new build.VerifyReceiptEndpoint({
      trustedRoots: atCapRoots,
      environment: 'Sandbox',
    }).verifyReceiptData(atCapReceipt);
    assert.equal(atCap.status, 0);

    const over = await endpoint().verifyReceiptData(paddedReceipt(MAX_RECEIPT_BYTES + 1));
    assert.equal(over.failureReason, build.Reason.INVALID_RECEIPT_FORMAT);
    assert.equal(over.status, 21002);
    assert.equal(over.toJson(), '{"status":21002}');

    // An object body is not measured as a request, only its receipt-data.
    const asObject = await endpoint().verifyReceiptResult({
      'receipt-data': paddedReceipt(MAX_RECEIPT_BYTES + 1),
    });
    assert.equal(asObject.failureReason, build.Reason.INVALID_RECEIPT_FORMAT);
    assert.equal(asObject.toJson(), '{"status":21002}');
  });

  // --- endpoint request body -------------------------------------------------

  test(`${name}: a request body at the cap is parsed and verifies`, async () => {
    for (const unit of [' ', 'é', '€', '😀']) {
      const result = await endpoint().verifyReceiptResult(bodyOfBytes(MAX_REQUEST_BYTES, unit));
      assert.equal(result.status, 0, `padded with ${unit}`);
    }
  });

  test(`${name}: a request body one byte over the cap is 21002 before parsing`, async () => {
    // Multi-byte padding keeps the UTF-16 length under the cap while the
    // UTF-8 length is one over: the cap is on bytes, as on the wire.
    for (const unit of [' ', 'é', '€', '😀']) {
      const body = bodyOfBytes(MAX_REQUEST_BYTES + 1, unit);
      let result;
      const parses = await countingCalls(
        JSON,
        'parse',
        () => true,
        async () => {
          result = await endpoint().verifyReceiptResult(body);
        },
      );
      assert.equal(parses, 0, `JSON.parse ran on a body padded with ${unit}`);
      // REQUEST_TOO_LARGE, the reason an HTTP layer maps to 413 as Apple does.
      assert.equal(result.failureReason, build.Reason.REQUEST_TOO_LARGE);
      assert.equal(result.status, 21002);
      assert.equal(result.toJson(), '{"status":21002}');
      assert.equal(await endpoint().verifyReceiptJson(body), '{"status":21002}');
    }
  });

  // Apple counts UTF-8 bytes: 3,145,729 bytes of U+00E9, barely half the cap
  // in characters, got HTTP 413 on 2026-09-23. A port that measured the body
  // in UTF-16 units would let this body through and verify it.
  test(`${name}: a request body is measured in UTF-8 bytes, not characters`, async () => {
    const over = bodyOfBytes(MAX_REQUEST_BYTES + 1, 'é');
    assert.ok(over.length < MAX_REQUEST_BYTES * 0.6, 'a character count calls this far under');
    const overResult = await endpoint().verifyReceiptResult(over);
    assert.equal(overResult.failureReason, build.Reason.REQUEST_TOO_LARGE);
    assert.equal(overResult.status, 21002);

    const at = bodyOfBytes(MAX_REQUEST_BYTES, 'é');
    assert.equal((await endpoint().verifyReceiptResult(at)).status, 0);
  });

  // The size check comes before any other look at the body, so a huge body
  // that is not even JSON is REQUEST_TOO_LARGE, not MALFORMED_REQUEST.
  test(`${name}: an oversized body that is not JSON is REQUEST_TOO_LARGE`, async () => {
    const result = await endpoint().verifyReceiptResult('['.repeat(MAX_REQUEST_BYTES + 1));
    assert.equal(result.failureReason, build.Reason.REQUEST_TOO_LARGE);
    assert.equal(result.toJson(), '{"status":21002}');
  });

  // --- endpoint nesting depth ------------------------------------------------

  test(`${name}: a request nested ${MAX_DEPTH} deep is parsed and verifies`, async () => {
    const result = await endpoint().verifyReceiptResult(bodyOfDepth(MAX_DEPTH));
    assert.equal(result.status, 0);
  });

  test(`${name}: a request nested ${MAX_DEPTH + 1} deep is 21002 before parsing`, async () => {
    let result;
    const parses = await countingCalls(
      JSON,
      'parse',
      () => true,
      async () => {
        result = await endpoint().verifyReceiptResult(bodyOfDepth(MAX_DEPTH + 1));
      },
    );
    assert.equal(parses, 0);
    assert.equal(result.failureReason, build.Reason.MALFORMED_REQUEST);
    assert.equal(result.toJson(), '{"status":21002}');
  });

  test(`${name}: brackets inside JSON strings are not nesting`, async () => {
    // Includes an escaped quote, which must not end the string early.
    const inString = `\\"${'['.repeat(200)}{`;
    const body = `{"receipt-data":"${receiptB64}","x":"${inString}"}`;
    const result = await endpoint().verifyReceiptResult(body);
    assert.equal(result.status, 0);
  });

  // --- JWS compact string ----------------------------------------------------

  test(`${name}: a JWS at the cap is split and parsed`, async () => {
    const error = await failureOf(() =>
      jwsVerifier().verifyTransaction(jwsOfLength(MAX_JWS_BYTES)),
    );
    assert.equal(error.reason, build.Reason.INVALID_JWS_FORMAT);
    assert.equal(error.message, 'INVALID_JWS_FORMAT: alg must be ES256, got none');
  });

  test(`${name}: a JWS one over the cap is refused before it is split`, async () => {
    const input = jwsOfLength(MAX_JWS_BYTES + 1);
    let error;
    const splits = await countingCalls(
      String.prototype,
      'split',
      (self) => typeof self === 'string' && self.length > MAX_JWS_BYTES,
      async () => {
        error = await failureOf(() => jwsVerifier().verifyTransaction(input));
      },
    );
    assert.equal(splits, 0);
    assert.equal(error.reason, build.Reason.INVALID_JWS_FORMAT);
    assert.equal(
      error.message,
      'INVALID_JWS_FORMAT: jws exceeds the maximum accepted size of 262144 characters',
    );
  });

  // --- JWS JSON depth --------------------------------------------------------

  test(`${name}: a JWS header nested past ${MAX_DEPTH} is refused before parsing`, async () => {
    const headerOf = (depth) => b64url(`{"alg":"ES256","x":${nested(depth)}}`);
    // At the cap the header parses and fails on its missing x5c.
    const atCap = await failureOf(() =>
      jwsVerifier().verifyTransaction(`${headerOf(MAX_DEPTH)}.e30.`),
    );
    assert.equal(atCap.message, 'INVALID_JWS_FORMAT: x5c must contain exactly 3 certificates');

    const input = `${headerOf(MAX_DEPTH + 1)}.e30.`;
    let over;
    const parses = await countingCalls(
      JSON,
      'parse',
      () => true,
      async () => {
        over = await failureOf(() => jwsVerifier().verifyTransaction(input));
      },
    );
    assert.equal(parses, 0);
    assert.equal(over.reason, build.Reason.INVALID_JWS_FORMAT);
    assert.equal(over.message, 'INVALID_JWS_FORMAT: header nests deeper than 64 levels');
  });

  test(`${name}: a JWS payload nested past ${MAX_DEPTH} is refused`, async () => {
    const [header, payload, signature] = gen('transaction.jws').toString('ascii').trim().split('.');
    const claims = Buffer.from(payload, 'base64url').toString('utf8');
    assert.ok(claims.endsWith('}'));
    const withDepth = (depth) =>
      `${header}.${b64url(`${claims.slice(0, -1)},"x":${nested(depth)}}`)}.${signature}`;
    // At the cap the payload parses and the altered bytes fail the signature.
    const atCap = await failureOf(() => jwsVerifier().verifyTransaction(withDepth(MAX_DEPTH)));
    assert.equal(atCap.reason, build.Reason.INVALID_SIGNATURE);

    const over = await failureOf(() => jwsVerifier().verifyTransaction(withDepth(MAX_DEPTH + 1)));
    assert.equal(over.reason, build.Reason.INVALID_JWS_FORMAT);
    assert.equal(over.message, 'INVALID_JWS_FORMAT: payload nests deeper than 64 levels');
  });
}
