// The facade's own contract (docs/rust-core/ARCHITECTURE.md §4 to §7.4),
// through the public API. Every verdict here is the module's; what these
// tests pin is what the package does around it: caller misuse at create,
// the Environment mapping, the clock read, the input bytes, one instance
// per Verifier, and recovery after a failure inside the instance.
//
// The endpoint answers in Apple's own JSON, so most checks read its
// status: that part of the wire is the same for every module this package
// can load.
// oxlint-disable no-await-in-loop -- entry points and inputs one after the other, so a failure names its case
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import * as node from '../dist/index.js';
import * as web from '../dist/web/index.js';
import { randomGet } from '../dist/engine.js';

const repo = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
const APPLE_ROOTS = ['AppleIncRootCertificate.cer', 'AppleRootCA-G2.cer', 'AppleRootCA-G3.cer'].map(
  (f) => new Uint8Array(repo(`certs/${f}`)),
);
const JWS_ROOT = new Uint8Array(repo('fixtures/generated/jws-root.der'));
const JWS = repo('fixtures/generated/transaction.jws').toString('ascii').trim();
const G5 = repo('fixtures/public-receipts/receipt-sandbox-g5.b64').toString('ascii').trim();
const G5_REQUEST = JSON.stringify({ 'receipt-data': G5 });

const status = (body) => JSON.parse(body).status;

// --- caller misuse: thrown at create or at the call, never a verdict ------

test('a null config, or one with no roots, is a TypeError from createVerifier', async () => {
  for (const bad of [null, undefined]) {
    assert.throws(() => node.createVerifier(bad), TypeError);
    assert.throws(() => web.createVerifier(bad), TypeError);
  }
  assert.throws(() => node.createVerifier({ roots: [], clock: Date.now }), TypeError);
  assert.throws(() => node.createConfig({ roots: [] }), TypeError);
  await assert.rejects(web.createConfig({ roots: [] }), TypeError);
});

test('a root the module refuses fails createVerifier, not a later call', () => {
  const config = node.createConfig({ roots: [new Uint8Array([1, 2, 3])] });
  assert.throws(
    () => node.createVerifier(config),
    (error) =>
      error instanceof TypeError &&
      /refused a configured root/.test(error.message) &&
      error.cause?.name === 'InitRefusedError',
  );
});

test('the environment is one of the two values, or a TypeError', async () => {
  const verifier = node.createVerifier(node.defaultConfig());
  for (const bad of [null, undefined, 'production', 'Xcode', 0, 1, 2, 2 ** 32 + 1, 1n]) {
    assert.throws(() => verifier.verifyReceiptEndpoint(bad, G5_REQUEST), TypeError, String(bad));
  }
  const webVerifier = web.createVerifier(await web.defaultConfig());
  await assert.rejects(webVerifier.verifyReceiptEndpoint(2, G5_REQUEST), TypeError);
});

test('PRODUCTION and SANDBOX reach the module as the two endpoints', () => {
  const verifier = node.createVerifier(node.defaultConfig());
  // A sandbox receipt: 21007 on the production URL, 0 on the sandbox one.
  assert.equal(
    status(verifier.verifyReceiptEndpoint(node.Environment.PRODUCTION, G5_REQUEST)),
    21007,
  );
  assert.equal(status(verifier.verifyReceiptEndpoint(node.Environment.SANDBOX, G5_REQUEST)), 0);
});

// --- the clock ---------------------------------------------------------------

test('the clock is read exactly once per call, whatever the input', async () => {
  let reads = 0;
  const config = node.createConfig({
    clock: () => {
      reads += 1;
      return Date.parse('2025-01-01T00:00:00Z');
    },
  });
  const verifier = node.createVerifier(config);
  const calls = [
    () => verifier.verifyReceipt(G5),
    () => verifier.verifyReceipt(''),
    () => verifier.verifyReceipt(undefined),
    () => verifier.verifySignedData('a.b.c'),
    () => verifier.verifyReceiptEndpoint(node.Environment.SANDBOX, G5_REQUEST),
    () => verifier.verifyReceiptEndpoint(node.Environment.SANDBOX, 'not json'),
  ];
  for (const call of calls) {
    const before = reads;
    call();
    assert.equal(reads - before, 1);
  }
  assert.equal(reads, calls.length);
  // A misused environment is thrown before the clock is read.
  assert.throws(() => verifier.verifyReceiptEndpoint(null, G5_REQUEST), TypeError);
  assert.equal(reads, calls.length);
});

test('the clock value is the now-ms the module uses for request_date', () => {
  const fixed = Date.parse('2025-03-04T05:06:07Z');
  const verifier = node.createVerifier(node.createConfig({ clock: () => fixed + 0.9 }));
  const body = JSON.parse(verifier.verifyReceiptEndpoint(node.Environment.SANDBOX, G5_REQUEST));
  assert.equal(body.status, 0);
  assert.equal(body.receipt.request_date_ms, String(fixed));
});

test('a clock that throws is INTERNAL_ERROR with the cause, and 21009 at the endpoint', async () => {
  const boom = new Error('clock down');
  for (const build of [node, web]) {
    const verifier = build.createVerifier(
      await build.createConfig({
        clock: () => {
          throw boom;
        },
      }),
    );
    for (const result of [
      await verifier.verifyReceipt(G5),
      await verifier.verifyReceipt('!!'),
      await verifier.verifySignedData(JWS),
    ]) {
      assert.equal(result.verified, false);
      assert.equal(result.failure.reason, 'INTERNAL_ERROR');
      assert.equal(result.failure.message, 'the configured clock failed');
      assert.equal(result.failure.cause, boom);
    }
    assert.equal(
      await verifier.verifyReceiptEndpoint(build.Environment.SANDBOX, G5_REQUEST),
      '{"status":21009}',
    );
  }
});

test('a clock that answers no epoch milliseconds is INTERNAL_ERROR, never a wrapped instant', () => {
  for (const value of [Number.NaN, -1, Infinity, 2 ** 53, '1700000000000', null, 1n]) {
    const verifier = node.createVerifier(node.createConfig({ clock: () => value }));
    const result = verifier.verifyReceipt(G5);
    assert.equal(result.failure?.reason, 'INTERNAL_ERROR', String(value));
    assert.match(result.failure.message, /did not answer epoch milliseconds/);
    assert.equal(
      verifier.verifyReceiptEndpoint(node.Environment.SANDBOX, G5_REQUEST),
      '{"status":21009}',
    );
  }
});

// --- input bytes -------------------------------------------------------------

test('the input reaches the module as its UTF-8 bytes, and only a string does', () => {
  const verifier = node.createVerifier(node.defaultConfig());
  const sandbox = node.Environment.SANDBOX;
  assert.equal(status(verifier.verifyReceiptEndpoint(sandbox, G5_REQUEST)), 0);
  // Not a string: the caller's value never reaches the bindings (jco would
  // coerce it), so the module sees no bytes at all.
  for (const value of [
    new String(G5_REQUEST),
    { toString: () => G5_REQUEST },
    [G5_REQUEST],
    null,
  ]) {
    assert.equal(status(verifier.verifyReceiptEndpoint(sandbox, value)), 21002);
  }
  // Text beyond ASCII and lone surrogates encode (U+FFFD for the latter)
  // and are answered, not thrown.
  for (const text of [`{"receipt-data":"${G5}é"}`, '{"receipt-data":"\ud800"}', '\u{1F600}']) {
    assert.equal(status(verifier.verifyReceiptEndpoint(sandbox, text)), 21002);
  }
});

// --- instances ---------------------------------------------------------------

test('each Verifier holds its own instance, initialised with its own roots', () => {
  const apple = node.createVerifier(node.createConfig({ roots: APPLE_ROOTS }));
  const other = node.createVerifier(node.createConfig({ roots: [JWS_ROOT] }));
  const defaults = node.createVerifier(node.defaultConfig());
  const sandbox = node.Environment.SANDBOX;
  assert.equal(status(apple.verifyReceiptEndpoint(sandbox, G5_REQUEST)), 0);
  assert.equal(status(other.verifyReceiptEndpoint(sandbox, G5_REQUEST)), 21003);
  assert.equal(status(defaults.verifyReceiptEndpoint(sandbox, G5_REQUEST)), 0);
});

test('a failure inside the instance is INTERNAL_ERROR, and the next call runs on a fresh one', (t) => {
  // The JWS path draws random bytes (ECDSA blinding), so a random-get that
  // throws fails that call inside the module. A component instance that
  // failed refuses every later call, so recovery is only observable if the
  // facade really replaced it.
  const verifier = node.createVerifier(node.createConfig({ roots: [...APPLE_ROOTS, JWS_ROOT] }));
  const sandbox = node.Environment.SANDBOX;
  assert.equal(status(verifier.verifyReceiptEndpoint(sandbox, G5_REQUEST)), 0);
  for (const thrown of [new Error('no entropy'), new WebAssembly.RuntimeError('trap')]) {
    const mock = t.mock.method(crypto, 'getRandomValues', () => {
      throw thrown;
    });
    const failed = verifier.verifySignedData(JWS);
    assert.ok(mock.mock.callCount() > 0, 'the JWS path asks for random bytes');
    mock.mock.restore();
    assert.equal(failed.verified, false);
    assert.equal(failed.failure.reason, 'INTERNAL_ERROR');
    assert.match(failed.failure.message, /the instance was discarded/);
    assert.ok(failed.failure.cause !== undefined);
    assert.equal(status(verifier.verifyReceiptEndpoint(sandbox, G5_REQUEST)), 0);
  }
});

test('random-get fills exactly the length asked, 64 KiB per getRandomValues call at most', (t) => {
  const sizes = [];
  const real = crypto.getRandomValues.bind(crypto);
  t.mock.method(crypto, 'getRandomValues', (view) => {
    sizes.push(view.length);
    return real(view);
  });
  for (const len of [0, 48, 65536, 65537, 200000]) {
    sizes.length = 0;
    const bytes = randomGet(len);
    assert.equal(bytes.length, len);
    assert.ok(
      sizes.every((n) => n <= 65536),
      `${len}: ${sizes}`,
    );
    assert.equal(
      sizes.reduce((a, b) => a + b, 0),
      len,
    );
  }
  // Not all zero: the bytes came from the CSPRNG.
  assert.ok(randomGet(64).some((b) => b !== 0));
});
