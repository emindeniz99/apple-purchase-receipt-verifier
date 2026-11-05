// The ABI tests of the canonical-ABI final round
// (docs/evidence/2026-09-29-canonical-abi-final.md) that apply through
// jco's bindings, run on the bindings this package ships, below the
// facade: the misuse the facade itself never commits, so that the module's
// answer to it stays pinned. Plus the facade's check of the module's
// exports and imports.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { instantiate } from '../dist/generated/aprv.js';
import { getCoreModule } from '../dist/load/node.js';
import { InitRefusedError, abiProblem, initAnswer, initConfig, randomGet } from '../dist/engine.js';

const repo = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
const utf8 = new TextEncoder();
const G5 = utf8.encode(
  repo('fixtures/public-receipts/receipt-sandbox-g5.b64').toString('ascii').trim(),
);
const G5_REQUEST = utf8.encode(JSON.stringify({ 'receipt-data': new TextDecoder().decode(G5) }));
const JWS = utf8.encode(repo('fixtures/generated/transaction.jws').toString('ascii').trim());
const JWS_CONFIG = initConfig([repo('fixtures/generated/jws-root.der').toString('base64')]);
const DEFAULTS = initConfig();
const now = () => BigInt(Date.now());

// The receipt and request-body cap; init states one byte over it as the
// most bytes of one input a host hands over (DECISIONS.md R42). With
// Apple's roots the answer names the four Apple list URLs; with an own
// root and no revocation setting, none (docs/design/revocation.md §7).
const CAP = 3_145_728;
const APPLE_LISTS = ['root', 'applerootcag3', 'wwdrg5', 'wwdrg6']
  .map((name) => `"http://crl.apple.com/${name}.crl"`)
  .join(',');
const INIT_OK =
  `{"ok":true,"max_input_bytes":${CAP + 1},"revocation_urls":[${APPLE_LISTS}],` +
  '"revocation_valid_until_ms":null}';
const INIT_OK_OWN_ROOTS = `{"ok":true,"max_input_bytes":${CAP + 1},"revocation_urls":[],"revocation_valid_until_ms":null}`;

/** Fresh bindings; `host` replaces the random-get import, `onCore` sees the core instance. */
function bindings({ host = randomGet, onCore } = {}) {
  const core = getCoreModule('aprv.core.wasm');
  return instantiate(
    getCoreModule,
    { 'aprv:verifier/host': { randomGet: host } },
    (compiled, imports) => {
      const instance = new WebAssembly.Instance(compiled, imports);
      if (compiled === core) {
        onCore?.(instance);
      }
      return instance;
    },
  ).verify;
}

function ready(config = DEFAULTS, options) {
  const b = bindings(options);
  assert.equal(b.init(config), config === DEFAULTS ? INIT_OK : INIT_OK_OWN_ROOTS);
  return b;
}

const decode = (bytes) => new TextDecoder().decode(bytes);
const traps = (fn) => assert.throws(fn, WebAssembly.RuntimeError);

test('the shipped module passes the facade ABI check', () => {
  assert.equal(abiProblem(getCoreModule('aprv.core.wasm')), null);
});

// A minimal module encoder, for modules that are not aprv.wasm.
const leb = (n) => (n < 0x80 ? [n] : [(n & 0x7f) | 0x80, ...leb(n >>> 7)]);
const vec = (items) => [...leb(items.length), ...items.flat()];
const name = (s) => vec([...utf8.encode(s)].map((b) => [b]));
const section = (id, body) => [id, ...leb(body.length), ...body];
function module({ imports = [], exports = [] }) {
  const funcs = exports.length;
  const bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
  bytes.push(...section(1, vec([[0x60, 0x00, 0x00]])));
  if (imports.length > 0) {
    bytes.push(...section(2, vec(imports.map(([m, n]) => [...name(m), ...name(n), 0x00, 0x00]))));
  }
  if (funcs > 0) {
    bytes.push(...section(3, vec(exports.map(() => [0x00]))));
    bytes.push(
      ...section(7, vec(exports.map((n, i) => [...name(n), 0x00, ...leb(imports.length + i)]))),
    );
    bytes.push(...section(10, vec(exports.map(() => [0x02, 0x00, 0x0b]))));
  }
  return new WebAssembly.Module(new Uint8Array(bytes));
}

test('a module without the @0.2.0 exports is an ABI mismatch naming what it has', () => {
  const problem = abiProblem(module({ exports: ['aprv:verifier/verify@2.0.0#init'] }));
  assert.match(problem, /does not implement aprv:verifier\/verify@0\.2\.0/);
  assert.match(problem, /missing aprv:verifier\/verify@0\.2\.0#init/);
  assert.match(problem, /exports aprv:verifier\/verify@2\.0\.0#init/);
});

test('a module that imports anything but random-get is an ABI mismatch', () => {
  const ops = ['init', 'verify-receipt', 'verify-signed-data', 'verify-receipt-endpoint'].map(
    (op) => `aprv:verifier/verify@0.2.0#${op}`,
  );
  const extra = module({
    imports: [
      ['aprv:verifier/host@0.2.0', 'random-get'],
      ['wasi_snapshot_preview1', 'fd_write'],
    ],
    exports: ops,
  });
  assert.match(abiProblem(extra), /must import exactly .*random-get; it imports .*fd_write/);
  const none = module({ exports: ops });
  assert.match(abiProblem(none), /it imports nothing/);
  const exact = module({ imports: [['aprv:verifier/host@0.2.0', 'random-get']], exports: ops });
  assert.equal(abiProblem(exact), null);
});

// `env` is the WIT enum `environment` (ABI 0.2.0): jco takes a case name
// and throws a TypeError for anything else before the module is entered,
// so the discriminant traps (2, 255, 2^32-1) are a hand-rolled host's to
// test (tools/wasm-trap-host.mjs abi-tests). The facade's Slot drops the
// instance after any throw.
test('an environment that is not a case name throws a TypeError at the binding', () => {
  for (const env of ['staging', 'Production', 0, 1, 2, null]) {
    assert.throws(
      () => ready().verifyReceiptEndpoint(env, now(), G5_REQUEST),
      TypeError,
      String(env),
    );
  }
  assert.equal(
    JSON.parse(ready().verifyReceiptEndpoint('production', now(), G5_REQUEST)).status,
    21007,
  );
  assert.equal(JSON.parse(ready().verifyReceiptEndpoint('sandbox', now(), G5_REQUEST)).status, 0);
});

test('a verify before init traps, and so does a second init', () => {
  traps(() => bindings().verifyReceipt(now(), G5));
  traps(() => bindings().verifySignedData(now(), JWS));
  traps(() => bindings().verifyReceiptEndpoint('sandbox', now(), G5_REQUEST));
  const b = ready();
  traps(() => b.init(DEFAULTS));
});

test('init may be retried after it refuses a root', () => {
  const b = bindings();
  const refused = JSON.parse(b.init(initConfig(['AQID'])));
  assert.equal(refused.ok, false);
  assert.equal(typeof refused.message, 'string');
  assert.equal(b.init(DEFAULTS), INIT_OK);
});

test('the built-in roots are sent as {}, and an empty root list is refused', () => {
  assert.equal(new TextDecoder().decode(DEFAULTS), '{}');
  assert.equal(bindings().init(initConfig([])), '{"ok":false,"message":"roots must not be empty"}');
});

test('the revocation settings are sent only when set, distrust entries as exactly {issuer, serial}', () => {
  assert.equal(decode(initConfig(undefined, { lists: [], issuers: [], distrust: [] })), '{}');
  assert.equal(
    decode(
      initConfig(['AQID'], {
        lists: ['BAU='],
        issuers: ['Bgc='],
        distrust: [{ issuer: 'ab', serial: '01', extra: true }],
      }),
    ),
    '{"roots":["AQID"],"revocation_lists":["BAU="],"revocation_issuers":["Bgc="],' +
      '"distrust":[{"issuer":"ab","serial":"01"}]}',
  );
  assert.equal(decode(initConfig(undefined, { lists: ['BAU='] })), '{"revocation_lists":["BAU="]}');
});

test('init refuses a revocation list that is not a CRL, naming it, and may be retried', () => {
  const b = bindings();
  const refused = JSON.parse(b.init(initConfig(undefined, { lists: ['AQID'] })));
  assert.equal(refused.ok, false);
  assert.match(refused.message, /^revocation_lists\[0\]/);
  assert.equal(b.init(DEFAULTS), INIT_OK);
});

test("the facade reads init's answer: max_input_bytes and the revocation state, or the refusal", () => {
  assert.deepEqual(initAnswer(INIT_OK), {
    maxInputBytes: CAP + 1,
    revocationUrls: [
      'http://crl.apple.com/root.crl',
      'http://crl.apple.com/applerootcag3.crl',
      'http://crl.apple.com/wwdrg5.crl',
      'http://crl.apple.com/wwdrg6.crl',
    ],
    revocationValidUntilMs: null,
  });
  assert.deepEqual(
    initAnswer(
      '{"revocation_valid_until_ms":1798761600000,"revocation_urls":["u"],"max_input_bytes":7,"ok":true}',
    ),
    { maxInputBytes: 7, revocationUrls: ['u'], revocationValidUntilMs: 1_798_761_600_000 },
  );
  const refused = '{"ok":false,"message":"not a certificate"}';
  assert.throws(
    () => initAnswer(refused),
    (e) => e instanceof InitRefusedError && e.answer === refused,
  );
  // An accepting answer without a positive integer, or without the two
  // revocation members, comes from a module of another version: no answer,
  // never a cap or a revocation state of the facade's own.
  const revocation = ',"revocation_urls":[],"revocation_valid_until_ms":null';
  for (const text of [
    '{"ok":true}',
    `{"ok":true${revocation}}`,
    `{"ok":true,"max_input_bytes":0${revocation}}`,
    // the answer of a 0.13.0 module, which knows no revocation
    '{"ok":true,"max_input_bytes":3145729}',
    '{"ok":true,"max_input_bytes":7,"revocation_valid_until_ms":null}',
    '{"ok":true,"max_input_bytes":7,"revocation_urls":[]}',
    '{"ok":true,"max_input_bytes":7,"revocation_urls":[1],"revocation_valid_until_ms":null}',
    '{"ok":true,"max_input_bytes":7,"revocation_urls":"u","revocation_valid_until_ms":null}',
    '{"ok":true,"max_input_bytes":7,"revocation_urls":[],"revocation_valid_until_ms":1.5}',
    '{"ok":true,"max_input_bytes":7,"revocation_urls":[],"revocation_valid_until_ms":"1"}',
    '{"ok":true,"max_input_bytes":0}',
    '{"ok":true,"max_input_bytes":-1}',
    '{"ok":true,"max_input_bytes":1.5}',
    '{"ok":true,"max_input_bytes":"3145729"}',
    '{"ok":true,"max_input_bytes":null}',
    '{"ok":true,"max_input_bytes":1e300}',
    '{"ok":false}',
    'null',
    'not json',
  ]) {
    assert.throws(
      () => initAnswer(text),
      (e) => !(e instanceof InitRefusedError) && /init answered/.test(e.message),
      text,
    );
  }
});

test('a random-get answer of the wrong length traps', () => {
  for (const wrong of [(n) => randomGet(n - 1), (n) => randomGet(n + 1), () => new Uint8Array(0)]) {
    traps(() => ready(JWS_CONFIG, { host: wrong }).verifySignedData(now(), JWS));
  }
});

test('a trapped instance refuses every later call; another instance is untouched', () => {
  const a = ready();
  const b = ready();
  traps(() => a.init(DEFAULTS));
  assert.throws(
    () => a.verifyReceiptEndpoint('sandbox', now(), G5_REQUEST),
    /cannot enter component instance/,
  );
  assert.equal(JSON.parse(b.verifyReceiptEndpoint('sandbox', now(), G5_REQUEST)).status, 0);
});

test('2,000 calls leave linear memory the same size', () => {
  let memory;
  const b = ready(DEFAULTS, { onCore: (instance) => (memory = instance.exports.memory) });
  const inputs = [utf8.encode('QUJD'), utf8.encode('not base64'), G5.subarray(0, 4096)];
  for (const input of inputs) {
    b.verifyReceipt(now(), input);
  }
  const before = memory.buffer.byteLength;
  for (let i = 0; i < 2000; i++) {
    b.verifyReceipt(now(), inputs[i % inputs.length]);
  }
  assert.equal(memory.buffer.byteLength, before);
});

// --- the input cap (ABI review) --------------------------------------------

test('the facade copies at most one byte over the cap, and the module still answers TOO_LARGE', async () => {
  const { inputBytes } = await import('../dist/verifier.js');
  const { createVerifier, createConfig, Environment } = await import('../dist/index.js');
  const max = initAnswer(bindings().init(DEFAULTS));
  assert.equal(max, CAP + 1);
  const huge = 'A'.repeat(4 * 1024 * 1024);
  assert.equal(inputBytes(huge, max).length, CAP + 1);

  // The facade's answer is byte for byte the module's answer to the whole input.
  const whole = ready().verifyReceipt(now(), utf8.encode(huge));
  const result = createVerifier(createConfig()).verifyReceipt(huge);
  assert.equal(result.failure?.reason, 'TOO_LARGE');
  assert.deepEqual({ verified: false, ...result.failure }, JSON.parse(whole));
  const body = `{"receipt-data":"${huge}"}`;
  assert.equal(
    createVerifier(createConfig()).verifyReceiptEndpoint(Environment.SANDBOX, body),
    ready().verifyReceiptEndpoint('sandbox', now(), utf8.encode(body)),
  );

  // Linear memory holds the capped copy, not the 4 MiB input.
  const grown = (bytes) => {
    let memory;
    const b = ready(DEFAULTS, { onCore: (instance) => (memory = instance.exports.memory) });
    const before = memory.buffer.byteLength;
    b.verifyReceipt(now(), bytes);
    return memory.buffer.byteLength - before;
  };
  const MiB = 1024 * 1024;
  assert.ok(grown(inputBytes(huge, max)) < 4 * MiB, 'the capped input grows memory by under 4 MiB');
  assert.ok(grown(utf8.encode(huge)) >= 4 * MiB, 'the whole input would have grown it by 4 MiB');
});

test('an input of exactly the cap is passed whole; one code point over it is not', async () => {
  const { inputBytes } = await import('../dist/verifier.js');
  for (const text of ['A'.repeat(CAP), 'é'.repeat(CAP / 2), `${'A'.repeat(CAP - 4)}\u{1F600}`]) {
    const bytes = inputBytes(text, CAP + 1);
    assert.equal(bytes.length, CAP);
    assert.deepEqual(bytes, utf8.encode(text));
  }
  // A four-byte code point straddling the cap: at least one byte over it.
  const over = inputBytes(`${'A'.repeat(CAP - 1)}\u{1F600}`, CAP + 1);
  assert.equal(over.length, CAP + 1);
  assert.match(ready().verifyReceipt(now(), over), /"reason":"TOO_LARGE"/);
});
