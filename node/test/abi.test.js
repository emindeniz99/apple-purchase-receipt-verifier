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
import { abiProblem, initConfig, randomGet } from '../dist/engine.js';

const repo = (rel) => readFileSync(fileURLToPath(new URL(`../../${rel}`, import.meta.url)));
const utf8 = new TextEncoder();
const G5 = utf8.encode(
  repo('fixtures/public-receipts/receipt-sandbox-g5.b64').toString('ascii').trim(),
);
const G5_REQUEST = utf8.encode(JSON.stringify({ 'receipt-data': new TextDecoder().decode(G5) }));
const JWS = utf8.encode(repo('fixtures/generated/transaction.jws').toString('ascii').trim());
const JWS_CONFIG = initConfig([repo('fixtures/generated/jws-root.der').toString('base64')]);
const DEFAULTS = initConfig([]);
const now = () => BigInt(Date.now());

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
  assert.equal(b.init(config), '{"ok":true}');
  return b;
}

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

test('a module without the @1.0.0 exports is an ABI mismatch naming what it has', () => {
  const problem = abiProblem(module({ exports: ['aprv:verifier/verify@2.0.0#init'] }));
  assert.match(problem, /does not implement aprv:verifier\/verify@1\.0\.0/);
  assert.match(problem, /missing aprv:verifier\/verify@1\.0\.0#init/);
  assert.match(problem, /exports aprv:verifier\/verify@2\.0\.0#init/);
});

test('a module that imports anything but random-get is an ABI mismatch', () => {
  const ops = ['init', 'verify-receipt', 'verify-signed-data', 'verify-receipt-endpoint'].map(
    (op) => `aprv:verifier/verify@1.0.0#${op}`,
  );
  const extra = module({
    imports: [
      ['aprv:verifier/host@1.0.0', 'random-get'],
      ['wasi_snapshot_preview1', 'fd_write'],
    ],
    exports: ops,
  });
  assert.match(abiProblem(extra), /must import exactly .*random-get; it imports .*fd_write/);
  const none = module({ exports: ops });
  assert.match(abiProblem(none), /it imports nothing/);
  const exact = module({ imports: [['aprv:verifier/host@1.0.0', 'random-get']], exports: ops });
  assert.equal(abiProblem(exact), null);
});

test('env 2, 255 and 2^32-1 trap', () => {
  for (const env of [2, 255, 2 ** 32 - 1]) {
    traps(() => ready().verifyReceiptEndpoint(env, now(), G5_REQUEST));
  }
  assert.equal(JSON.parse(ready().verifyReceiptEndpoint(1, now(), G5_REQUEST)).status, 0);
});

test('a verify before init traps, and so does a second init', () => {
  traps(() => bindings().verifyReceipt(now(), G5));
  traps(() => bindings().verifySignedData(now(), JWS));
  traps(() => bindings().verifyReceiptEndpoint(1, now(), G5_REQUEST));
  const b = ready();
  traps(() => b.init(DEFAULTS));
});

test('init may be retried after it refuses a root', () => {
  const b = bindings();
  const refused = JSON.parse(b.init(initConfig(['AQID'])));
  assert.equal(refused.ok, false);
  assert.equal(typeof refused.message, 'string');
  assert.equal(b.init(DEFAULTS), '{"ok":true}');
});

test('a random-get answer of the wrong length traps', () => {
  for (const wrong of [(n) => randomGet(n - 1), (n) => randomGet(n + 1), () => new Uint8Array(0)]) {
    traps(() => ready(JWS_CONFIG, { host: wrong }).verifySignedData(now(), JWS));
  }
});

test('a trapped instance refuses every later call; another instance is untouched', () => {
  const a = ready();
  const b = ready();
  traps(() => a.verifyReceiptEndpoint(2, now(), G5_REQUEST));
  assert.throws(
    () => a.verifyReceiptEndpoint(1, now(), G5_REQUEST),
    /cannot enter component instance/,
  );
  assert.equal(JSON.parse(b.verifyReceiptEndpoint(1, now(), G5_REQUEST)).status, 0);
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
