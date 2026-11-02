// Calls the real aprv.wasm (ABI 0.2.0) by hand over the canonical ABI on
// V8, as the hand-rolled hosts do, and prints for each call a value or the
// trap. The endpoint is given the sandbox G5 receipt, so its status names
// the environment the guest used: 0 for sandbox, 21007 for production.
//
//   node run-real.mjs <aprv.wasm> <repo>
import { readFileSync } from 'node:fs';
import { randomFillSync } from 'node:crypto';

const [file, repo] = process.argv.slice(2);
const mod = new WebAssembly.Module(readFileSync(file));
const IFACE = 'aprv:verifier/verify@0.2.0#';
const HOST = 'aprv:verifier/host@0.2.0';
const g5 = readFileSync(`${repo}/fixtures/public-receipts/receipt-sandbox-g5.b64`, 'ascii').trim();
const enc = new TextEncoder();
const dec = new TextDecoder();

function fresh() {
  let x;
  const imports = {
    [HOST]: {
      'random-get': (len, retptr) => {
        const n = len >>> 0;
        const p = x.cabi_realloc(0, 0, 1, n) >>> 0;
        randomFillSync(new Uint8Array(x.memory.buffer, p, n));
        const dv = new DataView(x.memory.buffer);
        dv.setUint32(retptr >>> 0, p, true);
        dv.setUint32((retptr >>> 0) + 4, n, true);
      },
    },
  };
  x = new WebAssembly.Instance(mod, imports).exports;
  const call = (op, scalars, bytes) => {
    const p = x.cabi_realloc(0, 0, 1, bytes.length) >>> 0;
    new Uint8Array(x.memory.buffer, p, bytes.length).set(bytes);
    const ret = x[IFACE + op](...scalars, p, bytes.length) >>> 0;
    const dv = new DataView(x.memory.buffer);
    const ptr = dv.getUint32(ret, true), len = dv.getUint32(ret + 4, true);
    const out = dec.decode(new Uint8Array(x.memory.buffer, ptr, len).slice());
    x[`cabi_post_${IFACE}${op}`](ret);
    return out;
  };
  call('init', [], enc.encode('{}'));
  return call;
}

function show(label, f) {
  try {
    const out = f();
    console.log(`${label}: value ${out.length > 120 ? out.slice(0, 120) + '...' : out}`);
  } catch (e) {
    console.log(`${label}: ${e.constructor.name}: ${e.message}`);
  }
}

console.log(`module: ${readFileSync(file).length} bytes`);
const body = enc.encode(JSON.stringify({ 'receipt-data': g5 }));
const now = BigInt(Date.UTC(2026, 10, 2));
for (const env of [0, 1, 2, 255, 0xffffffff]) {
  show(`endpoint env ${env}`, () => {
    const out = fresh()('verify-receipt-endpoint', [env | 0, now], body);
    return `status ${JSON.parse(out).status}`;
  });
}
for (const ms of [-1n, -(1n << 63n), (1n << 63n) - 1n]) {
  show(`endpoint env 1, now-ms ${ms}`, () => {
    const out = fresh()('verify-receipt-endpoint', [1, ms], body);
    return `status ${JSON.parse(out).status}`;
  });
  show(`verify-receipt, now-ms ${ms}`, () => {
    const out = JSON.parse(fresh()('verify-receipt', [ms], enc.encode(g5)));
    return `verified ${out.verified}${out.reason ? ' reason ' + out.reason : ''}`;
  });
}
