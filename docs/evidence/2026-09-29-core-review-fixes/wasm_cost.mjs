// Evidence only (2026-09-29). Time and linear memory of verifyReceipt calls
// through aprv.wasm's core module and the canonical ABI called by hand (as
// tools/wasm-trap-host.mjs does on rust-core; only random-get is supplied,
// every other import throws).
//
//   node wasm_cost.mjs hostile <aprv.wasm>
//   node wasm_cost.mjs files <aprv.wasm> <root.der> <receipt.der>...
//
// `files` runs each DER receipt, as base64, on a fresh instance configured
// with the one root, twice, and prints the second call's time: the
// reviewers' inputs, rebuilt by their scripts.
//
// The receipt is node/bench/memory.mjs's "flat-max" (lane/host-node): a
// CMS SignedData with no certificate and one SignerInfo, whose payload is a
// SET of 12-byte attributes of an unmodelled type, as large as a
// verifyReceipt request body under the 3 MiB cap allows. Nothing names an
// embedded certificate, so the answer is MALFORMED; the question is what it
// costs first. Prints the answer, the call's time (after one warm-up call
// on a fresh instance each), and linear memory before and after.
import { readFileSync } from 'node:fs';
import { getRandomValues } from 'node:crypto';

const IFACE = 'aprv:verifier/verify@1.0.0#';
const CAP = 3_145_728;
const MAX_DER = Math.floor((CAP - '{"receipt-data":""}'.length) / 4) * 3;

function length(n) {
  if (n < 0x80) return [n];
  const raw = [];
  for (let v = n; v > 0; v = Math.floor(v / 256)) raw.unshift(v % 256);
  return [0x80 | raw.length, ...raw];
}
const tlv = (tag, body) => Buffer.concat([Buffer.from([tag, ...length(body.length)]), body]);
const hex = (h) => Buffer.from(h, 'hex');
const ATTR = hex('300a0202270f020101040100');
const SHA256 = tlv(0x30, hex('06096086480165030402010500'));
const RSA = tlv(0x30, hex('06092a864886f70d0101010500'));

function cms(payload) {
  const signer = tlv(0x30, Buffer.concat([
    tlv(0x02, hex('01')),
    tlv(0x30, Buffer.concat([tlv(0x30, Buffer.alloc(0)), tlv(0x02, hex('01'))])),
    SHA256, RSA, tlv(0x04, hex('00')),
  ]));
  const signed = tlv(0x30, Buffer.concat([
    tlv(0x02, hex('01')),
    tlv(0x31, SHA256),
    tlv(0x30, Buffer.concat([hex('06092a864886f70d010701'), tlv(0xa0, tlv(0x04, payload))])),
    tlv(0x31, signer),
  ]));
  return tlv(0x30, Buffer.concat([hex('06092a864886f70d010702'), tlv(0xa0, signed)]));
}
const receipt = (count) => cms(tlv(0x31, Buffer.concat(Array(count).fill(ATTR))));
function flatMax() {
  let lo = 1;
  let hi = Math.floor(MAX_DER / ATTR.length);
  while (lo < hi) {
    const mid = Math.floor((lo + hi + 1) / 2);
    if (receipt(mid).length <= MAX_DER) lo = mid; else hi = mid - 1;
  }
  return receipt(lo);
}

function instance(module) {
  const imports = {};
  let exports;
  for (const imp of WebAssembly.Module.imports(module)) {
    imports[imp.module] ??= {};
    imports[imp.module][imp.name] = imp.name === 'random-get'
      ? (len, retptr) => {
        const bytes = getRandomValues(new Uint8Array(len >>> 0));
        const ptr = exports.cabi_realloc(0, 0, 1, bytes.length) >>> 0;
        new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
        const view = new DataView(exports.memory.buffer);
        view.setUint32(retptr >>> 0, ptr, true);
        view.setUint32((retptr >>> 0) + 4, bytes.length, true);
      }
      : () => { throw new Error(`unexpected import ${imp.module} ${imp.name}`); };
  }
  exports = new WebAssembly.Instance(module, imports).exports;
  const call = (fn, args) => {
    const lowered = args.map((a) => {
      if (!(a instanceof Uint8Array)) return a;
      const ptr = exports.cabi_realloc(0, 0, 1, a.length) >>> 0;
      new Uint8Array(exports.memory.buffer, ptr, a.length).set(a);
      return [ptr, a.length];
    }).flat();
    const retptr = exports[IFACE + fn](...lowered) >>> 0;
    const view = new DataView(exports.memory.buffer);
    const [ptr, len] = [view.getUint32(retptr, true), view.getUint32(retptr + 4, true)];
    const text = Buffer.from(new Uint8Array(exports.memory.buffer, ptr, len)).toString('utf8');
    exports[`cabi_post_${IFACE}${fn}`](retptr);
    return text;
  };
  return { call, memory: () => exports.memory.buffer.byteLength };
}

function configured(module, root) {
  const guest = instance(module);
  const config = root ? JSON.stringify({ roots: [root.toString('base64')] }) : '';
  const answer = guest.call('init', [new Uint8Array(Buffer.from(config))]);
  if (!answer.includes('"ok":true')) throw new Error(`init refused: ${answer}`);
  return guest;
}

const [mode, modulePath, ...rest] = process.argv.slice(2);
const module = new WebAssembly.Module(readFileSync(modulePath));
const now = BigInt(Date.UTC(2026, 8, 29));
const timed = (guest, text) => {
  const started = process.hrtime.bigint();
  const answer = guest.call('verify-receipt', [now, text]);
  return [Number(process.hrtime.bigint() - started) / 1e6, answer];
};
if (mode === 'hostile') {
  const text = new Uint8Array(Buffer.from(flatMax().toString('base64')));
  for (let run = 0; run < 3; run++) {
    const guest = configured(module, null);
    const before = guest.memory();
    const [millis, answer] = timed(guest, text);
    console.log(`run ${run}: ${text.length} B of base64, ${millis.toFixed(1)} ms, linear memory ${before} -> ${guest.memory()} B: ${answer}`);
  }
} else if (mode === 'files') {
  const [rootPath, ...files] = rest;
  const root = readFileSync(rootPath);
  for (const file of files) {
    const text = new Uint8Array(Buffer.from(readFileSync(file).toString('base64')));
    const guest = configured(module, root);
    timed(guest, text);
    const [millis, answer] = timed(guest, text);
    const name = file.split('/').pop();
    console.log(`${name}: ${millis.toFixed(1)} ms, memory ${guest.memory()} B: ${answer.slice(0, 140)}`);
  }
} else {
  console.error('usage: node wasm_cost.mjs hostile <aprv.wasm> | files <aprv.wasm> <root.der> <receipt.der>...');
  process.exit(2);
}
