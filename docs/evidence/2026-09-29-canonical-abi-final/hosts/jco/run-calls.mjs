// Spike only (2026-09-29, round 13). The canonical-ABI component through
// jco's generated bindings (jco transpile --instantiation async), on Node,
// Deno or Bun: a corpus runner and binding-level checks. No hand-written
// canonical ABI: the only host code is loading the glue, the random-get
// import (under the documented unversioned key only) and plain calls.
//
//   node run-calls.mjs OUT_DIR calls CALLS.jsonl   rows in the Node runner's format
//   node run-calls.mjs OUT_DIR tests CALLS.jsonl   binding-level checks
//   deno run --allow-read --allow-env=JCO_DEBUG run-calls.mjs ...   (the same on Deno)
//   bun run-calls.mjs ...                          (the same on Bun)
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Buffer } from 'node:buffer';
import process from 'node:process';

const runtime = globalThis.Deno ? `deno ${Deno.version.deno}` : globalThis.Bun ? `bun ${Bun.version}` : `node ${process.version}`;
const [outDir, mode, callsPath] = process.argv.slice(globalThis.Deno ? 1 : 2).slice(-3);
// --- component host (hand-written) begin ---
const { instantiate } = await import(pathToFileURL(resolve(outDir, 'aprv.js')).href);
const compiled = new Map();
const getCoreModule = (name) => {
  if (!compiled.has(name)) compiled.set(name, WebAssembly.compile(readFileSync(join(outDir, name))));
  return compiled.get(name);
};
const imports = { 'aprv:verifier/host': { randomGet: (n) => crypto.getRandomValues(new Uint8Array(n)) } };
const fresh = async () => (await instantiate(getCoreModule, imports)).verify;
// --- component host (hand-written) end ---
const utf8 = new TextEncoder();
const bytes = (r) => new Uint8Array(Buffer.from(r.b64, 'base64'));

if (mode === 'calls') {
  const inst = new Map();
  let rows = 0, traps = 0, created = 0;
  const out = [];
  for (const line of readFileSync(callsPath, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    const r = JSON.parse(line);
    rows++;
    if ('map' in r) { out.push(JSON.stringify({ id: r.id, map: r.map })); continue; }
    let v = inst.get(r.config), answer = null;
    if (!v) {
      v = await fresh(); created++;
      const ok = v.init(utf8.encode(r.config));
      if (ok === '{"ok":true}') inst.set(r.config, v); else answer = ok; // init refused the config
    }
    const now = BigInt(r.now ?? Date.now());
    try {
      if (answer === null) {
        const input = bytes(r);
        answer = r.fn === 'verify-receipt' ? v.verifyReceipt(now, input)
          : r.fn === 'verify-signed-data' ? v.verifySignedData(now, input)
          : v.verifyReceiptEndpoint(r.env, now, input);
      }
      out.push(JSON.stringify({ id: r.id, out: answer }));
    } catch (e) {
      traps++; inst.delete(r.config);
      out.push(JSON.stringify({ id: r.id, trap: String(e.message ?? e) }));
    }
  }
  process.stdout.write(out.join('\n') + '\n');
  console.error(JSON.stringify({ host: `${runtime} + jco 1.35.0`, rows, traps, instances: created }));
} else {
  const rows = readFileSync(callsPath, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  const g5 = bytes(rows.find((r) => r.id === 'receipt/verify-genuine-sandbox-g5-against-apple-roots'));
  const jwsRow = rows.find((r) => r.id === 'transaction/verify-shared-sandbox');
  const now = () => BigInt(Date.now());
  const show = (f) => { try { return String(f()).slice(0, 110); } catch (e) { return `THROWS ${e.constructor.name}: ${String(e.message).split('\n')[0].slice(0, 110)}`; } };
  const req = utf8.encode(`{"receipt-data":"${Buffer.from(g5).toString('latin1')}"}`);
  console.log(`# ${runtime}, jco 1.35.0 output`);
  let v = await fresh();
  console.log('init(empty bytes) ->', show(() => v.init(new Uint8Array(0))));
  console.log('verify-receipt(g5) ->', show(() => v.verifyReceipt(now(), g5)));
  console.log('second init ->', show(() => v.init(new Uint8Array(0))));
  v = await fresh();
  console.log('verify before init ->', show(() => v.verifyReceipt(now(), g5)));
  v = await fresh(); v.init(utf8.encode(jwsRow.config));
  console.log('verify-signed-data(shared-sandbox, test roots) ->', show(() => v.verifySignedData(now(), bytes(jwsRow))));
  const probe = (label, f) => { const w = []; w.push(label, '->', show(f)); console.log(...w); };
  const cases = [
    ['endpoint env 1 (sandbox)', (x) => x.verifyReceiptEndpoint(1, now(), req)],
    ['endpoint env 2', (x) => x.verifyReceiptEndpoint(2, now(), req)],
    ['endpoint env -1 (Number)', (x) => x.verifyReceiptEndpoint(-1, now(), req)],
    ['endpoint env 2**32 + 1 (Number)', (x) => x.verifyReceiptEndpoint(2 ** 32 + 1, now(), req)],
    ['endpoint env 1.5', (x) => x.verifyReceiptEndpoint(1.5, now(), req)],
    ['endpoint env "sandbox" (a string)', (x) => x.verifyReceiptEndpoint('sandbox', now(), req)],
    ['endpoint env 1n (a BigInt)', (x) => x.verifyReceiptEndpoint(1n, now(), req)],
    ['JWS bytes that are not UTF-8', (x) => x.verifySignedData(now(), new Uint8Array([0x65, 0x79, 0xff, 0xfe, 0x2e, 0x78]))],
    ['receipt as a JS string (the g5 base64 text), not bytes', (x) => x.verifyReceipt(now(), Buffer.from(g5).toString('latin1'))],
    ['receipt as a plain Array of numbers', (x) => x.verifyReceipt(now(), Array.from(g5))],
    ['receipt as an ArrayBuffer', (x) => x.verifyReceipt(now(), g5.slice().buffer)],
    ['now-ms as a Number, not a BigInt', (x) => x.verifyReceipt(1, g5)],
    ['now-ms negative BigInt', (x) => x.verifyReceipt(-1n, g5)],
    ['now-ms 2n ** 64n', (x) => x.verifyReceipt(2n ** 64n, g5)],
  ];
  for (const [label, f] of cases) {
    const x = await fresh(); x.init(new Uint8Array(0));
    const r = show(() => f(x));
    const after = show(() => x.verifyReceipt(now(), g5)).includes('"verified":true') ? 'usable' : 'NOT usable';
    console.log(`${label} -> ${r}  [instance afterwards: ${after}]`);
  }
  const a = await fresh(), b = await fresh(); a.init(new Uint8Array(0)); b.init(new Uint8Array(0));
  show(() => a.verifyReceiptEndpoint(2, now(), req));
  console.log('isolation: after a trap in another instance ->', show(() => b.verifyReceipt(now(), g5)));
}
