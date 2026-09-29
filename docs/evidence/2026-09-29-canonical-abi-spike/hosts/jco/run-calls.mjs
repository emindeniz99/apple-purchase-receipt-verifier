// Spike only (2026-09-29, round 12). The canonical-ABI component through
// jco's generated bindings (jco transpile --instantiation async): a corpus
// runner and a few binding-level checks. No hand-written canonical ABI:
// the only host code is the random-get import and plain function calls.
//
//   node run-calls.mjs OUT_DIR calls CALLS.jsonl   rows in the Node runner's format
//   node run-calls.mjs OUT_DIR tests CALLS.jsonl   binding-level checks + start-up timing
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { webcrypto } from 'node:crypto';

const [outDir, mode, callsPath] = process.argv.slice(2);
const t0 = performance.now();
// --- component host (hand-written) begin ---
const { instantiate } = await import(pathToFileURL(resolve(outDir, 'aprv.js')).href);
const compiled = new Map();
const getCoreModule = (name) => {
  if (!compiled.has(name)) compiled.set(name, WebAssembly.compile(readFileSync(join(outDir, name))));
  return compiled.get(name);
};
const host = { randomGet: (n) => webcrypto.getRandomValues(new Uint8Array(n)) };
// jco's glue reads imports['aprv:verifier/host'] while its .d.ts names 'aprv:verifier/host@1.0.0': pass both.
const imports = { 'aprv:verifier/host': host, 'aprv:verifier/host@1.0.0': host };
const fresh = async () => (await instantiate(getCoreModule, imports)).verify;
// --- component host (hand-written) end ---
const ENV = ['production', 'sandbox'];

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
      const ok = v.init(r.config);
      if (ok === '{"ok":true}') inst.set(r.config, v); else answer = ok; // init refused the config
    }
    const now = BigInt(r.now ?? Date.now());
    try {
      if (answer === null) {
        answer = r.fn === 'verify-receipt' ? v.verifyReceipt(now, r.text)
          : r.fn === 'verify-signed-data' ? v.verifySignedData(now, r.text)
          : v.verifyReceiptEndpoint(ENV[r.env], now, r.text);
      }
      out.push(JSON.stringify({ id: r.id, out: answer }));
    } catch (e) {
      traps++; inst.delete(r.config);
      out.push(JSON.stringify({ id: r.id, trap: String(e.message ?? e) }));
    }
  }
  process.stdout.write(out.join('\n') + '\n');
  console.error(JSON.stringify({ host: `node ${process.version} + jco 1.35.0`, rows, traps, instances: created }));
} else {
  const rows = readFileSync(callsPath, 'utf8').split('\n').filter(Boolean).map(JSON.parse);
  const g5 = rows.find((r) => r.id === 'receipt/verify-genuine-sandbox-g5-against-apple-roots');
  const jws = rows.find((r) => r.id === 'transaction/verify-shared-sandbox');
  const now = () => BigInt(Date.now());
  const show = (f) => { try { return String(f()).slice(0, 100); } catch (e) { return `THROWS ${e.constructor.name}: ${String(e.message).slice(0, 100)}`; } };
  let v = await fresh();
  const tFirst = performance.now();
  console.log('init("") ->', show(() => v.init('')));
  console.log('verify-receipt(g5) ->', show(() => v.verifyReceipt(now(), g5.text)), `(${(performance.now() - t0).toFixed(1)} ms from import to first result; first call ${(performance.now() - tFirst).toFixed(1)} ms)`);
  console.log('second init ->', show(() => v.init('')));
  v = await fresh();
  console.log('verify before init ->', show(() => v.verifyReceipt(now(), g5.text)));
  v = await fresh(); v.init(jws.config);
  console.log('verify-signed-data(shared-sandbox, test roots) ->', show(() => v.verifySignedData(now(), jws.text)));
  v = await fresh(); v.init('');
  console.log('endpoint with env "xcode" (not in the enum) ->', show(() => v.verifyReceiptEndpoint('xcode', now(), '{}')));
  console.log('endpoint with a lone surrogate in the string ->', show(() => v.verifyReceiptEndpoint('sandbox', now(), '{"receipt-data":"\ud800"}')));
  console.log('now-ms as a Number, not a BigInt ->', show(() => v.verifyReceipt(1, g5.text)));
  console.log('now-ms negative ->', show(() => v.verifyReceipt(-1n, g5.text)));
  console.log('the same instance after those ->', show(() => v.verifyReceipt(now(), g5.text)));
}
