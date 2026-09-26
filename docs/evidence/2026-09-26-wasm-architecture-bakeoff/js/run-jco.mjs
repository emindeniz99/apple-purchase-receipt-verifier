// Spike only. Node/Bun/Deno runner for a jco-transpiled component.
//
//   node js/run-jco.mjs <dir>/aprv.js <requests.jsonl> [--bench <id> <n>]
//
// Same output as js/run.mjs: rows on stdout, a summary line on stderr.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';
import { jsonl } from './driver.mjs';
import { makeJcoRunner } from './jco-driver.mjs';

const [jsPath, reqPath, flag, benchId, benchN] = process.argv.slice(2);
const { instantiate } = await import(pathToFileURL(jsPath).href);
const dir = dirname(jsPath);
const getCoreModule = (p) => new WebAssembly.Module(readFileSync(join(dir, p)));
const calls = {};
const t0 = performance.now();
// APRV_WASI_P2=min: js/wasi-p2-min.mjs; =shim: @bytecodealliance/preview2-shim
// (resolved from the working directory's node_modules).
let extra = {};
if (process.env.APRV_WASI_P2 === 'min') extra = (await import('./wasi-p2-min.mjs')).wasiP2Min(calls);
if (process.env.APRV_WASI_P2 === 'shim') {
  const { createRequire } = await import('node:module');
  const req = createRequire(pathToFileURL(process.cwd() + '/').href);
  const { WASIShim } = await import(pathToFileURL(req.resolve('@bytecodealliance/preview2-shim/instantiation')).href);
  extra = new WASIShim().getImportObject();
}
// APRV_WASI_P2=trapstubs: every wasi:* interface the bindings ask for is a
// Proxy whose members throw when called (or constructed): the run proves
// which WASI imports are never used. Works for WASI 0.2 and 0.3 imports.
// Exception: the wall clock is real (see below).
if (process.env.APRV_WASI_P2 === 'trapstubs') {
  const keys = new Set([...readFileSync(jsPath, 'utf8').matchAll(/imports\['(wasi:[^']+)'\]/g)].map((m) => m[1]));
  const stub = (iface) => new Proxy({}, { get: (_, k) => {
    if (typeof k !== 'string') return undefined;
    return new Proxy(function () {}, {
      apply: () => { throw new Error(`WASI import ${iface}#${k} called`); },
      construct: () => { throw new Error(`WASI import ${iface}#${k} constructed`); },
    });
  } });
  for (const k of keys) extra[k] = stub(k);
  // The one capability the verifier legitimately uses: the wall clock, for
  // the "no signed date" fallback (the core's SystemTime::now on WASI).
  for (const k of keys) {
    if (k.startsWith('wasi:clocks/wall-clock') || k.startsWith('wasi:clocks/system-clock')) {
      extra[k] = { now: () => { calls[k + '#now'] = (calls[k + '#now'] || 0) + 1; const ms = Date.now(); return { seconds: BigInt(Math.floor(ms / 1000)), nanoseconds: (ms % 1000) * 1e6 }; } };
    }
  }
  calls.wasiInterfacesStubbed = keys.size;
}
const run = await makeJcoRunner(instantiate, getCoreModule, calls, extra);
const initMs = performance.now() - t0;
const rows = jsonl(readFileSync(reqPath, 'utf8'));
let traps = 0;
if (flag === '--bench') {
  const r = rows.find((row) => row.id === benchId);
  const n = Number(benchN);
  const t1 = performance.now();
  const first = await run.run(r);
  const firstMs = performance.now() - t1;
  for (let i = 0; i < Math.min(200, n); i++) run.runSync(r);
  const t = performance.now();
  for (let i = 0; i < n; i++) run.runSync(r);
  const us = (performance.now() - t) * 1000 / n;
  console.log(JSON.stringify({ id: r.id, code: first.code, n, init_ms: Math.round(initMs * 100) / 100, first_call_ms: Math.round(firstMs * 100) / 100, mean_us: Math.round(us * 10) / 10 }));
} else {
  const out = [];
  for (const r of rows) {
    const row = await run.run(r);
    if (row.code === 'TRAP') traps++;
    out.push(JSON.stringify(row));
  }
  console.log(out.join('\n'));
}
console.error(JSON.stringify({ host: 'jco', calls, traps, rows: rows.length }));
