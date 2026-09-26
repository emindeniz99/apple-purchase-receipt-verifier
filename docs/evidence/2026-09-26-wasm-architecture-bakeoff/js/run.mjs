// Spike only. Command-line runner for Node, Bun and Deno (node:fs only).
//
//   node js/run.mjs --host <host> <module.wasm|module.mjs> <requests.jsonl> [--bench <id> <n>]
//
// Hosts:
//   nodewasi   node:wasi, no preopens, no env, no args (the previous
//              bake-off's setup; reference only)
//   minimal    js/hosts.mjs: a hand-written import object; unknown imports
//              answer ENOSYS and are counted
//   trap       as minimal, but an unknown import throws when called
//   strict     every import except aprv.clock_now_ms throws when called
//   emscripten the module is Emscripten's ES-module factory (.mjs)
//
// Rows go to stdout ({"id","code","json"}). At exit, stderr gets one JSON
// line: {"host", "calls": {import: count}, "traps": n, "rows": n}.
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { makeDriver, jsonl } from './driver.mjs';
import { instantiateMinimal } from './hosts.mjs';
import { instantiateEmscripten } from './emscripten-host.mjs';

const args = process.argv.slice(2);
const hostIdx = args.indexOf('--host');
const host = hostIdx >= 0 ? args.splice(hostIdx, 2)[1] : 'minimal';
const [modPath, reqPath, flag, benchId, benchN] = args;
const calls = {};
const merge = (c) => { for (const [k, v] of Object.entries(c)) calls[k] = (calls[k] || 0) + v; };
let lastHost = null;

async function instantiate() {
  if (lastHost) { merge(lastHost.calls); lastHost = null; }
  if (host === 'emscripten') {
    // modPath is the glue (.mjs); the .wasm sits next to it.
    const factory = (await import(pathToFileURL(modPath).href)).default;
    const wasmModule = new WebAssembly.Module(readFileSync(modPath.replace(/\.mjs$/, '.wasm')));
    const api = await instantiateEmscripten(factory, wasmModule, {});
    lastHost = api;
    return api;
  }
  const module = new WebAssembly.Module(readFileSync(modPath));
  if (host === 'nodewasi') {
    const { WASI } = await import('node:wasi');
    const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {}, returnOnExit: true });
    const imports = wasi.getImportObject ? wasi.getImportObject() : { wasi_snapshot_preview1: wasi.wasiImport };
    const inst = await WebAssembly.instantiate(module, imports);
    if (wasi.initialize) wasi.initialize(inst);
    else { if (wasi.setMemory) wasi.setMemory(inst.exports.memory); if (inst.exports._initialize) inst.exports._initialize(); }
    if (inst.exports.aprv_init) inst.exports.aprv_init();
    return { fn: (n) => inst.exports[n], buffer: () => inst.exports.memory.buffer };
  }
  const api = await instantiateMinimal(module, {
    policy: host === 'trap' ? 'trap' : 'enosys',
    strictAll: host === 'strict',
    random: process.env.APRV_RANDOM,   // "fail" | "zero": randomness investigation
  });
  lastHost = api.host;
  return api;
}

const d = makeDriver(instantiate);
const tInit = performance.now();
await d.init();
const initMs = performance.now() - tInit;
const memAfterInit = d.api().buffer().byteLength;
const rows = jsonl(readFileSync(reqPath, 'utf8'));
let traps = 0;
if (flag === '--bench') {
  const r = rows.find((row) => row.id === benchId);
  const n = Number(benchN);
  const t0 = performance.now();
  const first = await d.run(r);
  const firstMs = performance.now() - t0;
  for (let i = 0; i < Math.min(200, n); i++) d.runSync(r);
  const t = performance.now();
  for (let i = 0; i < n; i++) d.runSync(r);
  const us = (performance.now() - t) * 1000 / n;
  const mem = d.api().buffer().byteLength;
  console.log(JSON.stringify({ id: r.id, code: first.code, n, init_ms: Math.round(initMs * 100) / 100, first_call_ms: Math.round(firstMs * 100) / 100, mean_us: Math.round(us * 10) / 10, memory_after_init: memAfterInit, memory_bytes: mem }));
} else {
  const out = [];
  for (const r of rows) {
    // Per-row import calls ("imports" field; py/tri.py ignores it).
    const before = lastHost ? { ...lastHost.calls } : {};
    const hostBefore = lastHost;
    const row = await d.run(r);
    if (lastHost && lastHost === hostBefore) {
      const delta = {};
      for (const [k, v] of Object.entries(lastHost.calls)) if (v !== (before[k] || 0)) delta[k] = v - (before[k] || 0);
      if (Object.keys(delta).length) row.imports = delta;
    }
    if (row.code === 'TRAP') traps++;
    out.push(JSON.stringify(row));
  }
  console.log(out.join('\n'));
}
if (lastHost) merge(lastHost.calls);
console.error(JSON.stringify({ host, calls, traps, rows: rows.length }));
