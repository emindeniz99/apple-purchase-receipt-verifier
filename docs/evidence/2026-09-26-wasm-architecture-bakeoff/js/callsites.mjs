// Spike only. Which wasm functions call a given import? Runs a corpus
// through a module with the minimal host and records the wasm call stack
// (from the module's name section) at every call of the named imports.
//
//   node js/callsites.mjs <module.wasm> <requests.jsonl> <import> [<import> ...]
//
// Prints each distinct stack (innermost 12 wasm frames, demangled roughly)
// with its count.
import { readFileSync } from 'node:fs';
import { makeDriver, jsonl } from './driver.mjs';
import { minimalHost } from './hosts.mjs';

const [modPath, reqPath, ...names] = process.argv.slice(2);
const module = new WebAssembly.Module(readFileSync(modPath));
const stacks = new Map();
Error.stackTraceLimit = 64;
function frames() {
  return new Error().stack.split('\n').filter((l) => l.includes('wasm://') || l.includes('wasm-function'))
    .map((l) => l.trim().replace(/^at /, '').replace(/ \(wasm:.*$/, '')
      .replace(/_ZN(\d+)/g, '').replace(/17h[0-9a-f]{16}E$/, '').replace(/\d+([a-z_]+)/g, '$1::'))
    .slice(0, 12);
}
const d = makeDriver(async () => {
  const host = minimalHost(module, {});
  for (const full of names) {
    const [m, n] = full.split('.');
    const inner = host.imports[m] && host.imports[m][n];
    if (!inner) continue;
    host.imports[m][n] = (...a) => {
      const key = full + '\n    ' + frames().join('\n    ');
      stacks.set(key, (stacks.get(key) || 0) + 1);
      return inner(...a);
    };
  }
  const instance = await WebAssembly.instantiate(module, host.imports);
  host.setMemory(instance.exports.memory);
  if (instance.exports._initialize) instance.exports._initialize();
  if (instance.exports.aprv_init) instance.exports.aprv_init();
  return { fn: (n) => instance.exports[n], buffer: () => instance.exports.memory.buffer };
});
await d.init();
for (const r of jsonl(readFileSync(reqPath, 'utf8'))) await d.run(r);
for (const [k, v] of [...stacks].sort((a, b) => b[1] - a[1])) console.log(`${v}x ${k}\n`);
