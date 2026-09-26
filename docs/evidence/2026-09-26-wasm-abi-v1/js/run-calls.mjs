// Spike only (ABI v1). Runs calls.jsonl (py/abi_calls.py) through the module
// on Node: one instance, discarded and replaced after a trap.
//   node js/run-calls.mjs module.wasm calls.jsonl > out.jsonl
// Output per call: {"id","out"} (the result bytes as UTF-8) or {"id","trap"}.
// Calls without an "op" are passed through as {"id","map"}.
import { readFileSync } from 'node:fs';
import { instantiate } from './abi.mjs';

const [modPath, callsPath] = process.argv.slice(2);
const module = new WebAssembly.Module(readFileSync(modPath));
let inst = await instantiate(module);
const dec = new TextDecoder('utf-8', { fatal: true });
const lines = [];
let traps = 0, instances = 1;
const calls = {};
const tally = () => { for (const [k, v] of Object.entries(inst.calls)) calls[k] = (calls[k] || 0) + v; };
for (const line of readFileSync(callsPath, 'utf8').split('\n')) {
  if (!line.trim()) continue;
  const c = JSON.parse(line);
  if (c.op === undefined) { lines.push(JSON.stringify({ id: c.id, map: c.map })); continue; }
  try {
    const out = inst.call(c.op, Buffer.from(c.input, 'base64'));
    lines.push(JSON.stringify({ id: c.id, out: dec.decode(out) }));
  } catch (e) {
    traps++; tally(); inst = await instantiate(module); instances++;
    lines.push(JSON.stringify({ id: c.id, trap: String(e.message || e) }));
  }
}
tally();
process.stdout.write(lines.join('\n') + '\n');
console.error(JSON.stringify({ host: 'node', node: process.version, calls, traps, instances, rows: lines.length }));
