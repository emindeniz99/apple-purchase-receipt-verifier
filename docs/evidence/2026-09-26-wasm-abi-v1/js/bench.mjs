// Spike only (ABI v1). Round 6's Node method on the ABI v1 bridge: one
// instance, 200 warm-up calls, then 1,000 timed calls through the full
// lifecycle (alloc, copy, aprv_call, copy out, free, dealloc) plus the
// host's JSON decode, for one call id. Checks every result is verified.
//   node js/bench.mjs module.wasm calls-cases.jsonl id [n]
import { readFileSync } from 'node:fs';
import { instantiate } from './abi.mjs';

const [modPath, callsPath, id, n = '1000'] = process.argv.slice(2);
const c = readFileSync(callsPath, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l)).find((x) => x.id === id);
const input = Buffer.from(c.input, 'base64');
const inst = await instantiate(new WebAssembly.Module(readFileSync(modPath)));
const dec = new TextDecoder('utf-8', { fatal: true });
const once = () => { const v = JSON.parse(dec.decode(inst.call(c.op, input))); if (v.verified !== true) throw new Error('not verified'); };
for (let i = 0; i < 200; i++) once();
const t0 = process.hrtime.bigint();
for (let i = 0; i < Number(n); i++) once();
const us = Number(process.hrtime.bigint() - t0) / 1000 / Number(n);
console.log(JSON.stringify({ id, op: c.op, node: process.version, warm: 200, n: Number(n), mean_us: Math.round(us), per_s: Math.round(1e6 / us * 10) / 10 }));
