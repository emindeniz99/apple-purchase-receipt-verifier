#!/usr/bin/env node
// Evidence only (2026-09-29). What `init` costs against one call, in Node:
// the core module through Node's own WebAssembly and the canonical ABI
// called by hand (the calling convention of tools/wasm-trap-host.mjs and
// the hand-rolled hosts of the canonical-ABI final round).
//
//   node node-init-cost.mjs <aprv.wasm> <fixtures-dir> [runs] [calls]
//
// Same design as wasmtime/src/main.rs: for each input (the sandbox G5
// receipt under Apple's roots, the generated transaction JWS under its
// fixture root), `runs` runs (default 7) of `calls` iterations (default
// 20), after one warm-up run; each iteration times a fresh instance
// (instantiate, init, one verify call) and one call on a pooled instance
// that has had init. One JSON line per input and run, in microseconds.
import { readFileSync } from 'node:fs';
import { getRandomValues } from 'node:crypto';
import { join } from 'node:path';

const IFACE = 'aprv:verifier/verify@1.0.0#';
const NOW_MS = 1790640000000n; // 2026-09-29T00:00:00Z
const [modulePath, fixtures, runsArg, callsArg] = process.argv.slice(2);
if (!modulePath || !fixtures) {
  console.error('usage: node-init-cost.mjs <aprv.wasm> <fixtures-dir> [runs] [calls]');
  process.exit(2);
}
const runs = Number(runsArg ?? 7);
const calls = Number(callsArg ?? 20);
const utf8 = new TextDecoder('utf-8', { fatal: true });
const enc = new TextEncoder();

class Guest {
  constructor(module) {
    const imports = {
      'aprv:verifier/host@1.0.0': {
        'random-get': (len, retptr) => {
          const n = len >>> 0;
          const bytes = new Uint8Array(n);
          for (let i = 0; i < n; i += 65536) getRandomValues(bytes.subarray(i, Math.min(n, i + 65536)));
          const ptr = this.exports.cabi_realloc(0, 0, 1, n) >>> 0;
          new Uint8Array(this.exports.memory.buffer, ptr, n).set(bytes);
          const view = new DataView(this.exports.memory.buffer);
          view.setUint32(retptr >>> 0, ptr, true);
          view.setUint32((retptr >>> 0) + 4, n, true);
        },
      },
    };
    this.exports = new WebAssembly.Instance(module, imports).exports;
    // The module needs no _initialize (the ABI tests call none); called if
    // present, as tools/wasm-trap-host.mjs does.
    if (typeof this.exports._initialize === 'function') this.exports._initialize();
  }

  lower(bytes) {
    const ptr = this.exports.cabi_realloc(0, 0, 1, bytes.length) >>> 0;
    new Uint8Array(this.exports.memory.buffer, ptr, bytes.length).set(bytes);
    return [ptr | 0, bytes.length];
  }

  lift(fn, retptr) {
    const view = new DataView(this.exports.memory.buffer);
    const ptr = view.getUint32(retptr >>> 0, true);
    const len = view.getUint32((retptr >>> 0) + 4, true);
    const text = utf8.decode(new Uint8Array(this.exports.memory.buffer, ptr, len).slice());
    this.exports[`cabi_post_${IFACE}${fn}`](retptr);
    return text;
  }

  init(config) {
    return this.lift('init', this.exports[`${IFACE}init`](...this.lower(config)));
  }

  verify(fn, input) {
    return this.lift(fn, this.exports[`${IFACE}${fn}`](BigInt.asIntN(64, NOW_MS), ...this.lower(input)));
  }
}

const module = new WebAssembly.Module(readFileSync(modulePath));
const read = (p) => readFileSync(join(fixtures, p));
const inputs = [
  {
    name: 'g5',
    config: enc.encode('{"roots":[]}'),
    fn: 'verify-receipt',
    bytes: enc.encode(read('public-receipts/receipt-sandbox-g5.b64').toString('ascii').replace(/\s+/g, '')),
  },
  {
    name: 'jws',
    config: enc.encode(JSON.stringify({ roots: [read('generated/jws-root.der').toString('base64')] })),
    fn: 'verify-signed-data',
    bytes: enc.encode(read('generated/transaction.jws').toString('utf8').trim()),
  },
];

const call = (g, input) => {
  const out = g.verify(input.fn, input.bytes);
  if (!out.startsWith('{"verified":true')) throw new Error(`${input.name}: ${out.slice(0, 200)}`);
};
const initOk = (g, config) => {
  const answer = g.init(config);
  if (answer !== '{"ok":true}') throw new Error(`init: ${answer}`);
};

for (const input of inputs) {
  const pooled = new Guest(module);
  initOk(pooled, input.config);
  for (let run = 0; run <= runs; run++) {
    let inst = 0;
    let init = 0;
    let first = 0;
    let pool = 0;
    for (let i = 0; i < calls; i++) {
      const a = process.hrtime.bigint();
      const g = new Guest(module);
      const b = process.hrtime.bigint();
      initOk(g, input.config);
      const c = process.hrtime.bigint();
      call(g, input);
      const d = process.hrtime.bigint();
      call(pooled, input);
      const e = process.hrtime.bigint();
      inst += Number(b - a);
      init += Number(c - b);
      first += Number(d - c);
      pool += Number(e - d);
    }
    if (run === 0) continue; // warm-up
    const us = (ns) => Math.round(ns / calls / 100) / 10;
    console.log(
      JSON.stringify({
        host: `node-${process.version}`,
        input: input.name,
        run,
        calls,
        instantiate_us: us(inst),
        init_us: us(init),
        fresh_call_us: us(first),
        pool_call_us: us(pool),
      }),
    );
  }
}
