// Reproduces the Bun 1.3.11 node:wasi random_get defect recorded in the note:
// random_get(buf=1000, len=16) on a fresh, zeroed 64 KiB memory. WASI says:
// fill [1000, 1016) and return errno 0. Bun 1.3.11 returned 16 and left
// non-zero bytes across the whole memory (nonzero range 0..65535).
//   bun wasm/bun-random-get.mjs
// (Node refuses a WASI call on an instance that was not started, so this
// file is for Bun; Node's correct behavior shows in the corpus runs.)
import { WASI } from 'node:wasi';
const wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {} });
const mem = new WebAssembly.Memory({ initial: 1 });
wasi.setMemory ? wasi.setMemory(mem) : null;
const u = new Uint8Array(mem.buffer);
const r = wasi.wasiImport.random_get(1000, 16);
const nz = (a, b) => u.slice(a, b).some((x) => x !== 0);
console.log('ret', r, 'written at [1000,1016)', nz(1000, 1016), 'after 1016', nz(1016, 65536), 'before 1000', nz(0, 1000));
let first = -1, last = -1; u.forEach((x, i) => { if (x) { if (first < 0) first = i; last = i; } });
console.log('nonzero range', first, last);
