// Spike only (2026-09-29, round 13). Start-up to the first result in one
// fresh process, on Node, Deno or Bun: the ABI v1 module through ABI v1's
// own bridge (../../../2026-09-26-wasm-abi-v1/js/abi.mjs), or the
// canonical-ABI component through jco's glue. Prints the runtime's clock
// (performance.now(), from the time origin) at entry and at the first
// result, and the compile/instantiate/first-call split.
//   node startup.mjs v1 V1.wasm CASES.jsonl
//   node startup.mjs cabi JCO_OUT_DIR CASES.jsonl
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Buffer } from 'node:buffer';
import process from 'node:process';

const atEntry = performance.now();
const [which, path, casesPath] = process.argv.slice(globalThis.Deno ? 1 : 2).slice(-3);
const g5row = readFileSync(casesPath, 'utf8').split('\n').find((l) => l.includes('"receipt/verify-genuine-sandbox-g5-against-apple-roots"'));
const g5 = new Uint8Array(Buffer.from(JSON.parse(g5row).b64, 'base64'));
const t0 = performance.now();
let first, second, t1;
if (which === 'v1') {
  const { instantiate } = await import(new URL('../../../2026-09-26-wasm-abi-v1/js/abi.mjs', import.meta.url).href);
  const inst = await instantiate(await WebAssembly.compile(readFileSync(path)));
  t1 = performance.now();
  const dec = new TextDecoder();
  first = dec.decode(inst.call(1, g5));
  var atFirst = performance.now();
  second = dec.decode(inst.call(1, g5));
} else {
  const { instantiate } = await import(pathToFileURL(resolve(path, 'aprv.js')).href);
  const getCoreModule = (name) => WebAssembly.compile(readFileSync(join(path, name)));
  const v = (await instantiate(getCoreModule, { 'aprv:verifier/host': { randomGet: (n) => crypto.getRandomValues(new Uint8Array(n)) } })).verify;
  v.init(new Uint8Array(0));
  t1 = performance.now();
  first = v.verifyReceipt(BigInt(Date.now()), g5);
  var atFirst = performance.now();
  second = v.verifyReceipt(BigInt(Date.now()), g5);
}
const t3 = performance.now();
if (!first.includes('"verified":true') || !second.includes('"verified":true')) throw new Error(first.slice(0, 200));
const f = (x) => Math.round(x * 10) / 10;
console.log(JSON.stringify({ module: which === 'v1' ? 'ABI v1' : 'canonical ABI', at_entry_ms: f(atEntry), load_compile_instantiate_ms: f(t1 - t0), first_g5_ms: f(atFirst - t1), second_g5_ms: f(t3 - atFirst), at_first_result_ms: f(atFirst) }));
