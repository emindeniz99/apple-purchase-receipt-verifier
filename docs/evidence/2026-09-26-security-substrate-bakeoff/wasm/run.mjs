// Runs a request corpus through the C ABI inside a wasm module, the same
// way run_rust.py (2026-09-25 native-image spike) runs it through the
// native .so. Rows: {"id","code","json"}, so py/tri.py compares them.
//
//   node wasm/run.mjs <module.wasm> <requests.jsonl> > rows.jsonl
//   node wasm/run.mjs <module.wasm> <requests.jsonl> --bench <row id> <n>
//
// The module is the shim (wasm/shim): rust/ffi's exports plus aprv_alloc
// and aprv_dealloc. A module that imports wasi_snapshot_preview1 gets
// node:wasi with no preopened directories, no environment and no
// arguments. Any other import is reported and the run stops.
//
// A trap (a Rust panic under panic=abort, an `unreachable` in C) is row
// code "TRAP"; the instance is thrown away and a fresh one serves the next
// row, since a trapped instance's heap can be half-updated.
import { readFileSync } from 'node:fs';

const [wasmPath, requestsPath, flag, benchId, benchN] = process.argv.slice(2);
const bytes = readFileSync(wasmPath);
const module = new WebAssembly.Module(bytes);
const importModules = [...new Set(WebAssembly.Module.imports(module).map((i) => i.module))];
const foreign = importModules.filter((m) => m !== 'wasi_snapshot_preview1');
if (foreign.length) {
  console.error('unresolvable imports:', WebAssembly.Module.imports(module)
    .filter((i) => i.module !== 'wasi_snapshot_preview1').map((i) => `${i.module}.${i.name}`).join(' '));
  process.exit(3);
}
const ENV_BITS = { Production: 1, Sandbox: 2, Xcode: 4, LocalTesting: 8 };
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

let memoryRef = null;
const wasiCalls = {};
if (process.env.APRV_TRACE_WASI === '1') process.on('exit', () => console.error('wasi calls', JSON.stringify(wasiCalls)));
async function instantiate() {
  let imports = {};
  let wasi = null;
  if (importModules.includes('wasi_snapshot_preview1')) {
    const { WASI } = await import('node:wasi');
    wasi = new WASI({ version: 'preview1', args: [], env: {}, preopens: {}, returnOnExit: true });
    // Bun's node:wasi has only the older wasiImport property.
    imports = wasi.getImportObject ? wasi.getImportObject() : { wasi_snapshot_preview1: wasi.wasiImport };
    // Bun 1.3.11's random_get(buf, len) fills the WHOLE linear memory with
    // random bytes and returns len instead of errno 0 (TESTED, see
    // README.md). With APRV_FIX_RANDOM_GET=1 the harness supplies its own
    // random_get that writes only [buf, buf+len) and returns 0.
    if (process.env.APRV_FIX_RANDOM_GET === '1') {
      const p1 = {};
      for (const k of Object.keys(imports.wasi_snapshot_preview1)) p1[k] = imports.wasi_snapshot_preview1[k];
      p1.random_get = (buf, len) => {
        for (let off = 0; off < len; off += 65536) {
          crypto.getRandomValues(new Uint8Array(memoryRef.buffer, buf + off, Math.min(65536, len - off)));
        }
        return 0;
      };
      imports = { wasi_snapshot_preview1: p1 };
    }
    // APRV_TRACE_WASI=1 counts every WASI call and prints the counts to
    // stderr at exit: the wasm form of the strace isolation check.
    if (process.env.APRV_TRACE_WASI === '1') {
      const inner = imports.wasi_snapshot_preview1;
      const traced = {};
      for (const k of Object.keys(inner)) {
        traced[k] = (...a) => { wasiCalls[k] = (wasiCalls[k] || 0) + 1; return inner[k](...a); };
      }
      imports = { wasi_snapshot_preview1: traced };
    }
  }
  const instance = await WebAssembly.instantiate(module, imports);
  memoryRef = instance.exports.memory;
  // Node: initialize() runs _initialize when the module exports one, and
  // must be called before any WASI import is used. Bun has no initialize().
  if (wasi && wasi.initialize) wasi.initialize(instance);
  else {
    if (wasi && wasi.setMemory) wasi.setMemory(instance.exports.memory);
    if (instance.exports._initialize) instance.exports._initialize();
  }
  return instance.exports;
}

let x = await instantiate();
let handles = new Map();

function u8() { return new Uint8Array(x.memory.buffer); }
function dv() { return new DataView(x.memory.buffer); }
let pending = [];
function alloc(len) {
  const p = x.aprv_alloc(len);
  pending.push([p, len]);
  return p;
}
function release() {
  for (const [p, len] of pending) x.aprv_dealloc(p, len);
  pending = [];
}
function put(data, nul = false) {
  const len = Math.max(data.length + (nul ? 1 : 0), 1);
  const p = alloc(len);
  u8().set(data, p);
  if (nul) u8()[p + data.length] = 0;
  return p;
}
function cstr(p) {
  if (!p) return '';
  const m = u8();
  let e = p;
  while (m[e]) e++;
  return dec.decode(m.subarray(p, e));
}
function take(p) {
  const s = cstr(p);
  if (p) x.aprv_string_free(p);
  return s;
}
const b64 = (s) => Uint8Array.from(Buffer.from(s, 'base64'));

function handleFor(r, opts) {
  const key = r.kind + '\0' + r.options;
  if (handles.has(key)) return handles.get(key);
  let ders = 0, lens = 0, count = 0;
  if (opts.roots != null) {
    const blobs = opts.roots.map(b64);
    count = blobs.length;
    ders = alloc(4 * Math.max(count, 1));
    lens = alloc(4 * Math.max(count, 1));
    blobs.forEach((b, i) => {
      dv().setUint32(ders + 4 * i, put(b), true);
      dv().setUint32(lens + 4 * i, b.length, true);
    });
  }
  let bundle = enc.encode(opts.bundleId || '');
  if (r.kind === 'jws' && bundle.length === 0) bundle = enc.encode('conformance.unset.bundle.id');
  let h;
  if (r.kind === 'receipt') {
    if (opts.bundleId == null) h = 0;
    else {
      const bp = put(bundle, true);
      h = opts.roots == null ? x.aprv_verifier_new_receipt(bp)
        : x.aprv_verifier_new_receipt_with_roots(bp, ders, lens, count);
    }
  } else if (r.kind === 'jws') {
    let mask = 0;
    for (const n of opts.acceptedEnvironments || []) mask |= ENV_BITS[n];
    const app = BigInt(opts.appAppleId || 0);
    const bp = put(bundle, true);
    h = opts.roots == null ? x.aprv_verifier_new_jws(bp, mask, app)
      : x.aprv_verifier_new_jws_with_roots(bp, mask, app, ders, lens, count);
  } else {
    const env = ENV_BITS[opts.environment] || 0;
    let clock = 0;
    if (opts.nowMillis != null) {
      clock = alloc(8);
      dv().setBigInt64(clock, BigInt(opts.nowMillis), true);
    }
    h = x.aprv_endpoint_new_with_roots_and_clock(env, ders, lens, count, clock);
  }
  handles.set(key, h);
  return h;
}

function runRow(r) {
  const opts = JSON.parse(r.options);
  const data = b64(r.input);
  const h = handleFor(r, opts);
  if (!h) return { id: r.id, code: 'CTOR_REFUSED', json: null };
  if (r.kind === 'endpoint') {
    if (data.includes(0)) return { id: r.id, code: 'NUL_IN_BODY', json: null };
    const out = alloc(4);
    dv().setUint32(out, 0, true);
    const st = x.aprv_verify_receipt_endpoint_json(h, put(data, true), out);
    return { id: r.id, code: st === 0 ? null : st, json: take(dv().getUint32(out, true)) };
  }
  const res = alloc(8);
  dv().setUint32(res, 0, true);
  dv().setUint32(res + 4, 0, true);
  if (r.kind === 'jws') {
    if (data.includes(0)) return { id: r.id, code: 'NUL_IN_INPUT', json: null };
    const call = [x.aprv_verify_transaction, x.aprv_verify_app_transaction, x.aprv_verify_raw][r.op];
    call(h, put(data, true), res);
  } else {
    const guid = r.guidHex != null ? Uint8Array.from(Buffer.from(r.guidHex, 'hex')) : null;
    if (r.base64) {
      if (data.includes(0)) return { id: r.id, code: 'NUL_IN_INPUT', json: null };
      if (guid) x.aprv_verify_receipt_base64_with_device_guid(h, put(data, true), put(guid), guid.length, res);
      else x.aprv_verify_receipt_base64(h, put(data, true), res);
    } else if (guid) {
      x.aprv_verify_receipt_der_with_device_guid(h, put(data), data.length, put(guid), guid.length, res);
    } else {
      x.aprv_verify_receipt_der(h, put(data), data.length, res);
    }
  }
  return { id: r.id, code: dv().getInt32(res, true), json: take(dv().getUint32(res + 4, true)) };
}

// Every input copy is released after its row (the ABI retains no input
// pointer). The ABI's own strings are freed with aprv_string_free, as the
// header requires. Handles live for the whole run, as in run_rust.py.
const rows = readFileSync(requestsPath, 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
async function safe(r) {
  try {
    const row = runRow(r);
    release();
    return row;
  } catch (e) {
    if (!(e instanceof WebAssembly.RuntimeError)) throw e;
    x = await instantiate();
    handles = new Map();
    pending = [];
    return { id: r.id, code: 'TRAP', json: null, trap: String(e.message) };
  }
}
if (flag === '--bench') {
  const r = rows.find((row) => row.id === benchId);
  const n = Number(benchN);
  const first = await safe(r);
  for (let i = 0; i < Math.min(200, n); i++) await safe(r);
  x = await instantiate();
  handles = new Map();
  pending = [];
  runRow(r);
  release();
  const t = process.hrtime.bigint();
  for (let i = 0; i < n; i++) { runRow(r); release(); }
  const us = Number(process.hrtime.bigint() - t) / 1000 / n;
  console.log(JSON.stringify({ id: r.id, code: first.code, n, mean_us: Math.round(us * 10) / 10, memory_bytes: x.memory.buffer.byteLength }));
} else {
  for (const r of rows) console.log(JSON.stringify(await safe(r)));
}
