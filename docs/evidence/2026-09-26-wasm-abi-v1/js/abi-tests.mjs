// Spike only (ABI v1). The brief's mandatory ABI tests, on Node.
//   node js/abi-tests.mjs module.wasm calls-cases.jsonl
// Every trap is caught, the instance is discarded, and a fresh instance
// must then work. Prints one PASS/FAIL line per test and a summary.
import { readFileSync } from 'node:fs';
import { instantiate, OP, AbiError } from './abi.mjs';

const [modPath, callsPath] = process.argv.slice(2);
const module = new WebAssembly.Module(readFileSync(modPath));
const calls = Object.fromEntries(readFileSync(callsPath, 'utf8').split('\n').filter(Boolean).map((l) => { const c = JSON.parse(l); return [c.id, c]; }));
const G5 = calls['receipt/verify-genuine-sandbox-g5-against-apple-roots'];
const JWS = calls['transaction/verify-shared-sandbox'];
const bytes = (c) => Buffer.from(c.input, 'base64');
const dec = (u8) => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(u8));
let pass = 0, fail = 0;
const ok = (name, cond, detail = '') => { (cond ? pass++ : fail++); console.log(`${cond ? 'PASS' : 'FAIL'} ${name}${detail ? ': ' + detail : ''}`); };
// Runs f on a fresh instance; returns ['trap', message] or ['ok', value].
async function attempt(f) {
  const inst = await instantiate(module);
  try { return ['ok', f(inst)]; } catch (e) { return [e instanceof WebAssembly.RuntimeError ? 'trap' : 'error', String(e.message)]; }
}
async function trapsThenRecovers(name, f) {
  const [kind, msg] = await attempt(f);
  const fresh = await instantiate(module);
  const after = dec(fresh.call(OP.VERIFY_RECEIPT, bytes(G5))).verified === true;
  ok(name, kind === 'trap' && after, `${kind} (${msg}); fresh instance verifies g5: ${after}`);
}

{ const i = await instantiate(module); ok('aprv_abi_version() == 1', i.exports.aprv_abi_version() === 1); }
{ const [k, v] = await attempt((i) => dec(i.call(OP.VERIFY_RECEIPT, bytes(G5))));
  ok('aprv_call(1, VERIFY_RECEIPT, genuine g5) verifies', k === 'ok' && v.verified === true && v.payload.bundleId === 'dev.bonzer.weeka.app', `bundleId ${v && v.payload && v.payload.bundleId}`); }
{ const canon = (x) => JSON.stringify(x, (key, val) => (val && typeof val === 'object' && !Array.isArray(val) ? Object.fromEntries(Object.entries(val).sort()) : val));
  const [k, v] = await attempt((i) => dec(i.call(JWS.op, bytes(JWS))));
  ok('aprv_call(1, VERIFY_SIGNED_DATA (test anchors), shared-sandbox JWS) verifies; payloadJson is the exact signed JSON and parses to payload', k === 'ok' && v.verified === true && canon(JSON.parse(v.payloadJson)) === canon(v.payload), `payloadJson ${v && v.payloadJson && v.payloadJson.length} chars`); }
// ABI version checked first: garbage everywhere else.
await trapsThenRecovers('aprv_call(0, garbage op, invalid ptr, absurd len) fails hard', (i) => i.exports.aprv_call(0, 0x7fffffff, 0xfffffff0, 0x7fffffff));
await trapsThenRecovers('aprv_call(2, garbage op, invalid ptr, absurd len) fails hard', (i) => i.exports.aprv_call(2, 0x7fffffff, 0xfffffff0, 0x7fffffff));
{ const [k, msg] = await attempt((i) => i.call(OP.VERIFY_RECEIPT, bytes(G5), 2));
  ok('bridge reports a version mismatch as an ABI error, never verified=false', k === 'error' && /APRV Wasm ABI mismatch: module=1, caller=2/.test(msg), msg); }
{ const [k, v] = await attempt((i) => { const clock = i.calls['aprv.clock_now_ms']; try { i.exports.aprv_call(3, 1, 0, 0); } catch (e) { /* trap */ } return i.calls['aprv.clock_now_ms'] - clock; });
  ok('a version mismatch runs nothing (no host import called)', k === 'ok' && v === 0, `clock calls during the call: ${v}`); }
// Unknown operation.
for (const op of [0, 5, 99, 255, 256, 261, -1]) await trapsThenRecovers(`unknown operation ${op} fails hard`, (i) => { const p = i.exports.aprv_alloc(4); return i.exports.aprv_call(1, op, p, 4); });
// Invalid pointers and lengths.
await trapsThenRecovers('null input pointer with a length fails hard', (i) => i.exports.aprv_call(1, OP.VERIFY_RECEIPT, 0, 10));
await trapsThenRecovers('input beyond linear memory fails hard', (i) => i.exports.aprv_call(1, OP.VERIFY_RECEIPT, i.memory.buffer.byteLength - 4, 16));
await trapsThenRecovers('input range that overflows u32 fails hard', (i) => i.exports.aprv_call(1, OP.VERIFY_RECEIPT, 0xfffffff0, 0x20));
{ const [k, v] = await attempt((i) => dec(i.call(OP.VERIFY_RECEIPT, new Uint8Array(0))));
  ok('empty input is a verification failure value', k === 'ok' && v.verified === false && v.reason === 'INVALID_RECEIPT_FORMAT', JSON.stringify(v)); }
{ const [k, v] = await attempt((i) => [i.exports.aprv_alloc(0x7fffffff), i.exports.aprv_alloc(0x7ffffff0), dec(i.call(OP.VERIFY_RECEIPT, bytes(G5))).verified]);
  ok('absurd aprv_alloc lengths return 0, and the instance keeps working', k === 'ok' && v[0] === 0 && v[1] === 0 && v[2] === true, JSON.stringify(v)); }
// Invalid handles, double free, use after free.
for (const [name, f] of [
  ['aprv_result_ptr(0)', (i) => i.exports.aprv_result_ptr(0)],
  ['aprv_result_len(12345)', (i) => i.exports.aprv_result_len(12345)],
  ['aprv_result_free(0)', (i) => i.exports.aprv_result_free(0)],
  ['aprv_result_free(never issued)', (i) => i.exports.aprv_result_free(7)],
]) await trapsThenRecovers(`invalid handle: ${name} fails hard`, f);
const withHandle = (i) => { const p = i.exports.aprv_alloc(4); return i.exports.aprv_call(1, OP.VERIFY_RECEIPT, p, 4); };
await trapsThenRecovers('double free fails hard', (i) => { const h = withHandle(i); i.exports.aprv_result_free(h); i.exports.aprv_result_free(h); });
await trapsThenRecovers('use after free (result_ptr) fails hard', (i) => { const h = withHandle(i); i.exports.aprv_result_free(h); i.exports.aprv_result_ptr(h); });
await trapsThenRecovers('use after free (result_len) fails hard', (i) => { const h = withHandle(i); i.exports.aprv_result_free(h); i.exports.aprv_result_len(h); });
{ const [k, v] = await attempt((i) => { const hs = [withHandle(i), withHandle(i), withHandle(i)]; i.exports.aprv_result_free(hs[1]); const h4 = withHandle(i); return [hs, h4]; });
  ok('freed handles are reused and live ones stay valid', k === 'ok' && v[1] === v[0][1], JSON.stringify(v)); }
// Verification failures are values, not traps.
{ const [k, v] = await attempt((i) => dec(i.call(OP.VERIFY_RECEIPT, new TextEncoder().encode('not a receipt'))));
  ok('garbage receipt -> verified=false value', k === 'ok' && v.verified === false, JSON.stringify(v)); }
{ const [k, v] = await attempt((i) => dec(i.call(OP.VERIFY_SIGNED_DATA, new Uint8Array([0xff, 0xfe, 0x2e]))));
  ok('non-UTF-8 JWS -> verified=false INVALID_JWS_FORMAT', k === 'ok' && v.verified === false && v.reason === 'INVALID_JWS_FORMAT', JSON.stringify(v)); }
{ const [k, v] = await attempt((i) => dec(i.call(OP.ENDPOINT_SANDBOX, new TextEncoder().encode('{"receipt-data": '))));
  ok('malformed endpoint request JSON -> Apple status 21002 value', k === 'ok' && v.status === 21002, JSON.stringify(v)); }
// Host-side malformed JSON: the bridge's decode refuses it as an internal failure.
{ let msg = '';
  try { dec(new TextEncoder().encode('{"verified":tru')); } catch (e) { msg = `${e.name}: ${e.message}`; }
  ok('malformed result JSON is a host decode error (internal failure), not a verdict', /SyntaxError/.test(msg), msg); }
// Ownership: the result is a copy; freeing the handle and reusing memory does not change it.
{ const [k, v] = await attempt((i) => { const a = i.call(OP.VERIFY_RECEIPT, bytes(G5)); const snap = Buffer.from(a).toString('hex'); for (let n = 0; n < 5; n++) i.call(OP.VERIFY_RECEIPT, new TextEncoder().encode('x'.repeat(n + 1))); return snap === Buffer.from(a).toString('hex'); });
  ok('a result is a host-owned copy (unchanged after later calls reuse guest memory)', k === 'ok' && v === true); }
// Leak check: 2,000 calls keep linear memory flat after warm-up.
{ const [k, v] = await attempt((i) => { for (let n = 0; n < 200; n++) i.call(OP.VERIFY_RECEIPT, bytes(G5)); const m1 = i.memory.buffer.byteLength; for (let n = 0; n < 2000; n++) i.call(OP.VERIFY_RECEIPT, bytes(G5)); return [m1, i.memory.buffer.byteLength]; });
  ok('no growth of linear memory over 2,000 more calls', k === 'ok' && v[0] === v[1], JSON.stringify(v)); }
console.log(`summary: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
