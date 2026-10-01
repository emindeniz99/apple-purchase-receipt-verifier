#!/usr/bin/env node
// A trap-on-anything host for aprv.wasm: Node's own WebAssembly, the core
// module (not the component), and the canonical ABI called by hand, as the
// canonical-ABI final round's hand-rolled hosts do
// (docs/evidence/2026-09-29-canonical-abi-final/hosts/wazero/main.go).
//
// The import object supplies `random-get` from aprv:verifier/host@0.1.0 and,
// for every other import the module declares, a function that throws. So
// the module can take no path nobody measured: a call to any other import
// traps the call, and the run fails. A module that declares any import but
// `random-get` fails the run as well, before anything is called.
//
//   node tools/wasm-trap-host.mjs imports   <module.wasm>
//        Lists the imports; exit 1 unless they are exactly random-get.
//   node tools/wasm-trap-host.mjs cases     <module.wasm> <cases.json> [--answers <dir>]
//        Every case of fixtures/cases.json through the ABI, checked against
//        its expectation, one line per case; exit 1 on any failure or trap.
//        --answers writes what each export answered, one JSON text per
//        line (init-config.jsonl, init.jsonl, verify-receipt.jsonl,
//        verify-signed-data.jsonl), for tools/validate-wire.mjs.
//   node tools/wasm-trap-host.mjs calls     <module.wasm> <calls.jsonl> [--reference <rows.jsonl>]
//        The spike corpora in round 13's calls format
//        (docs/evidence/2026-09-29-canonical-abi-final/py/calls_bytes.py):
//        one {"id","out"} / {"id","trap"} / {"id","map"} row per call on
//        stdout, as the round's hosts print them. --reference compares each
//        row's answer byte for byte with another run's rows; exit 1 on a
//        difference, a trap, or an unexpected import call.
//   node tools/wasm-trap-host.mjs abi-tests <module.wasm> <cases.json>
//        The ABI tests of the final round that a hand-rolled host can run
//        (ARCHITECTURE.md §9): env 2, 255 and 2^32-1 trap; verify before
//        init and a second init trap; a bad root is {"ok":false} and init
//        retries; a wrong-length random-get traps; a trap in one instance
//        leaves another verifying; 2,000 calls leave memory the same size.
//
// No dependencies: node:fs, node:crypto and WebAssembly only. Node 20+.
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { createHash, getRandomValues } from 'node:crypto';
import { dirname, join } from 'node:path';

const IFACE = 'aprv:verifier/verify@0.1.0#';
const HOST_MODULE = 'aprv:verifier/host@0.1.0';
const RANDOM_GET = 'random-get';

class HostError extends Error {}

// --- canonical ABI (hand-written) begin ---------------------------------

// Each export's WIT parameters, in order: 'w' u32, 'd' u64, 'b' list<u8>.
const SIGS = { init: 'b', 'verify-receipt': 'db', 'verify-signed-data': 'db', 'verify-receipt-endpoint': 'wdb' };
const utf8 = new TextDecoder('utf-8', { fatal: true });

class Guest {
  /** @param {WebAssembly.Module} module @param {{randomTrim?: number}} hooks */
  constructor(module, hooks = {}) {
    this.unexpectedCalls = [];
    this.randomCalls = 0;
    const imports = {};
    for (const imp of WebAssembly.Module.imports(module)) {
      imports[imp.module] ??= {};
      if (imp.module === HOST_MODULE && imp.name === RANDOM_GET && imp.kind === 'function') {
        // random-get: func(len: u32) -> list<u8>, lowered as (len, retptr);
        // the list lives in guest memory from the guest's cabi_realloc.
        imports[imp.module][imp.name] = (len, retptr) => {
          this.randomCalls++;
          const n = Math.max(0, (len >>> 0) - (hooks.randomTrim ?? 0)); // test hook
          const bytes = new Uint8Array(n);
          for (let i = 0; i < n; i += 65536) getRandomValues(bytes.subarray(i, Math.min(n, i + 65536)));
          const ptr = this.exports.cabi_realloc(0, 0, 1, n) >>> 0;
          this.write(ptr, bytes);
          const view = new DataView(this.memory.buffer);
          view.setUint32(retptr >>> 0, ptr, true);
          view.setUint32((retptr >>> 0) + 4, n, true);
        };
      } else if (imp.kind === 'function') {
        const what = `${imp.module} ${imp.name}`;
        imports[imp.module][imp.name] = () => {
          this.unexpectedCalls.push(what);
          throw new HostError(`unexpected import called: ${what}`);
        };
      } else {
        throw new HostError(`the module imports a ${imp.kind} (${imp.module} ${imp.name}); only the function random-get is allowed`);
      }
    }
    this.instance = new WebAssembly.Instance(module, imports);
    this.exports = this.instance.exports;
    this.memory = this.exports.memory;
    if (typeof this.exports._initialize === 'function') this.exports._initialize();
  }

  write(ptr, bytes) {
    if (ptr + bytes.length > this.memory.buffer.byteLength) {
      throw new HostError(`cabi_realloc returned an out-of-range buffer (${ptr}, ${bytes.length})`);
    }
    new Uint8Array(this.memory.buffer, ptr, bytes.length).set(bytes);
  }

  /** WIT values to core arguments, checked against fn's signature. */
  lower(fn, args) {
    const sig = SIGS[fn];
    if (sig === undefined || sig.length !== args.length) {
      throw new HostError(`${fn}: unknown export or wrong argument count`);
    }
    const out = [];
    args.forEach((a, i) => {
      if (sig[i] === 'w' && typeof a === 'number' && Number.isInteger(a) && a >= 0 && a <= 0xffffffff) {
        out.push(a | 0);
      } else if (sig[i] === 'd' && typeof a === 'bigint' && a >= 0n && a < 1n << 64n) {
        out.push(BigInt.asIntN(64, a));
      } else if (sig[i] === 'b' && a instanceof Uint8Array) {
        const ptr = this.exports.cabi_realloc(0, 0, 1, a.length) >>> 0;
        this.write(ptr, a); // the guest takes ownership of this buffer
        out.push(ptr | 0, a.length);
      } else {
        throw new HostError(`${fn}: argument ${i} is ${typeof a}, the WIT type is ${sig[i]}`);
      }
    });
    return out;
  }

  /** An export whose result is a string: lower, call, lift, post-return. */
  call(fn, ...args) {
    const retptr = this.exports[IFACE + fn](...this.lower(fn, args)) >>> 0;
    const size = this.memory.buffer.byteLength;
    if (retptr + 8 > size) throw new HostError(`${fn}: return area ${retptr} is out of range`);
    const view = new DataView(this.memory.buffer);
    const ptr = view.getUint32(retptr, true);
    const len = view.getUint32(retptr + 4, true);
    if (ptr + len > size) throw new HostError(`${fn}: result (${ptr}, ${len}) is out of range`);
    const text = utf8.decode(new Uint8Array(this.memory.buffer, ptr, len).slice());
    this.exports[`cabi_post_${IFACE}${fn}`](retptr | 0);
    return text;
  }
}

// --- canonical ABI (hand-written) end -----------------------------------

function loadModule(path) {
  return new WebAssembly.Module(readFileSync(path));
}

function importList(module) {
  return WebAssembly.Module.imports(module).map((i) => `${i.module} ${i.name} (${i.kind})`);
}

function onlyRandomGet(module) {
  const list = WebAssembly.Module.imports(module);
  return list.length === 1 && list[0].module === HOST_MODULE && list[0].name === RANDOM_GET && list[0].kind === 'function';
}

function requireOnlyRandomGet(module) {
  if (!onlyRandomGet(module)) {
    console.error(`wasm-trap-host: the module must import exactly ${HOST_MODULE} ${RANDOM_GET}; it imports: ${importList(module).join('; ') || 'nothing'}`);
    process.exit(1);
  }
}

const enc = new TextEncoder();
const bytesOf = (s) => enc.encode(s);
const isTrap = (e) => e instanceof WebAssembly.RuntimeError || e instanceof HostError;

// --- fixtures/cases.json ---------------------------------------------------

// JSON.parse reads numbers as doubles; the endpoint's 64-bit ids would round.
// Integer literals a double cannot hold become BigInts (the Node port's rule).
const BIG = '__bigint__:';
const LITERAL = /"(?:[^"\\]|\\.)*"|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?/g;
function parseBig(text) {
  const tagged = text.replace(LITERAL, (l) =>
    l.startsWith('"') || !/^-?\d+$/.test(l) || Number.isSafeInteger(Number(l)) ? l : `"${BIG}${l}"`,
  );
  return JSON.parse(tagged, (_k, v) => (typeof v === 'string' && v.startsWith(BIG) ? BigInt(v.slice(BIG.length)) : v));
}

function loadCases(path) {
  const doc = parseBig(readFileSync(path, 'utf8'));
  const base = dirname(path);
  const cache = new Map();
  const fixture = (id) => {
    if (cache.has(id)) return cache.get(id);
    const entry = doc.fixtures[id];
    if (entry === undefined) throw new Error(`cases.json registers no fixture "${id}"`);
    const raw = readFileSync(join(base, entry.path));
    let bytes;
    switch (entry.codec) {
      case 'raw':
      case 'text':
        bytes = raw;
        break;
      case 'base64':
        bytes = Buffer.from(raw.toString('ascii').replace(/\s+/g, ''), 'base64');
        break;
      case 'utf8':
        bytes = Buffer.from(raw.toString('utf8').trim(), 'utf8');
        break;
      default:
        throw new Error(`unknown fixture codec "${entry.codec}"`);
    }
    const digest = createHash('sha256').update(bytes).digest('hex');
    if (digest !== entry.contentSha256) throw new Error(`fixture "${id}" has drifted from its contentSha256`);
    const value = { entry, bytes: new Uint8Array(bytes) };
    cache.set(id, value);
    return value;
  };
  return { doc, fixture };
}

function receiptText({ entry, bytes }) {
  return entry.codec === 'raw' || entry.codec === 'base64' ? Buffer.from(bytes).toString('base64') : Buffer.from(bytes).toString('utf8');
}

/** init's argument for a case: its roots as base64 DER, or [] for the three Apple roots. */
function initConfig(kase, fixture) {
  const spec = kase.config?.trustedRoots;
  const roots = spec === undefined || spec.source === 'defaults' ? [] : spec.fixtures.map((id) => Buffer.from(fixture(id).bytes).toString('base64'));
  return JSON.stringify({ roots });
}

function nowMs(kase) {
  if (kase.clock?.now === undefined) return BigInt(Date.now());
  const ms = Date.parse(kase.clock.now);
  if (Number.isNaN(ms)) throw new Error(`unparseable clock "${kase.clock.now}"`);
  return BigInt(ms);
}

function pointer(root, ptr) {
  if (ptr === '') return root;
  let cur = root;
  for (const raw of ptr.slice(1).split('/')) {
    const token = raw.replace(/~1/g, '/').replace(/~0/g, '~');
    if (cur === null || cur === undefined) return undefined;
    const bracket = /^\[(.*)]$/.exec(token);
    if (bracket) {
      const inner = bracket[1];
      const eq = inner.indexOf('=');
      if (eq > 0) {
        const [k, want] = [inner.slice(0, eq), inner.slice(eq + 1)];
        const hits = Array.isArray(cur) ? cur.filter((e) => e !== null && typeof e === 'object' && String(e[k]) === want) : [];
        if (hits.length !== 1) throw new Error(`[${inner}] selected ${hits.length} elements`);
        cur = hits[0];
      } else {
        cur = Array.isArray(cur) ? cur[Number(inner)] : cur[inner];
      }
      continue;
    }
    cur = token === 'length' && Array.isArray(cur) ? cur.length : cur[token];
  }
  return cur;
}

function sameValue(a, b) {
  if (typeof a === 'bigint' || typeof b === 'bigint') return String(a) === String(b);
  if (a === null || b === null || typeof a !== 'object' || typeof b !== 'object') return Object.is(a, b);
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a);
  const kb = Object.keys(b);
  return ka.length === kb.length && ka.every((k) => Object.hasOwn(b, k) && sameValue(a[k], b[k]));
}

function checkFields(doc, expected, problems) {
  for (const [ptr, want] of Object.entries(expected.fields ?? {})) {
    const got = pointer(doc, ptr);
    const ok = want === null ? got === null || got === undefined : sameValue(got, want);
    if (!ok) problems.push(`${ptr}: got ${stringify(got)}, want ${stringify(want)}`);
  }
  for (const [ptr, want] of Object.entries(expected.lengths ?? {})) {
    const got = pointer(doc, ptr);
    if (!Array.isArray(got) || got.length !== want) problems.push(`${ptr} length: got ${Array.isArray(got) ? got.length : stringify(got)}, want ${want}`);
  }
}

const stringify = (v) => JSON.stringify(v, (_k, x) => (typeof x === 'bigint' ? `${x}n` : x));

/** A JWS whose header carries `text` as every x5c entry, to reach the x5c decoder through the ABI. */
function x5cProbe(text) {
  const b64url = (s) => Buffer.from(s).toString('base64url');
  return `${b64url(JSON.stringify({ alg: 'ES256', x5c: [text, text, text] }))}.${b64url('{}')}.${b64url('signature')}`;
}

// --- modes -------------------------------------------------------------------

function modeImports(modulePath) {
  const module = loadModule(modulePath);
  for (const line of importList(module)) console.log(`import ${line}`);
  if (!onlyRandomGet(module)) {
    console.error(`wasm-trap-host: expected exactly one import, ${HOST_MODULE} ${RANDOM_GET}`);
    process.exit(1);
  }
  console.log(`imports: exactly ${HOST_MODULE} ${RANDOM_GET}`);
}

function modeCases(modulePath, casesPath, answersDir) {
  const module = loadModule(modulePath);
  requireOnlyRandomGet(module);
  const { doc, fixture } = loadCases(casesPath);
  const answers = { 'init-config': [], init: [], 'verify-receipt': [], 'verify-signed-data': [] };
  const pool = new Map(); // init config -> Guest
  const unexpected = new Set();
  let traps = 0;

  const guestFor = (config) => {
    let g = pool.get(config);
    if (g) return { g };
    g = new Guest(module);
    const answer = g.call('init', bytesOf(config));
    answers['init-config'].push(config);
    answers.init.push(answer);
    if (answer !== '{"ok":true}') return { refused: answer };
    pool.set(config, g);
    return { g };
  };
  const invoke = (config, fn, ...args) => {
    const got = guestFor(config);
    if (got.refused !== undefined) throw new Error(`init refused the case's roots: ${got.refused}`);
    try {
      const out = got.g.call(fn, ...args);
      if (fn === 'verify-receipt' || fn === 'verify-signed-data') answers[fn].push(out);
      return out;
    } catch (e) {
      got.g.unexpectedCalls.forEach((c) => unexpected.add(c));
      pool.delete(config); // a trap discards the instance
      throw e;
    }
  };

  const runVerify = (kase) => {
    const config = initConfig(kase, fixture);
    const now = nowMs(kase);
    const problems = [];
    let out;
    switch (kase.operation) {
      case 'verifyReceipt':
        out = invoke(config, 'verify-receipt', now, bytesOf(receiptText(fixture(kase.input.fixture))));
        break;
      case 'verifySignedData':
        out = invoke(config, 'verify-signed-data', now, fixture(kase.input.fixture).bytes);
        break;
      case 'verifyReceiptEndpoint': {
        const env = { PRODUCTION: 0, SANDBOX: 1 }[kase.config.environment];
        if (env === undefined) throw new Error(`unknown environment ${kase.config.environment}`);
        const body =
          kase.input.requestBody !== undefined
            ? fixture(kase.input.requestBody).bytes
            : bytesOf(JSON.stringify({ 'receipt-data': receiptText(fixture(kase.input.fixture)) }));
        out = invoke(config, 'verify-receipt-endpoint', env, now, body);
        checkFields(parseBig(out), kase.expected, problems);
        return problems;
      }
      default:
        throw new Error(`no mapping for operation ${kase.operation}`);
    }
    const result = parseBig(out);
    const outcome = result.verified === true ? 'ok' : result.reason;
    const e = kase.expected;
    if (e.oneOf) {
      if (!e.oneOf.includes(outcome)) problems.push(`answered ${outcome}, want one of ${e.oneOf.join(', ')}`);
      return problems;
    }
    if (e.status === 'error') {
      if (outcome !== e.reason) problems.push(`answered ${outcome}, want ${e.reason}`);
      for (const cp of e.messageMustNotContain ?? []) {
        if (typeof result.message === 'string' && result.message.includes(String.fromCodePoint(cp))) {
          problems.push(`message contains U+${cp.toString(16)}`);
        }
      }
      return problems;
    }
    if (outcome !== 'ok') {
      problems.push(`answered ${outcome} (${result.message}), want ok`);
      return problems;
    }
    // verify-receipt's payload is the ReceiptPayload JSON; verify-signed-data's
    // is a JSON string holding the signed payload's bytes.
    const payload = typeof result.payload === 'string' ? parseBig(result.payload) : result.payload;
    if (e.toJson !== undefined && !sameValue(payload, parseBig(e.toJson))) problems.push('toJson value differs');
    checkFields(payload, e, problems);
    return problems;
  };

  // decodeBase64: a receipt-data text through verify-receipt, an x5c text
  // through a JWS header (SURFACE.md §6). Both sides of the rule share a
  // reason, so which side a text landed on is read from the message: a
  // decoder refusal names base64; anything later (the bytes are no receipt,
  // no certificate) does not.
  const runDecode = (kase) => {
    const problems = [];
    const config = JSON.stringify({ roots: [] });
    for (const decoder of kase.decoders) {
      kase.input.texts.forEach((text, i) => {
        let out;
        let refusal;
        if (decoder === 'receipt-data') {
          out = invoke(config, 'verify-receipt', BigInt(Date.now()), bytesOf(text));
          refusal = 'MALFORMED';
        } else if (decoder === 'x5c') {
          out = invoke(config, 'verify-signed-data', BigInt(Date.now()), bytesOf(x5cProbe(text)));
          refusal = 'INVALID_CERTIFICATE';
        } else {
          throw new Error(`no decoder ${decoder}`);
        }
        const r = JSON.parse(out);
        const refused = r.verified === false && r.reason === refusal && (text === '' || /base64/i.test(r.message ?? ''));
        const where = `${decoder} texts[${i}] ${JSON.stringify(text).slice(0, 40)}`;
        if (r.verified === true) problems.push(`${where} verified`);
        else if (kase.expected.status === 'error' && !refused) problems.push(`${where} not refused by the decoder: ${r.reason} ${r.message}`);
        else if (kase.expected.status === 'ok' && refused) problems.push(`${where} refused by the decoder: ${r.message}`);
      });
    }
    return problems;
  };

  const ran = new Set();
  let failed = 0;
  for (const kase of doc.cases) {
    ran.add(kase.id);
    let problems;
    try {
      if (kase.operation === 'decodeBase64') {
        problems = runDecode(kase);
      } else if (kase.maxMillis !== undefined) {
        runVerify(kase); // warm-up, as every port's runner does
        const start = performance.now();
        problems = runVerify(kase);
        const ms = performance.now() - start;
        if (ms > kase.maxMillis) problems.push(`took ${ms.toFixed(1)} ms, over the ${kase.maxMillis} ms budget`);
      } else {
        problems = runVerify(kase);
      }
    } catch (e) {
      if (isTrap(e)) traps++;
      problems = [`${isTrap(e) ? 'TRAP' : 'ERROR'} ${e.message}`];
    }
    if (problems.length === 0) {
      console.log(`ok   ${kase.id}`);
    } else {
      failed++;
      console.log(`FAIL ${kase.id}: ${problems.join('; ')}`);
    }
  }
  const missing = doc.cases.filter((k) => !ran.has(k.id)).length;
  if (answersDir) {
    mkdirSync(answersDir, { recursive: true });
    for (const [name, list] of Object.entries(answers)) writeFileSync(join(answersDir, `${name}.jsonl`), list.map((l) => `${l}\n`).join(''));
  }
  console.log(
    `summary: ${doc.cases.length} cases, ${doc.cases.length - failed} passed, ${failed} failed, ${traps} traps, ` +
      `${unexpected.size} unexpected imports called${unexpected.size ? ` (${[...unexpected].join(', ')})` : ''}, ${missing} not run`,
  );
  process.exit(failed || traps || unexpected.size || missing ? 1 : 0);
}

function modeCalls(modulePath, callsPath, referencePath) {
  const module = loadModule(modulePath);
  requireOnlyRandomGet(module);
  const reference = new Map();
  if (referencePath) {
    for (const line of readFileSync(referencePath, 'utf8').split('\n')) {
      if (line.trim()) {
        const r = JSON.parse(line);
        reference.set(r.id, r);
      }
    }
  }
  const pool = new Map();
  const unexpected = new Set();
  let rows = 0;
  let traps = 0;
  let differ = 0;
  const lines = [];
  for (const line of readFileSync(callsPath, 'utf8').split('\n')) {
    if (!line.trim()) continue;
    const r = JSON.parse(line);
    rows++;
    let o;
    if (r.map !== undefined) {
      o = { id: r.id, map: r.map };
    } else {
      let g = pool.get(r.config);
      let initAnswer = '';
      if (!g) {
        g = new Guest(module);
        initAnswer = g.call('init', bytesOf(r.config));
        if (initAnswer === '{"ok":true}') pool.set(r.config, g);
      }
      if (initAnswer !== '' && initAnswer !== '{"ok":true}') {
        o = { id: r.id, out: initAnswer }; // init refused the config: that is the row's answer
      } else {
        const input = new Uint8Array(Buffer.from(r.b64, 'base64'));
        const now = r.now === null || r.now === undefined ? BigInt(Date.now()) : BigInt(r.now);
        try {
          const out =
            r.fn === 'verify-receipt'
              ? g.call('verify-receipt', now, input)
              : r.fn === 'verify-signed-data'
                ? g.call('verify-signed-data', now, input)
                : g.call('verify-receipt-endpoint', r.env, now, input);
          o = { id: r.id, out };
        } catch (e) {
          if (!isTrap(e)) throw e;
          traps++;
          g.unexpectedCalls.forEach((c) => unexpected.add(c));
          pool.delete(r.config); // a trap discards the instance
          o = { id: r.id, trap: e.message };
        }
      }
    }
    if (referencePath) {
      const ref = reference.get(r.id);
      if (!ref || ref.out !== o.out || ref.trap !== o.trap || stringify(ref.map) !== stringify(o.map)) {
        differ++;
        if (differ <= 20) console.error(`differs: ${r.id}`);
      }
    }
    lines.push(JSON.stringify(o));
  }
  process.stdout.write(lines.map((l) => `${l}\n`).join(''));
  const summary = { host: `node ${process.version} (trap host)`, rows, traps, unexpected_imports: [...unexpected], instances_left: pool.size };
  if (referencePath) summary.differ = differ;
  console.error(JSON.stringify(summary));
  process.exit(traps || unexpected.size || differ ? 1 : 0);
}

function modeAbiTests(modulePath, casesPath) {
  const module = loadModule(modulePath);
  requireOnlyRandomGet(module);
  const { fixture } = loadCases(casesPath);
  let failed = 0;
  const check = (name, ok, detail = '') => {
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail ? `: ${detail}` : ''}`);
  };
  const attempt = (f) => {
    try {
      return { out: f() };
    } catch (e) {
      return { trap: isTrap(e), error: e };
    }
  };
  const show = (r) => (r.error ? `${r.trap ? 'trap' : 'error'}: ${String(r.error.message).split('\n')[0]}` : String(r.out).slice(0, 100));
  const now = () => BigInt(Date.now());
  const DEFAULTS = bytesOf('{"roots":[]}');
  const g5 = bytesOf(receiptText(fixture('public-receipt-sandbox-g5')));
  const jws = fixture('transaction').bytes;
  const jwsConfig = bytesOf(JSON.stringify({ roots: [Buffer.from(fixture('jws-root').bytes).toString('base64')] }));
  const request = bytesOf(JSON.stringify({ 'receipt-data': receiptText(fixture('public-receipt-sandbox-g5')) }));
  const fresh = (config = DEFAULTS, hooks) => {
    const g = new Guest(module, hooks);
    const answer = g.call('init', config);
    if (answer !== '{"ok":true}') throw new Error(`init: ${answer}`);
    return g;
  };
  const verifies = (g) => {
    const r = attempt(() => g.call('verify-receipt', now(), g5));
    return !r.error && JSON.parse(r.out).verified === true;
  };

  let g = new Guest(module);
  let r = attempt(() => g.call('init', DEFAULTS));
  check('init with no roots of its own answers {"ok":true}', r.out === '{"ok":true}', show(r));
  g = fresh();
  check('verify-receipt(genuine g5) verifies', verifies(g));
  r = attempt(() => fresh(jwsConfig).call('verify-signed-data', now(), jws));
  check('verify-signed-data(shared JWS, init with its own root) verifies', !r.error && JSON.parse(r.out).verified === true, show(r));
  r = attempt(() => g.call('verify-receipt-endpoint', 1, now(), request));
  check('endpoint env 1 (sandbox) answers status 0 for the sandbox g5', !r.error && JSON.parse(r.out).status === 0, show(r));
  r = attempt(() => g.call('verify-receipt-endpoint', 0, now(), request));
  check('endpoint env 0 (production) answers status 21007 for the sandbox g5', !r.error && JSON.parse(r.out).status === 21007, show(r));
  r = attempt(() => g.call('verify-receipt', now(), new Uint8Array(0)));
  check('empty input is a verification failure value, not a trap', !r.error && JSON.parse(r.out).verified === false, show(r));
  // Three segments, so the guest's UTF-8 check is what refuses it (`eyJ\xff.eyJ9.c2ln`).
  r = attempt(() => g.call('verify-signed-data', now(), new Uint8Array([0x65, 0x79, 0x4a, 0xff, 0x2e, 0x65, 0x79, 0x4a, 0x39, 0x2e, 0x63, 0x32, 0x6c, 0x6e])));
  check('a JWS that is not UTF-8 reaches the guest and is a value', !r.error && JSON.parse(r.out).verified === false, show(r));

  g = new Guest(module);
  r = attempt(() => g.call('verify-receipt', now(), g5));
  check('verify before init traps', r.trap === true, show(r));
  g = fresh();
  r = attempt(() => g.call('init', DEFAULTS));
  check('a second init traps', r.trap === true, show(r));
  g = new Guest(module);
  r = attempt(() => g.call('init', bytesOf('{"roots":["bm90IGEgY2VydGlmaWNhdGU="]}')));
  const retry = attempt(() => g.call('init', DEFAULTS));
  check('a root that does not parse is {"ok":false}, and init can be retried', !r.error && JSON.parse(r.out).ok === false && retry.out === '{"ok":true}' && verifies(g), `${show(r)}; retry: ${show(retry)}`);
  g = new Guest(module);
  r = attempt(() => g.call('init', bytesOf('{not json')));
  check('a configuration that is not JSON is {"ok":false}', !r.error && JSON.parse(r.out).ok === false, show(r));

  for (const env of [2, 255, 0xffffffff]) {
    r = attempt(() => fresh().call('verify-receipt-endpoint', env, now(), request));
    check(`endpoint with env ${env} traps`, r.trap === true, show(r));
  }

  let wrong = fresh(jwsConfig, { randomTrim: 1 });
  r = attempt(() => wrong.call('verify-signed-data', now(), jws));
  check('random-get answering one byte short traps', r.trap === true && wrong.randomCalls > 0, `random-get calls: ${wrong.randomCalls}; ${show(r)}`);
  wrong = fresh(jwsConfig);
  attempt(() => wrong.call('verify-signed-data', now(), jws));
  console.log(`INFO random-get calls for one ES256 JWS verification: ${wrong.randomCalls}`);

  const a = fresh();
  const b = fresh();
  const before = verifies(b);
  r = attempt(() => a.call('verify-receipt-endpoint', 2, now(), request));
  check('isolation: a trap in one instance leaves another verifying', r.trap === true && before && verifies(b) && verifies(b), show(r));

  g = fresh();
  for (let i = 0; i < 200; i++) g.call('verify-receipt', now(), g5);
  const m1 = g.memory.buffer.byteLength;
  const t = performance.now();
  let ok = true;
  for (let i = 0; i < 2000; i++) ok = JSON.parse(g.call('verify-receipt', now(), g5)).verified === true && ok;
  const m2 = g.memory.buffer.byteLength;
  check('2,000 more calls leave linear memory the same size', m1 === m2 && ok, `${m1} -> ${m2} bytes; ${((performance.now() - t) / 2000).toFixed(2)} ms per call`);

  console.log(`summary: ${failed} failed`);
  process.exit(failed ? 1 : 0);
}

// --- main ----------------------------------------------------------------------

function usage() {
  console.error(
    'usage: node tools/wasm-trap-host.mjs imports <module.wasm>\n' +
      '       node tools/wasm-trap-host.mjs cases <module.wasm> <cases.json> [--answers <dir>]\n' +
      '       node tools/wasm-trap-host.mjs calls <module.wasm> <calls.jsonl> [--reference <rows.jsonl>]\n' +
      '       node tools/wasm-trap-host.mjs abi-tests <module.wasm> <cases.json>',
  );
  process.exit(2);
}

const [mode, ...rest] = process.argv.slice(2);
const opts = {};
const pos = [];
for (let i = 0; i < rest.length; i++) {
  if (rest[i] === '--answers' || rest[i] === '--reference') opts[rest[i].slice(2)] = rest[++i] ?? usage();
  else if (rest[i].startsWith('--')) usage();
  else pos.push(rest[i]);
}
if (mode === 'imports' && pos.length === 1) modeImports(pos[0]);
else if (mode === 'cases' && pos.length === 2) modeCases(pos[0], pos[1], opts.answers);
else if (mode === 'calls' && pos.length === 2) modeCalls(pos[0], pos[1], opts.reference);
else if (mode === 'abi-tests' && pos.length === 2) modeAbiTests(pos[0], pos[1]);
else usage();
