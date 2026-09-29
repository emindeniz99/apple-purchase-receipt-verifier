// Spike only. Runs request-corpus rows through the jco-transpiled APRV
// COMPONENT (component/wit/aprv.wit): typed WIT calls, no pointer, length
// or free function in sight. Produces the same {id, code, json} rows as
// driver.mjs so py/same.py compares them with the native C ABI.
//
// The component's typed errors are mapped back to the C ABI's numbers only
// for that comparison: reason enum -> AprvReason code, a configuration
// error from a constructor -> CTOR_REFUSED.
//
//   const run = await makeJcoRunner(instantiate, getCoreModule, calls);
//   const row = await run.run(requestRow);
//
// instantiate: the `instantiate` export of jco's --instantiation async
// output; getCoreModule(path) -> WebAssembly.Module (or a Promise of one).
import { b64 } from './driver.mjs';

const REASON_CODE = {
  'invalid-jws-format': 1, 'invalid-certificate': 2, 'invalid-certificate-purpose': 3,
  'invalid-chain': 4, 'invalid-signature': 5, 'wrong-bundle-id': 6, 'wrong-environment': 7,
  'wrong-app-apple-id': 8, 'invalid-receipt-format': 9, 'device-hash-mismatch': 10,
  'internal-error': 12,
};
const ENV = { Production: 'production', Sandbox: 'sandbox', Xcode: 'xcode', LocalTesting: 'local-testing' };
// ignoreBOM: true keeps a leading U+FEFF. The default (false) silently
// strips it, which turned hostile/endpoint/bom from 21002 into 0 in the
// first run (TESTED, results/parity.txt): a string-typed boundary puts a
// decode step in the host, and its defaults are part of the semantics.
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function hex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
  return out;
}

// jco wraps a WIT `result` error in ComponentError with the variant in .payload.
function errorRow(id, e) {
  const p = e && e.payload;
  if (p && p.tag === 'verification') return { id, code: REASON_CODE[p.val.reason] ?? -9, json: null };
  if (p && p.tag === 'configuration') {
    const m = /^status (\d+)$/.exec(p.val);
    return m ? { id, code: Number(m[1]), json: null } : { id, code: 'CONFIG', json: null, detail: p.val };
  }
  throw e;
}

export async function makeJcoRunner(instantiate, getCoreModule, calls = {}, extraImports = {}) {
  let root = null;
  let handles = new Map();
  const imports = {
    'clock-now-ms': { default: () => { calls['clock-now-ms'] = (calls['clock-now-ms'] || 0) + 1; return Date.now(); } },
    'aprv:verifier/types@0.1.0': {},
    ...extraImports,
  };
  async function fresh() {
    root = await instantiate(getCoreModule, imports);
    handles = new Map();
  }
  await fresh();

  function handleFor(r, opts) {
    const key = r.kind + '\0' + r.options;
    if (handles.has(key)) return handles.get(key);
    const roots = opts.roots == null ? undefined : opts.roots.map(b64);
    const V = root.verifier;
    let h;
    try {
      if (r.kind === 'receipt') {
        h = opts.bundleId == null ? null : V.ReceiptVerifier.create(opts.bundleId, roots);
      } else if (r.kind === 'jws') {
        const envs = (opts.acceptedEnvironments || []).map((n) => ENV[n]);
        const app = opts.appAppleId ? BigInt(opts.appAppleId) : undefined;
        h = V.JwsVerifier.create(opts.bundleId || 'conformance.unset.bundle.id', envs, app, roots);
      } else {
        const env = ENV[opts.environment];
        h = env === undefined ? null
          : V.Endpoint.create(env, roots, opts.nowMillis == null ? undefined : BigInt(opts.nowMillis));
      }
    } catch (e) {
      if (!(e && e.payload && e.payload.tag === 'configuration')) throw e;
      h = null;
    }
    handles.set(key, h);
    return h;
  }

  function runRow(r) {
    const opts = JSON.parse(r.options);
    const data = b64(r.input);
    const h = handleFor(r, opts);
    if (!h) return { id: r.id, code: 'CTOR_REFUSED', json: null };
    let text = null;
    const needsText = r.kind !== 'receipt' || r.base64;
    if (needsText) {
      if (data.includes(0)) return { id: r.id, code: r.kind === 'endpoint' ? 'NUL_IN_BODY' : 'NUL_IN_INPUT', json: null };
      // A WIT string is UTF-8 by construction; the C ABI answers 101
      // INVALID_UTF8 for these bytes, so the harness does too.
      try { text = utf8.decode(data); } catch { return { id: r.id, code: 101, json: null }; }
    }
    if (r.kind === 'endpoint') return { id: r.id, code: null, json: h.verifyReceiptJson(text) };
    try {
      if (r.kind === 'jws') {
        const out = [() => h.verifyTransaction(text), () => h.verifyAppTransaction(text), () => h.verifyRaw(text)][r.op]();
        return { id: r.id, code: 0, json: out };
      }
      const guid = r.guidHex != null ? hex(r.guidHex) : undefined;
      const out = r.base64 ? h.verifyBase64(text, guid) : h.verify(data, guid);
      return { id: r.id, code: 0, json: out };
    } catch (e) {
      return errorRow(r.id, e);
    }
  }

  return {
    async run(r) {
      try {
        return runRow(r);
      } catch (e) {
        if (!(e instanceof WebAssembly.RuntimeError)) throw e;
        await fresh();
        return { id: r.id, code: 'TRAP', json: null, trap: String(e.message) };
      }
    },
    runSync: runRow,
    calls,
  };
}
