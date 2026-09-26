// Spike only. Runs request-corpus rows through the unchanged C ABI
// (rust/ffi) inside a wasm instance, whatever produced the instance:
// a WASI p1 module, a freestanding core module, or an Emscripten module.
// Same row format as the native runner (run_rust.py, 2026-09-25 spike) and
// the previous bake-off's wasm/run.mjs, from which this is derived, so
// py/tri.py and py/same.py compare the rows unchanged.
//
// Pure ECMAScript: no node:* import, no Buffer, so the SAME file runs in
// Node, Bun, Deno, Chromium and workerd.
//
//   const d = makeDriver(instantiate);   // instantiate(): Promise<api>
//   await d.init();
//   const row = await d.run(requestRow);
//
// api = { fn(name) -> function, buffer() -> ArrayBuffer }.
// A throw from inside wasm (a Rust panic under panic=abort, an
// `unreachable` in C, an Emscripten abort) becomes row code "TRAP"; the
// instance is thrown away and a fresh one serves the next row.

const ENV_BITS = { Production: 1, Sandbox: 2, Xcode: 4, LocalTesting: 8 };
const enc = new TextEncoder();
const dec = new TextDecoder('utf-8', { fatal: false });

export function b64(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function hex(s) {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(2 * i, 2), 16);
  return out;
}

export function makeDriver(instantiate) {
  let api = null;
  let handles = new Map();
  let pending = [];
  const f = (n) => api.fn(n);
  const u8 = () => new Uint8Array(api.buffer());
  const dv = () => new DataView(api.buffer());

  function alloc(len) {
    const p = f('aprv_alloc')(len);
    pending.push([p, len]);
    return p;
  }
  function release() {
    for (const [p, len] of pending) f('aprv_dealloc')(p, len);
    pending = [];
  }
  function put(data, nul = false) {
    const len = Math.max(data.length + (nul ? 1 : 0), 1);
    const p = alloc(len);
    u8().set(data, p);
    if (nul) u8()[p + data.length] = 0;
    return p;
  }
  function take(p) {
    if (!p) return '';
    const m = u8();
    let e = p;
    while (m[e]) e++;
    const s = dec.decode(m.subarray(p, e));
    f('aprv_string_free')(p);
    return s;
  }

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
        h = opts.roots == null ? f('aprv_verifier_new_receipt')(bp)
          : f('aprv_verifier_new_receipt_with_roots')(bp, ders, lens, count);
      }
    } else if (r.kind === 'jws') {
      let mask = 0;
      for (const n of opts.acceptedEnvironments || []) mask |= ENV_BITS[n];
      const app = BigInt(opts.appAppleId || 0);
      const bp = put(bundle, true);
      h = opts.roots == null ? f('aprv_verifier_new_jws')(bp, mask, app)
        : f('aprv_verifier_new_jws_with_roots')(bp, mask, app, ders, lens, count);
    } else {
      const env = ENV_BITS[opts.environment] || 0;
      let clock = 0;
      if (opts.nowMillis != null) {
        clock = alloc(8);
        dv().setBigInt64(clock, BigInt(opts.nowMillis), true);
      }
      h = f('aprv_endpoint_new_with_roots_and_clock')(env, ders, lens, count, clock);
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
      const st = f('aprv_verify_receipt_endpoint_json')(h, put(data, true), out);
      return { id: r.id, code: st === 0 ? null : st, json: take(dv().getUint32(out, true)) };
    }
    const res = alloc(8);
    dv().setUint32(res, 0, true);
    dv().setUint32(res + 4, 0, true);
    if (r.kind === 'jws') {
      if (data.includes(0)) return { id: r.id, code: 'NUL_IN_INPUT', json: null };
      const call = ['aprv_verify_transaction', 'aprv_verify_app_transaction', 'aprv_verify_raw'][r.op];
      f(call)(h, put(data, true), res);
    } else {
      const guid = r.guidHex != null ? hex(r.guidHex) : null;
      if (r.base64) {
        if (data.includes(0)) return { id: r.id, code: 'NUL_IN_INPUT', json: null };
        if (guid) f('aprv_verify_receipt_base64_with_device_guid')(h, put(data, true), put(guid), guid.length, res);
        else f('aprv_verify_receipt_base64')(h, put(data, true), res);
      } else if (guid) {
        f('aprv_verify_receipt_der_with_device_guid')(h, put(data), data.length, put(guid), guid.length, res);
      } else {
        f('aprv_verify_receipt_der')(h, put(data), data.length, res);
      }
    }
    return { id: r.id, code: dv().getInt32(res, true), json: take(dv().getUint32(res + 4, true)) };
  }

  async function fresh() {
    api = await instantiate();
    handles = new Map();
    pending = [];
  }

  return {
    init: fresh,
    api: () => api,
    // One row; a throw from wasm becomes a TRAP row and a new instance.
    async run(r) {
      try {
        const row = runRow(r);
        release();
        return row;
      } catch (e) {
        if (e instanceof TypeError || e instanceof SyntaxError || e instanceof ReferenceError) throw e;
        await fresh();
        return { id: r.id, code: 'TRAP', json: null, trap: String(e && e.message || e) };
      }
    },
    // Synchronous hot loop for timing; no trap handling.
    runSync(r) { const row = runRow(r); release(); return row; },
  };
}

// Parses JSONL text into rows.
export function jsonl(text) {
  return text.split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
}
