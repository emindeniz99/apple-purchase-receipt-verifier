// Spike only: the package façade over the C ABI inside the wasm (Route C
// core module or Emscripten build). It converts arguments, calls one aprv_*
// function, converts the result. No parsing, crypto or policy.
// api = { fn(name) -> function, buffer() -> ArrayBuffer }.
const REASONS = ['OK', 'INVALID_JWS_FORMAT', 'INVALID_CERTIFICATE', 'INVALID_CERTIFICATE_PURPOSE',
  'INVALID_CHAIN', 'INVALID_SIGNATURE', 'WRONG_BUNDLE_ID', 'WRONG_ENVIRONMENT', 'WRONG_APP_APPLE_ID',
  'INVALID_RECEIPT_FORMAT', 'DEVICE_HASH_MISMATCH', 'RETIRED_11', 'INTERNAL_ERROR'];
const ENV_BITS = { Production: 1, Sandbox: 2, Xcode: 4, LocalTesting: 8 };
const enc = new TextEncoder();
const dec = new TextDecoder();

export class VerificationError extends Error {
  constructor(code, detail) {
    super(detail || REASONS[code] || `status ${code}`);
    this.name = 'VerificationError';
    this.code = code;
    this.reason = REASONS[code] || `STATUS_${code}`;
  }
}

export function makeVerifierApi(instantiate) {
  let api = null;
  const ready = () => api || (api = instantiate());
  // A trap leaves the instance unusable: drop it, rebuild on next call,
  // and report INTERNAL_ERROR (ARCHITECTURE.md section 5).
  function guarded(body) {
    const a = ready();
    try { return body(a); } catch (e) {
      if (e instanceof VerificationError) throw e;
      api = null;
      throw new VerificationError(12, 'wasm trap: ' + (e && e.message));
    }
  }
  function call(a, fn) {
    const held = [];
    const f = (n) => a.fn(n);
    const alloc = (n) => { const p = f('aprv_alloc')(Math.max(n, 1)); held.push([p, Math.max(n, 1)]); return p; };
    const put = (bytes, nul) => { const p = alloc(bytes.length + (nul ? 1 : 0)); const m = new Uint8Array(a.buffer()); m.set(bytes, p); if (nul) m[p + bytes.length] = 0; return p; };
    const take = (p) => { if (!p) return null; const m = new Uint8Array(a.buffer()); let e = p; while (m[e]) e++; const s = dec.decode(m.subarray(p, e)); f('aprv_string_free')(p); return s; };
    const roots = (list) => {
      if (!list) return [0, 0, 0];
      const d = alloc(4 * Math.max(list.length, 1)); const l = alloc(4 * Math.max(list.length, 1));
      list.forEach((b, i) => { const v = new DataView(a.buffer()); v.setUint32(d + 4 * i, put(b), true); v.setUint32(l + 4 * i, b.length, true); });
      return [d, l, list.length];
    };
    try { return fn({ f, alloc, put, take, roots, view: () => new DataView(a.buffer()) }); } finally {
      for (const [p, n] of held) f('aprv_dealloc')(p, n);
    }
  }
  function result(c, handle, invoke, free) {
    const res = c.alloc(8);
    const v = c.view(); v.setUint32(res, 0, true); v.setUint32(res + 4, 0, true);
    try { invoke(res); } finally { c.f(free)(handle); }
    const code = c.view().getInt32(res, true);
    const text = c.take(c.view().getUint32(res + 4, true));
    if (code !== 0) {
      let detail = text;
      try { detail = JSON.parse(text).message ?? text; } catch { /* plain text */ }
      throw new VerificationError(code, detail);
    }
    return JSON.parse(text);
  }
  return {
    VerificationError,
    /** receipt: Uint8Array (DER) or base64 string. roots: Uint8Array[] (DER) or undefined for Apple's. */
    verifyReceipt(receipt, { bundleId, trustedRoots } = {}) {
      return guarded((a) => call(a, (c) => {
        const [d, l, n] = c.roots(trustedRoots);
        const b = c.put(enc.encode(bundleId), true);
        const h = trustedRoots ? c.f('aprv_verifier_new_receipt_with_roots')(b, d, l, n) : c.f('aprv_verifier_new_receipt')(b);
        if (!h) throw new VerificationError(102, 'receipt verifier refused its configuration');
        return result(c, h, (res) => typeof receipt === 'string'
          ? c.f('aprv_verify_receipt_base64')(h, c.put(enc.encode(receipt), true), res)
          : c.f('aprv_verify_receipt_der')(h, c.put(receipt), receipt.length, res), 'aprv_verifier_free_receipt');
      }));
    },
    verifyTransaction(jws, { bundleId, environments = ['Production'], appAppleId = 0n, trustedRoots } = {}) {
      return guarded((a) => call(a, (c) => {
        const [d, l, n] = c.roots(trustedRoots);
        const mask = environments.reduce((m, e) => m | ENV_BITS[e], 0);
        const b = c.put(enc.encode(bundleId), true);
        const h = trustedRoots ? c.f('aprv_verifier_new_jws_with_roots')(b, mask, BigInt(appAppleId), d, l, n)
          : c.f('aprv_verifier_new_jws')(b, mask, BigInt(appAppleId));
        if (!h) throw new VerificationError(102, 'JWS verifier refused its configuration');
        return result(c, h, (res) => c.f('aprv_verify_transaction')(h, c.put(enc.encode(jws), true), res), 'aprv_verifier_free_jws');
      }));
    },
  };
}
