// Spike only. Smoke test for an installed prototype package, runtime-
// agnostic: the caller passes the package's exports and the vectors
// (npm/make-vectors.mjs). Returns a report; ok only if every check holds.
export function smoke(pkg, v) {
  const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const checks = [];
  const t0 = performance.now();
  const expectReason = (name, fn, reason) => {
    try { fn(); checks.push([name, false, 'no error']); } catch (e) {
      checks.push([name, e instanceof pkg.VerificationError && e.reason === reason, e.reason || String(e)]);
    }
  };
  const r = pkg.verifyReceipt(v.receiptB64, { bundleId: 'dev.bonzer.weeka.app' });
  const rs = JSON.stringify(r);
  checks.push(['genuine g5 receipt (base64, pinned Apple roots)', rs.includes('dev.bonzer.weeka.app'), rs.slice(0, 80)]);
  const firstMs = performance.now() - t0;
  const r2 = pkg.verifyReceipt(b64(v.receiptB64), { bundleId: 'dev.bonzer.weeka.app' });
  checks.push(['same receipt as DER bytes', JSON.stringify(r2) === rs, '']);
  expectReason('wrong bundle id', () => pkg.verifyReceipt(v.receiptB64, { bundleId: 'com.example.other' }), 'WRONG_BUNDLE_ID');
  const roots = [b64(v.jwsRootB64)];
  const t = pkg.verifyTransaction(v.jws, { bundleId: 'com.example.app', environments: ['Sandbox'], trustedRoots: roots });
  checks.push(['generated transaction JWS', JSON.stringify(t).includes('com.example.app.pro'), JSON.stringify(t).slice(0, 80)]);
  expectReason('JWS outside accepted environments', () => pkg.verifyTransaction(v.jws, { bundleId: 'com.example.app', environments: ['Production'], trustedRoots: roots }), 'WRONG_ENVIRONMENT');
  expectReason('JWS against Apple roots (untrusted chain)', () => pkg.verifyTransaction(v.jws, { bundleId: 'com.example.app', environments: ['Sandbox'] }), 'INVALID_CHAIN');
  return { ok: checks.every((c) => c[1]), firstCallMs: Math.round(firstMs * 10) / 10, checks };
}
