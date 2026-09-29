// Spike only (follow-up): the Route D facade for a component that imports
// WASI 0.2 (the OpenSSL component, built through the p1->p2 adapter). Same
// typed calls as the AWS-LC package's facade.js; the only difference is
// the extra import object, which comes from wasi-p2-min.mjs (clocks,
// random from crypto.getRandomValues, a stderr that drops bytes).
import { wasiP2Min } from './wasi-p2-min.mjs';
const CODES = { 'invalid-jws-format': 1, 'invalid-certificate': 2, 'invalid-certificate-purpose': 3,
  'invalid-chain': 4, 'invalid-signature': 5, 'wrong-bundle-id': 6, 'wrong-environment': 7,
  'wrong-app-apple-id': 8, 'invalid-receipt-format': 9, 'device-hash-mismatch': 10, 'internal-error': 12 };
const ENV = { Production: 'production', Sandbox: 'sandbox', Xcode: 'xcode', LocalTesting: 'local-testing' };

export class VerificationError extends Error {
  constructor(reason, detail) {
    super(detail || reason);
    this.name = 'VerificationError';
    this.reason = reason.toUpperCase().replaceAll('-', '_');
    this.code = CODES[reason] ?? 102;
  }
}

function unwrap(fn) {
  try { return fn(); } catch (e) {
    const p = e && e.payload;
    if (p && p.tag === 'verification') throw new VerificationError(p.val.reason, p.val.message);
    if (p && p.tag === 'configuration') throw new VerificationError('configuration', p.val);
    throw e;
  }
}

export async function makeComponentApi(instantiate, getCoreModule) {
  const root = await instantiate(getCoreModule, { ...wasiP2Min(), 'aprv:verifier/types@0.1.0': {} });
  const V = root.verifier;
  return {
    VerificationError,
    verifyReceipt(receipt, { bundleId, trustedRoots } = {}) {
      return unwrap(() => {
        const v = V.ReceiptVerifier.create(bundleId, trustedRoots);
        try {
          return JSON.parse(typeof receipt === 'string' ? v.verifyBase64(receipt, undefined) : v.verify(receipt, undefined));
        } finally { v[Symbol.dispose]?.(); }
      });
    },
    verifyTransaction(jws, { bundleId, environments = ['Production'], appAppleId, trustedRoots } = {}) {
      return unwrap(() => {
        const v = V.JwsVerifier.create(bundleId, environments.map((e) => ENV[e]), appAppleId, trustedRoots);
        try { return JSON.parse(v.verifyTransaction(jws)); } finally { v[Symbol.dispose]?.(); }
      });
    },
  };
}
