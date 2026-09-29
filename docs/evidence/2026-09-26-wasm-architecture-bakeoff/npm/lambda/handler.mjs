// Spike only: a Lambda-style handler over an installed prototype package.
// Event: { kind: "receipt"|"transaction", pkg, ... }. No filesystem use
// beyond the package's own .wasm, no child process, no native addon.
const PKG = process.env.APRV_PKG || 'aprv-spike-core';
const pkg = await import(PKG);   // cold init happens here, once per environment
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
export async function handler(event) {
  try {
    const out = event.kind === 'receipt'
      ? pkg.verifyReceipt(event.receiptB64, { bundleId: event.bundleId })
      : pkg.verifyTransaction(event.jws, { bundleId: event.bundleId, environments: event.environments,
          trustedRoots: event.rootB64 ? [b64(event.rootB64)] : undefined });
    return { statusCode: 200, body: JSON.stringify(out) };
  } catch (e) {
    if (e instanceof pkg.VerificationError) return { statusCode: 422, body: JSON.stringify({ reason: e.reason }) };
    throw e;
  }
}
