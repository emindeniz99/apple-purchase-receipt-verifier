// Runtime-portability smoke: the same checks every non-Node JavaScript
// runtime must pass (Bun, Deno, Cloudflare workerd). Pure: no filesystem
// access, so the same module runs where `node:fs` does not exist. Fixture
// bytes come in from the runner (node-like.mjs reads files, worker.mjs gets
// them embedded by workerd.capnp).
import { createConfig, createVerifier, defaultConfig } from '../dist/index.js';

/**
 * @param {{ appleRootDer: Uint8Array, sandboxReceiptB64: string,
 *           jwsRootDer: Uint8Array, transactionJws: string,
 *           foreignReceiptDer: Uint8Array }} fx
 * @returns {string[]} one line per passed check
 */
export function run(fx) {
  const out = [];

  // defaultConfig() must not touch the filesystem: the roots are inlined
  // at build time so a bundled runtime can call it.
  const builtin = createVerifier(defaultConfig());
  const builtinResult = builtin.verifyReceipt(fx.sandboxReceiptB64.trim());
  if (!builtinResult.verified || builtinResult.payload.receiptType !== 'ProductionSandbox') {
    throw new Error('the bundled roots did not verify the genuine receipt');
  }
  out.push('defaultConfig() works without a filesystem');

  const receipts = createVerifier(createConfig({ roots: [fx.appleRootDer] }));
  const receiptResult = receipts.verifyReceipt(fx.sandboxReceiptB64.trim());
  if (!receiptResult.verified || receiptResult.payload.receiptType !== 'ProductionSandbox') {
    throw new Error(`receiptType ${receiptResult.payload?.receiptType}`);
  }
  out.push('genuine sandbox receipt verifies against the real Apple root');

  const jws = createVerifier(createConfig({ roots: [fx.jwsRootDer] }));
  const tx = jws.verifySignedData(fx.transactionJws.trim());
  if (!tx.verified) {
    throw new Error(`shared JWS transaction fixture failed: ${tx.failure.reason}`);
  }
  const claims = JSON.parse(tx.payload.json);
  if (claims.transactionId !== '2000000000000001') {
    throw new Error(`transactionId ${claims.transactionId}`);
  }
  out.push('shared JWS transaction fixture verifies');

  const foreign = receipts.verifyReceipt(fx.foreignReceiptDer.toString('base64'));
  if (foreign.verified || foreign.failure.reason !== 'UNTRUSTED_CHAIN') {
    throw new Error(`foreign receipt reason ${foreign.verified ? 'none' : foreign.failure.reason}`);
  }
  out.push('foreign receipt fails with UNTRUSTED_CHAIN');

  return out;
}
