// Runtime-portability smoke: the same three checks every non-Node JavaScript
// runtime must pass (Bun, Deno, Cloudflare workerd). Pure: no filesystem
// access, so the same module runs where `node:fs` does not exist. Fixture
// bytes come in from the runner (node-like.mjs reads files, worker.mjs gets
// them embedded by workerd.capnp).
import {
  JwsVerifier,
  ReceiptVerifier,
  VerificationError,
  appleReceiptRoots,
} from '../dist/index.js';

const BUNDLE = 'com.example.app';

/**
 * @param {{ appleRootDer: Uint8Array, sandboxReceiptB64: string,
 *           jwsRootDer: Uint8Array, transactionJws: string,
 *           foreignReceiptDer: Uint8Array }} fx
 * @returns {string[]} one line per passed check
 */
export function run(fx) {
  const out = [];

  // appleReceiptRoots() must not touch the filesystem: the roots are
  // inlined at build time so a bundled runtime can call it.
  const builtin = new ReceiptVerifier({
    trustedRoots: appleReceiptRoots(),
    bundleId: 'dev.bonzer.weeka.app',
  });
  if (builtin.verify(fx.sandboxReceiptB64.trim()).receiptType !== 'ProductionSandbox') {
    throw new Error('builtin roots did not verify the genuine receipt');
  }
  out.push('appleReceiptRoots() works without a filesystem');

  const receipts = new ReceiptVerifier({
    trustedRoots: [fx.appleRootDer],
    bundleId: 'dev.bonzer.weeka.app',
  });
  const receipt = receipts.verify(fx.sandboxReceiptB64.trim());
  if (receipt.receiptType !== 'ProductionSandbox')
    throw new Error(`receiptType ${receipt.receiptType}`);
  out.push('genuine sandbox receipt verifies against the real Apple root');

  const jws = new JwsVerifier({
    trustedRoots: [fx.jwsRootDer],
    bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'],
  });
  const tx = jws.verifyTransaction(fx.transactionJws.trim());
  if (tx.transactionId !== '2000000000000001') throw new Error(`transactionId ${tx.transactionId}`);
  out.push('shared JWS transaction fixture verifies');

  let reason = 'none';
  try {
    receipts.verify(fx.foreignReceiptDer);
  } catch (e) {
    if (!(e instanceof VerificationError)) throw e;
    reason = e.reason;
  }
  if (reason !== 'INVALID_CHAIN') throw new Error(`foreign receipt reason ${reason}`);
  out.push('foreign receipt fails with INVALID_CHAIN');

  return out;
}
