// Runtime-portability smoke for the WEB entry point: the checks every
// WebCrypto-only runtime must pass. Pure — no filesystem, no node:*, no
// Buffer — so the same module runs inside a Cloudflare Worker with no
// compatibility flags and inside the Vercel Edge runtime's isolate.
// Fixture bytes come in from the runner.
import {
  JwsVerifier,
  ReceiptVerifier,
  VerificationError,
  appleReceiptRoots,
} from '../dist/web/index.js';

const BUNDLE = 'com.example.app';

async function reasonOf(work) {
  try {
    await work();
    return 'none';
  } catch (error) {
    if (!(error instanceof VerificationError)) {
      throw error;
    }
    return error.reason;
  }
}

/**
 * @param {{ appleRootDer: Uint8Array, sandboxReceiptB64: string,
 *           legacyReceiptB64: string, jwsRootDer: Uint8Array,
 *           transactionJws: string, foreignReceiptDer: Uint8Array }} fx
 * @returns {Promise<string[]>} one line per passed check
 */
export async function run(fx) {
  const out = [];

  // appleReceiptRoots() must not touch the filesystem: the roots are
  // inlined at build time so a bundled runtime can call it.
  const builtin = new ReceiptVerifier({
    trustedRoots: appleReceiptRoots(),
    bundleId: 'dev.bonzer.weeka.app',
  });
  if ((await builtin.verify(fx.sandboxReceiptB64.trim())).receiptType !== 'ProductionSandbox') {
    throw new Error('builtin roots did not verify the genuine receipt');
  }
  out.push('appleReceiptRoots() works without a filesystem');

  const receipts = new ReceiptVerifier({
    trustedRoots: [fx.appleRootDer],
    bundleId: 'dev.bonzer.weeka.app',
  });
  const receipt = await receipts.verify(fx.sandboxReceiptB64.trim());
  if (receipt.receiptType !== 'ProductionSandbox') {
    throw new Error(`receiptType ${receipt.receiptType}`);
  }
  out.push('genuine sandbox receipt verifies against the real Apple root');

  // The legacy receipt is the SHA-1 check: its CMS signature is RSA over a
  // SHA-1 digest and its whole certificate chain is signed sha1WithRSA, so
  // a runtime that refuses SHA-1 for RSASSA-PKCS1-v1_5 fails here and only
  // here.
  const legacy = new ReceiptVerifier({
    trustedRoots: appleReceiptRoots(),
    bundleId: 'com.nutcall.alert',
  });
  const purchases = (await legacy.verify(fx.legacyReceiptB64.trim())).inAppPurchases.length;
  if (purchases !== 187) {
    throw new Error(`legacy receipt has ${purchases} purchases, expected 187`);
  }
  out.push('genuine legacy receipt verifies (SHA-1 RSA chain and signature, 187 purchases)');

  const jws = new JwsVerifier({
    trustedRoots: [fx.jwsRootDer],
    bundleId: BUNDLE,
    acceptedEnvironments: ['Sandbox'],
  });
  const transaction = fx.transactionJws.trim();
  const tx = await jws.verifyTransaction(transaction);
  if (tx.transactionId !== '2000000000000001') {
    throw new Error(`transactionId ${tx.transactionId}`);
  }
  out.push('shared JWS transaction fixture verifies');

  const foreign = await reasonOf(() => receipts.verify(fx.foreignReceiptDer));
  if (foreign !== 'INVALID_CHAIN') {
    throw new Error(`foreign receipt reason ${foreign}`);
  }
  out.push('foreign receipt fails with INVALID_CHAIN');

  // Last character of the signature segment changed: same length, different
  // signature bytes. A runtime whose verify() returned true regardless would
  // pass every check above and fail only this one.
  const flipped = transaction.slice(0, -1) + (transaction.endsWith('A') ? 'B' : 'A');
  const tampered = await reasonOf(() => jws.verifyTransaction(flipped));
  if (tampered !== 'INVALID_SIGNATURE') {
    throw new Error(`tampered JWS reason ${tampered}`);
  }
  out.push('tampered JWS signature fails with INVALID_SIGNATURE');

  return out;
}
