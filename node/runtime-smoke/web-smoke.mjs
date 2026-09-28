// Runtime-portability smoke for the WEB entry point: the checks every
// WebCrypto-only runtime must pass. Pure — no filesystem, no node:*, no
// Buffer — so the same module runs inside a Cloudflare Worker with no
// compatibility flags and inside the Vercel Edge runtime's isolate.
// Fixture bytes come in from the runner.
import { createConfig, createVerifier, defaultConfig, Environment } from '../dist/web/index.js';

// No Buffer here (web-portability.test.js enforces it): a small standard
// base64 encoder for the one place this smoke needs to turn DER back into
// the string form verifyReceipt takes.
const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function base64Encode(bytes) {
  let out = '';
  let i = 0;
  for (; i + 3 <= bytes.length; i += 3) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
    out +=
      BASE64_ALPHABET[(chunk >> 18) & 0x3f] +
      BASE64_ALPHABET[(chunk >> 12) & 0x3f] +
      BASE64_ALPHABET[(chunk >> 6) & 0x3f] +
      BASE64_ALPHABET[chunk & 0x3f];
  }
  const left = bytes.length - i;
  if (left === 1) {
    const chunk = bytes[i] << 16;
    out += BASE64_ALPHABET[(chunk >> 18) & 0x3f] + BASE64_ALPHABET[(chunk >> 12) & 0x3f] + '==';
  } else if (left === 2) {
    const chunk = (bytes[i] << 16) | (bytes[i + 1] << 8);
    out +=
      BASE64_ALPHABET[(chunk >> 18) & 0x3f] +
      BASE64_ALPHABET[(chunk >> 12) & 0x3f] +
      BASE64_ALPHABET[(chunk >> 6) & 0x3f] +
      '=';
  }
  return out;
}

/**
 * @param {{ appleRootDer: Uint8Array, sandboxReceiptB64: string,
 *           legacyReceiptB64: string, jwsRootDer: Uint8Array,
 *           transactionJws: string, foreignReceiptDer: Uint8Array }} fx
 * @returns {Promise<string[]>} one line per passed check
 */
export async function run(fx) {
  const out = [];

  // defaultConfig() must not touch the filesystem: the roots are inlined
  // at build time so a bundled runtime can call it.
  const builtin = createVerifier(await defaultConfig());
  const builtinResult = await builtin.verifyReceipt(fx.sandboxReceiptB64.trim());
  if (!builtinResult.verified || builtinResult.payload.receiptType !== 'ProductionSandbox') {
    throw new Error('the bundled roots did not verify the genuine receipt');
  }
  out.push('defaultConfig() works without a filesystem');

  const receipts = createVerifier(await createConfig({ roots: [fx.appleRootDer] }));
  const receiptResult = await receipts.verifyReceipt(fx.sandboxReceiptB64.trim());
  if (!receiptResult.verified || receiptResult.payload.receiptType !== 'ProductionSandbox') {
    throw new Error(`receiptType ${receiptResult.payload?.receiptType}`);
  }
  out.push('genuine sandbox receipt verifies against the real Apple root');

  // The endpoint renders its GMT and Pacific dates itself, since Fastly
  // Compute has no Intl; this is the check that a status-0 body renders on
  // every runtime, the Pacific daylight-saving offset included.
  const fixedInstant = new Date('2025-06-15T12:34:56Z');
  const endpoint = createVerifier(
    await createConfig({ roots: [fx.appleRootDer], clock: () => fixedInstant.getTime() }),
  );
  const sandboxJson = await endpoint.verifyReceiptEndpoint(
    Environment.SANDBOX,
    JSON.stringify({ 'receipt-data': fx.sandboxReceiptB64.trim() }),
  );
  if (
    !sandboxJson.startsWith('{"status":0') ||
    !sandboxJson.includes('2025-06-15 05:34:56 America/Los_Angeles')
  ) {
    throw new Error(`endpoint rendered ${sandboxJson.slice(0, 200)}`);
  }
  out.push('verifyReceiptEndpoint answers 0, then renders the Sandbox body');

  // The legacy receipt is the SHA-1 check: its CMS signature is RSA over a
  // SHA-1 digest and its whole certificate chain is signed sha1WithRSA, so
  // a runtime that refuses SHA-1 for RSASSA-PKCS1-v1_5 fails here and only
  // here.
  const legacy = createVerifier(await defaultConfig());
  const legacyResult = await legacy.verifyReceipt(fx.legacyReceiptB64.trim());
  if (!legacyResult.verified) {
    throw new Error(`legacy receipt failed: ${legacyResult.failure.reason}`);
  }
  const purchases = legacyResult.payload.inApp.length;
  if (purchases !== 187) {
    throw new Error(`legacy receipt has ${purchases} purchases, expected 187`);
  }
  out.push('genuine legacy receipt verifies (SHA-1 RSA chain and signature, 187 purchases)');

  const jws = createVerifier(await createConfig({ roots: [fx.jwsRootDer] }));
  const transaction = fx.transactionJws.trim();
  const tx = await jws.verifySignedData(transaction);
  if (!tx.verified) {
    throw new Error(`shared JWS transaction fixture failed: ${tx.failure.reason}`);
  }
  const claims = JSON.parse(tx.payload.json);
  if (claims.transactionId !== '2000000000000001') {
    throw new Error(`transactionId ${claims.transactionId}`);
  }
  out.push('shared JWS transaction fixture verifies');

  const foreign = await receipts.verifyReceipt(base64Encode(fx.foreignReceiptDer));
  if (foreign.verified || foreign.failure.reason !== 'UNTRUSTED_CHAIN') {
    throw new Error(`foreign receipt reason ${foreign.verified ? 'none' : foreign.failure.reason}`);
  }
  out.push('foreign receipt fails with UNTRUSTED_CHAIN');

  // Last character of the signature segment changed: same length, different
  // signature bytes. A runtime whose verify() returned true regardless would
  // pass every check above and fail only this one.
  const flipped = transaction.slice(0, -1) + (transaction.endsWith('A') ? 'B' : 'A');
  const tampered = await jws.verifySignedData(flipped);
  if (tampered.verified || tampered.failure.reason !== 'INVALID_SIGNATURE') {
    throw new Error(`tampered JWS reason ${tampered.verified ? 'none' : tampered.failure.reason}`);
  }
  out.push('tampered JWS signature fails with INVALID_SIGNATURE');

  return out;
}
