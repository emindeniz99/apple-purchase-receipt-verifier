/**
 * `apple-purchase-receipt-verifier/web` — the WebCrypto-only entry point.
 *
 * Same classes, same option names and same `VerificationError` reasons as
 * the default entry point; every verify method returns a Promise, because
 * `crypto.subtle` is async. Porting between the two is adding or removing
 * `await`.
 *
 * It uses nothing but `crypto.subtle`, `TextDecoder` and plain
 * `Uint8Array`s — no `node:*`, no `Buffer`, no filesystem — so it runs on
 * Node, Bun, Deno, Cloudflare Workers with or without `nodejs_compat`, the
 * Vercel Edge runtime and other WebCrypto-only isolates.
 */
export {
  JwsVerifier, isTransactionActiveAt,
  type JwsVerifierOptions, type TransactionPayload, type AppTransactionPayload, type Claims,
  type Clock,
} from './jws.js';
export {
  ReceiptVerifier, verifyReceiptCore,
  type ReceiptVerifierOptions, type AppReceipt, type InAppPurchase,
} from './receipt.js';
export { VerificationError, Reason, Environment } from '../errors.js';
export { appleJwsRoots, appleReceiptRoots } from './roots.js';
export type { RootInput } from './chain.js';
