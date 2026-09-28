/**
 * `apple-purchase-receipt-verifier/web` — the WebCrypto-only entry point.
 *
 * Same shape and the same `Reason`s as the default entry point; every
 * verify method (and `createConfig`/`defaultConfig`, since loading the
 * bundled roots checks a fingerprint through `crypto.subtle`) returns a
 * Promise, because `crypto.subtle` is async. Porting between the two is
 * adding or removing `await`.
 *
 * It uses nothing but `crypto.subtle`, `TextDecoder` and plain
 * `Uint8Array`s — no `node:*`, no `Buffer`, no filesystem — so it runs on
 * Node, Bun, Deno, Cloudflare Workers with or without `nodejs_compat`, the
 * Vercel Edge runtime and other WebCrypto-only isolates.
 */
export { createConfig, defaultConfig, type Config, type CreateConfigOptions } from './config.js';
export { createVerifier, type Verifier } from './verifier.js';
export {
  Reason,
  VerificationError,
  type Failure,
  type VerificationResult,
  type VerifiedResult,
  type FailedResult,
} from '../errors.js';
export {
  AppleStatus,
  Environment,
  environmentFromJwsEnvironment,
  environmentFromReceiptType,
} from '../environment.js';
export type { JsonPayload } from './jws.js';
export { createJsonPayload, decodeX5cEntry } from './jws.js';
export type { InAppPurchase, RawAttributes, ReceiptPayload } from '../receipt-payload.js';
export { createInAppPurchase, createReceiptPayload } from '../receipt-payload.js';
export { decodeReceiptBase64 } from './receipt.js';
export type { RootInput } from './chain.js';
