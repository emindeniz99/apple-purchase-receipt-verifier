/**
 * apple-purchase-receipt-verifier, 0.7: a verifier, not business logic.
 * `createVerifier(config).verifyReceipt/verifySignedData/verifyReceiptEndpoint`
 * answer one question — did Apple sign this data, under a pinned Apple
 * root? — and, if so, return the data. Bundle id, environment, product id,
 * device binding, refunds and idempotency are the caller's decisions; see
 * the README's post-verification checklist.
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
} from './errors.js';
export {
  AppleStatus,
  Environment,
  environmentFromJwsEnvironment,
  environmentFromReceiptType,
} from './environment.js';
export type { JsonPayload } from './jws.js';
export { createJsonPayload, decodeX5cEntry } from './jws.js';
export type { InAppPurchase, RawAttributes, ReceiptPayload } from './receipt-payload.js';
export { createInAppPurchase, createReceiptPayload } from './receipt-payload.js';
export { decodeReceiptBase64 } from './receipt.js';
export type { RootInput } from './chain.js';
