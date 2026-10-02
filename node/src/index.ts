/**
 * apple-purchase-receipt-verifier, 0.7 API over aprv.wasm: a verifier, not
 * business logic. `createVerifier(config).verifyReceipt/verifySignedData/
 * verifyReceiptEndpoint` answer one question — did Apple sign this data,
 * under a pinned Apple root? — and, if so, return the data. Every verdict
 * comes from aprv.wasm, the one Rust core every package of this library
 * runs; this package moves bytes in and results out. Bundle id,
 * environment, product id, device binding, refunds and idempotency are the
 * caller's decisions; see the README's post-verification checklist.
 */
export {
  createConfig,
  defaultConfig,
  type Config,
  type CreateConfigOptions,
  type RootInput,
} from './config.js';
export { createVerifier, type Verifier } from './verifier.js';
export {
  Reason,
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
export {
  createInAppPurchase,
  createJsonPayload,
  createReceiptPayload,
  type InAppPurchase,
  type JsonPayload,
  type RawAttributes,
  type ReceiptPayload,
} from './payload.js';
