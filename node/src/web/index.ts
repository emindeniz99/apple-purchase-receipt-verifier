/**
 * `apple-purchase-receipt-verifier/web` — the Promise-returning entry
 * point, kept from 0.7 so code written for it keeps working.
 *
 * Same verifier, same module, same `Reason`s as the default entry point;
 * `createConfig` and every `Verifier` method return a Promise. Porting
 * between the two is adding or removing `await`.
 */
import {
  createConfig as createConfigSync,
  type Config,
  type CreateConfigOptions,
} from '../config.js';
import type { Environment } from '../environment.js';
import type { VerificationResult } from '../errors.js';
import type { JsonPayload, ReceiptPayload } from '../payload.js';
import { createVerifier as createVerifierSync } from '../verifier.js';

export type { Config, CreateConfigOptions, RootInput } from '../config.js';
export {
  Reason,
  type Failure,
  type VerificationResult,
  type VerifiedResult,
  type FailedResult,
} from '../errors.js';
export { AppleStatus, Environment } from '../environment.js';
export {
  createInAppPurchase,
  createJsonPayload,
  createReceiptPayload,
  type InAppPurchase,
  type JsonPayload,
  type RawAttributes,
  type ReceiptPayload,
} from '../payload.js';

export interface Verifier {
  verifyReceipt(base64: string): Promise<VerificationResult<ReceiptPayload>>;
  verifySignedData(jws: string): Promise<VerificationResult<JsonPayload>>;
  verifyReceiptEndpoint(environment: Environment, requestJson: string): Promise<string>;
}

/**
 * The one way to build a config. Anything left out takes the default, so
 * `createConfig()` is Apple's three pinned roots and the system clock.
 */
export async function createConfig(options: CreateConfigOptions = {}): Promise<Config> {
  return createConfigSync(options);
}

/**
 * A `Verifier` for `config`.
 *
 * @throws {TypeError} if `config` is null/undefined, its roots are empty, or
 * aprv.wasm refuses one of them.
 * @throws {Error} if aprv.wasm is not the module this package binds.
 */
export function createVerifier(config: Config): Verifier {
  const verifier = createVerifierSync(config);
  return {
    verifyReceipt: async (base64) => verifier.verifyReceipt(base64),
    verifySignedData: async (jws) => verifier.verifySignedData(jws),
    verifyReceiptEndpoint: async (environment, requestJson) =>
      verifier.verifyReceiptEndpoint(environment, requestJson),
  };
}
