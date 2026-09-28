/**
 * The one `Verifier` for the web build — the same contract as the Node
 * build's verifier.ts, every method async because `crypto.subtle` is.
 */
import { AppleStatus, type Environment } from '../environment.js';
import { Reason, VerificationError, type Failure, type VerificationResult } from '../errors.js';
import type { Config } from './config.js';
import { verifySignedData, type JsonPayload } from './jws.js';
import type { ReceiptPayload } from '../receipt-payload.js';
import { verifyReceipt } from './receipt.js';
import { respond } from './verify-receipt-endpoint.js';

export interface Verifier {
  verifyReceipt(base64: string): Promise<VerificationResult<ReceiptPayload>>;
  verifySignedData(jws: string): Promise<VerificationResult<JsonPayload>>;
  verifyReceiptEndpoint(environment: Environment, requestJson: string): Promise<string>;
}

function toFailure(error: VerificationError): Failure {
  const keepCause =
    error.reason === Reason.UNREADABLE_PAYLOAD || error.reason === Reason.INTERNAL_ERROR;
  return keepCause && error.cause !== undefined
    ? { reason: error.reason, message: error.message, cause: error.cause }
    : { reason: error.reason, message: error.message };
}

function internalError(cause: unknown): Failure {
  const name = cause instanceof Error ? cause.constructor.name : typeof cause;
  return { reason: Reason.INTERNAL_ERROR, message: `unexpected ${name}`, cause };
}

async function run<T>(work: () => Promise<T>): Promise<VerificationResult<T>> {
  try {
    return { verified: true, payload: await work() };
  } catch (error) {
    if (error instanceof VerificationError) {
      return { verified: false, failure: toFailure(error) };
    }
    return { verified: false, failure: internalError(error) };
  }
}

function stringInput(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/**
 * A `Verifier` for `config`.
 *
 * @throws {TypeError} if `config` is null/undefined, or its roots are empty.
 */
export function createVerifier(config: Config): Verifier {
  if (config === null || config === undefined) {
    throw new TypeError('config must not be null');
  }
  if (config.roots.length === 0) {
    throw new TypeError('config.roots must not be empty');
  }
  const roots = config.roots;
  const clock = config.clock;
  return {
    verifyReceipt: (base64: string) => run(() => verifyReceipt(stringInput(base64), roots, clock)),
    verifySignedData: (jws: string) => run(() => verifySignedData(stringInput(jws), roots, clock)),
    async verifyReceiptEndpoint(environment: Environment, requestJson: string): Promise<string> {
      if (environment === null || environment === undefined) {
        throw new TypeError('environment must not be null');
      }
      try {
        return await respond(environment, stringInput(requestJson), roots, clock);
      } catch {
        return `{"status":${AppleStatus.INTERNAL_DATA_ACCESS_ERROR}}`;
      }
    },
  };
}
