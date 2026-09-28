/**
 * The one `Verifier`. Immutable, thread-safe (there is only ever one JS
 * thread per instance, but nothing here holds mutable state across calls),
 * and never throws from a verify method for any input — only `Config` and
 * `Environment` being null are programming errors, and those throw
 * `TypeError` before any verification runs.
 */
import type { Config } from './config.js';
import { AppleStatus, type Environment } from './environment.js';
import { Reason, VerificationError, type Failure, type VerificationResult } from './errors.js';
import { verifySignedData, type JsonPayload } from './jws.js';
import type { ReceiptPayload } from './receipt-payload.js';
import { verifyReceipt } from './receipt.js';
import { respond } from './verify-receipt-endpoint.js';

export interface Verifier {
  verifyReceipt(base64: string): VerificationResult<ReceiptPayload>;
  verifySignedData(jws: string): VerificationResult<JsonPayload>;
  verifyReceiptEndpoint(environment: Environment, requestJson: string): string;
}

/**
 * The failure a caller sees. The cause is kept only where it explains
 * Apple-signed content or a library fault (`UNREADABLE_PAYLOAD`,
 * `INTERNAL_ERROR`): behind any other reason it would be a parser or
 * provider exception about unverified input, whose message can quote raw
 * certificate text a logged stack trace would print.
 */
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

function run<T>(work: () => T): VerificationResult<T> {
  try {
    return { verified: true, payload: work() };
  } catch (error) {
    if (error instanceof VerificationError) {
      return { verified: false, failure: toFailure(error) };
    }
    // Only a JS engine failure (an out-of-memory condition, a stack
    // overflow) escapes past here; everything else this library can throw
    // is a VerificationError.
    return { verified: false, failure: internalError(error) };
  }
}

function stringInput(value: unknown): string {
  return typeof value === 'string' ? value : '';
}

/**
 * A `Verifier` for `config`.
 *
 * @throws {TypeError} if `config` is null/undefined, or its roots are
 * empty — a verifier with no roots would answer `UNTRUSTED_CHAIN` to
 * everything and nobody would notice until production.
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
    // A null/empty base64, jws or requestJson is input, not a programming
    // error, and fails as MALFORMED — so a non-string value is coerced to
    // "" defensively rather than throwing, for callers outside TypeScript's
    // type checking.
    verifyReceipt(base64: string): VerificationResult<ReceiptPayload> {
      return run(() => verifyReceipt(stringInput(base64), roots, clock));
    },
    verifySignedData(jws: string): VerificationResult<JsonPayload> {
      return run(() => verifySignedData(stringInput(jws), roots, clock));
    },
    verifyReceiptEndpoint(environment: Environment, requestJson: string): string {
      if (environment === null || environment === undefined) {
        throw new TypeError('environment must not be null');
      }
      try {
        return respond(environment, stringInput(requestJson), roots, clock);
      } catch {
        // respond() itself never throws for a VerificationError (it maps
        // every reason to a status internally); this is the same
        // engine-failure backstop as run() above.
        return `{"status":${AppleStatus.INTERNAL_DATA_ACCESS_ERROR}}`;
      }
    },
  };
}
