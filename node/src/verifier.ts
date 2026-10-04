/**
 * The one `Verifier`, over aprv.wasm. Reading the clock, moving the input
 * in as bytes, reading the answer out and keeping the six outcomes of
 * docs/rust-core/ARCHITECTURE.md §4 apart is all it does; every verdict is
 * the module's.
 *
 * The verify methods never throw for any input. A null `Config`, an empty
 * root set, a root the module refuses, a module that is not the one this
 * package binds, and an `Environment` other than the two values are
 * programming errors and throw from `createVerifier` or the endpoint call.
 */
import { InitRefusedError, Slot, initConfig, type Bindings } from './engine.js';
import type { Config } from './config.js';
import { AppleStatus, Environment } from './environment.js';
import { Reason, type Failure, type VerificationResult } from './errors.js';
import {
  WireError,
  receiptPayloadFromWire,
  rootToBase64,
  type JsonPayload,
  type ReceiptPayload,
} from './payload.js';

export interface Verifier {
  verifyReceipt(base64: string): VerificationResult<ReceiptPayload>;
  verifySignedData(jws: string): VerificationResult<JsonPayload>;
  verifyReceiptEndpoint(environment: Environment, requestJson: string): string;
}

const REASONS = new Set<string>(Object.values(Reason));
const ENDPOINT_INTERNAL_ERROR = `{"status":${AppleStatus.INTERNAL_DATA_ACCESS_ERROR}}`;
const utf8 = new TextEncoder();

/** The clock threw or answered something that is not a time: `INTERNAL_ERROR`. */
class ClockError extends Error {
  constructor(message: string, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'ClockError';
  }
}

/**
 * Reads the clock once, as the first thing a call does. Epoch milliseconds
 * from 0 to `Number.MAX_SAFE_INTEGER`; fractions are dropped.
 */
function readClock(clock: () => number): bigint {
  let value: unknown;
  try {
    value = clock();
  } catch (cause) {
    throw new ClockError('the configured clock failed', cause);
  }
  if (typeof value !== 'number' || !(value >= 0 && value <= Number.MAX_SAFE_INTEGER)) {
    throw new ClockError('the configured clock did not answer epoch milliseconds');
  }
  return BigInt(Math.floor(value));
}

/**
 * The input as UTF-8 bytes, at most `maxBytes` of them: the
 * `max_input_bytes` the instance's `init` stated, one over the largest cap
 * the module applies, so the module still sees an oversized input as
 * oversized and answers `TOO_LARGE` itself, while linear memory never has
 * to hold more than this. A value that is not a string is input, not a
 * programming error, and reaches the module as no bytes, which it answers
 * as `MALFORMED`. The caller's value itself never reaches the bindings.
 */
export function inputBytes(value: unknown, maxBytes: number): Uint8Array {
  const text = typeof value === 'string' ? value : '';
  if (text.length * 3 <= maxBytes) {
    return utf8.encode(text);
  }
  // Encode only a prefix. encodeInto stops before a code point that does
  // not fit, so with 3 bytes of room past the limit an input that does
  // not fit has written at least maxBytes bytes.
  const buffer = new Uint8Array(maxBytes + 3);
  const { written } = utf8.encodeInto(text, buffer);
  return buffer.subarray(0, Math.min(written, maxBytes));
}

function environmentCode(environment: Environment): number {
  if (environment === null || environment === undefined) {
    throw new TypeError('environment must not be null');
  }
  if (environment === Environment.PRODUCTION) {
    return 0;
  }
  if (environment === Environment.SANDBOX) {
    return 1;
  }
  throw new TypeError('environment must be Environment.PRODUCTION or Environment.SANDBOX');
}

function internalError(cause: unknown): Failure {
  if (cause instanceof ClockError) {
    return cause.cause === undefined
      ? { reason: Reason.INTERNAL_ERROR, message: cause.message }
      : { reason: Reason.INTERNAL_ERROR, message: cause.message, cause: cause.cause };
  }
  const name = cause instanceof Error ? cause.constructor.name : typeof cause;
  const what =
    cause instanceof WireError || cause instanceof SyntaxError
      ? 'answered in a shape this package does not read'
      : `failed (${name})`;
  return {
    reason: Reason.INTERNAL_ERROR,
    message: `aprv.wasm ${what}; the instance was discarded`,
    cause,
  };
}

const ENVIRONMENTS = new Set<unknown>([...Object.values(Environment), null]);

/** The `environment` member of a verified answer: one of the two values, or `null`. */
function environmentMember(doc: Record<string, unknown>): Environment | null {
  const value = doc['environment'];
  if (!Object.hasOwn(doc, 'environment') || !ENVIRONMENTS.has(value)) {
    throw new WireError('a verified answer has no environment of Production, Sandbox or null');
  }
  return value as Environment | null;
}

/**
 * Reads a verify answer: the payload and environment through `payload`, or
 * the module's failure.
 */
function answer<T>(
  text: string,
  payload: (value: unknown, environment: Environment | null) => T,
): VerificationResult<T> {
  const doc: unknown = JSON.parse(text);
  if (doc !== null && typeof doc === 'object') {
    const fields = doc as Record<string, unknown>;
    const { verified, reason, message } = fields;
    if (verified === true) {
      return { verified: true, payload: payload(fields['payload'], environmentMember(fields)) };
    }
    if (
      verified === false &&
      typeof reason === 'string' &&
      REASONS.has(reason) &&
      typeof message === 'string'
    ) {
      return { verified: false, failure: { reason: reason as Reason, message } };
    }
  }
  throw new WireError('the answer is neither a verified result nor a failure with a 0.7 reason');
}

/** Reads `verify-receipt`'s answer. Throws when it is not the 0.7 wire format. */
export function receiptAnswer(text: string): VerificationResult<ReceiptPayload> {
  return answer(text, receiptPayloadFromWire);
}

/** Reads `verify-signed-data`'s answer. Throws when it is not the 0.7 wire format. */
export function jwsAnswer(text: string): VerificationResult<JsonPayload> {
  return answer(text, jsonPayload);
}

function jsonPayload(value: unknown, environment: Environment | null): JsonPayload {
  if (typeof value !== 'string') {
    throw new WireError('a verified JWS payload is not a string');
  }
  return { json: value, environment };
}

function endpointAnswer(text: string): string {
  if (typeof text !== 'string') {
    throw new WireError('the endpoint answer is not a string');
  }
  return text;
}

function initRoots(config: Config): Uint8Array {
  if (config.roots === null) {
    return initConfig();
  }
  if (!Array.isArray(config.roots) || config.roots.length === 0) {
    throw new TypeError('config.roots must not be empty');
  }
  return initConfig(config.roots.map(rootToBase64));
}

/**
 * A `Verifier` for `config`.
 *
 * @throws {TypeError} if `config` is null/undefined, its roots are empty (a
 * verifier with no roots would answer `UNTRUSTED_CHAIN` to everything and
 * nobody would notice until production), or aprv.wasm refuses one of them.
 * @throws {Error} if aprv.wasm is not the module this package binds.
 */
export function createVerifier(config: Config): Verifier {
  if (config === null || config === undefined) {
    throw new TypeError('config must not be null');
  }
  const clock = config.clock;
  let slot: Slot;
  try {
    slot = new Slot(initRoots(config));
  } catch (error) {
    if (error instanceof InitRefusedError) {
      throw new TypeError(`aprv.wasm refused a configured root: ${error.message}`, {
        cause: error,
      });
    }
    throw error;
  }

  function verify<T>(
    input: unknown,
    op: (bindings: Bindings, now: bigint, bytes: Uint8Array) => string,
    read: (text: string) => VerificationResult<T>,
  ): VerificationResult<T> {
    try {
      const now = readClock(clock);
      return slot.call((bindings, max) => op(bindings, now, inputBytes(input, max)), read);
    } catch (error) {
      return { verified: false, failure: internalError(error) };
    }
  }

  return {
    verifyReceipt(base64: string): VerificationResult<ReceiptPayload> {
      return verify(base64, (b, now, bytes) => b.verifyReceipt(now, bytes), receiptAnswer);
    },
    verifySignedData(jws: string): VerificationResult<JsonPayload> {
      return verify(jws, (b, now, bytes) => b.verifySignedData(now, bytes), jwsAnswer);
    },
    verifyReceiptEndpoint(environment: Environment, requestJson: string): string {
      const env = environmentCode(environment);
      try {
        const now = readClock(clock);
        return slot.call(
          (b, max) => b.verifyReceiptEndpoint(env, now, inputBytes(requestJson, max)),
          endpointAnswer,
        );
      } catch {
        return ENDPOINT_INTERNAL_ERROR;
      }
    },
  };
}
