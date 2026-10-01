/**
 * The 0.7 result vocabulary, shared by both entry points. The reasons are
 * the names aprv.wasm answers with; this file only spells them for
 * JavaScript. A failure is a value inside the result, never a thrown error.
 */

export const Reason = {
  /** base64, ASN.1, CMS or JWS structure is broken. */
  MALFORMED: 'MALFORMED',
  /** Input over a fixed cap (see the Bounds table in docs/design/0.7-api.md). */
  TOO_LARGE: 'TOO_LARGE',
  /** The signature does not match the content. */
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  /** The chain does not reach a pinned root. */
  UNTRUSTED_CHAIN: 'UNTRUSTED_CHAIN',
  /** Unreadable certificate, or outside its validity window. */
  INVALID_CERTIFICATE: 'INVALID_CERTIFICATE',
  /** A valid Apple certificate of the wrong kind: marker OID missing. */
  INVALID_CERTIFICATE_PURPOSE: 'INVALID_CERTIFICATE_PURPOSE',
  /** Apple signed it, but the content does not parse. */
  UNREADABLE_PAYLOAD: 'UNREADABLE_PAYLOAD',
  /** The library failed; alert, do not retry. */
  INTERNAL_ERROR: 'INTERNAL_ERROR',
} as const;

export type Reason = (typeof Reason)[keyof typeof Reason];

/** A failed {@link VerificationResult}: `reason()`, a log-safe `message`, and the cause when there is one. */
export interface Failure {
  readonly reason: Reason;
  readonly message: string;
  readonly cause?: unknown;
}

/** A verified result: `payload` is set. */
export interface VerifiedResult<T> {
  readonly verified: true;
  readonly payload: T;
  readonly failure?: undefined;
}

/** A failed result: `failure` is set. */
export interface FailedResult {
  readonly verified: false;
  readonly payload?: undefined;
  readonly failure: Failure;
}

/** The result of `verifyReceipt` or `verifySignedData`: never throws. */
export type VerificationResult<T> = VerifiedResult<T> | FailedResult;
