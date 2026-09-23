/**
 * Thrown when a signed payload fails verification. `reason` is the
 * machine-readable cause (same reason codes as the Java implementation —
 * PLAN.md §3). A payload that throws must be treated as fully untrusted.
 */
export class VerificationError extends Error {
  readonly reason: Reason;

  constructor(reason: Reason, message: string, cause?: unknown) {
    super(`${reason}: ${message}`, cause !== undefined ? { cause } : undefined);
    this.name = 'VerificationError';
    this.reason = reason;
  }
}

export const Reason = {
  INVALID_JWS_FORMAT: 'INVALID_JWS_FORMAT',
  INVALID_CERTIFICATE: 'INVALID_CERTIFICATE',
  INVALID_CERTIFICATE_PURPOSE: 'INVALID_CERTIFICATE_PURPOSE',
  INVALID_CHAIN: 'INVALID_CHAIN',
  INVALID_SIGNATURE: 'INVALID_SIGNATURE',
  WRONG_BUNDLE_ID: 'WRONG_BUNDLE_ID',
  WRONG_ENVIRONMENT: 'WRONG_ENVIRONMENT',
  WRONG_APP_APPLE_ID: 'WRONG_APP_APPLE_ID',
  INVALID_RECEIPT_FORMAT: 'INVALID_RECEIPT_FORMAT',
  DEVICE_HASH_MISMATCH: 'DEVICE_HASH_MISMATCH',
  STALE_PAYLOAD: 'STALE_PAYLOAD',
  /**
   * The verifyReceipt request envelope is unusable: the body is not a JSON
   * object or nests deeper than 64, or `receipt-data` is missing, empty or
   * not a string. Reported only as a `VerifyReceiptResult.failureReason`;
   * never thrown.
   */
  MALFORMED_REQUEST: 'MALFORMED_REQUEST',
  /**
   * An unexpected error inside the verifyReceipt endpoint, answered as
   * status 21009. Reported only as a `VerifyReceiptResult.failureReason`;
   * never thrown.
   */
  INTERNAL_ERROR: 'INTERNAL_ERROR',
  /**
   * The raw verifyReceipt request body is over
   * `VerifyReceiptEndpoint.MAX_REQUEST_BYTES` (3,145,728 UTF-8 bytes), the
   * size at which Apple's endpoint answers HTTP 413. Status 21002 in the
   * response body; an HTTP layer can map it to 413 as Apple does. Reported
   * only as a `VerifyReceiptResult.failureReason`; never thrown.
   */
  REQUEST_TOO_LARGE: 'REQUEST_TOO_LARGE',
} as const;

export type Reason = (typeof Reason)[keyof typeof Reason];

export const Environment = {
  PRODUCTION: 'Production',
  SANDBOX: 'Sandbox',
  XCODE: 'Xcode',
  LOCAL_TESTING: 'LocalTesting',
} as const;

export type Environment = (typeof Environment)[keyof typeof Environment];
