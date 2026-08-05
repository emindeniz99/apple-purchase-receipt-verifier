/**
 * Thrown when a signed payload fails verification. `reason` is the
 * machine-readable cause (same reason codes as the Java implementation —
 * PLAN.md §3). A payload that throws must be treated as fully untrusted.
 */
export class VerificationError extends Error {
  constructor(reason, message, cause) {
    super(`${reason}: ${message}`, cause ? { cause } : undefined);
    this.name = 'VerificationError';
    this.reason = reason;
  }
}

export const Reason = Object.freeze({
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
});

export const Environment = Object.freeze({
  PRODUCTION: 'Production',
  SANDBOX: 'Sandbox',
  XCODE: 'Xcode',
  LOCAL_TESTING: 'LocalTesting',
});
