/**
 * Apple's two App Store environments, and the two verifyReceipt URLs
 * `verifyReceiptEndpoint` imitates. The helpers state what an Apple value
 * means; whether to accept an environment is the caller's decision.
 */
export const Environment = {
  PRODUCTION: 'Production',
  SANDBOX: 'Sandbox',
} as const;

export type Environment = (typeof Environment)[keyof typeof Environment];

/**
 * Maps a receipt's `receipt_type` (attribute 0): `Production` and
 * `ProductionVPP` to `PRODUCTION`, `ProductionSandbox` and
 * `ProductionVPPSandbox` to `SANDBOX`, anything else (a missing value
 * included) to `null`. The endpoint uses the same rule for 21007 and 21008.
 */
export function environmentFromReceiptType(receiptType: string | null): Environment | null {
  if (receiptType === 'Production' || receiptType === 'ProductionVPP') {
    return Environment.PRODUCTION;
  }
  if (receiptType === 'ProductionSandbox' || receiptType === 'ProductionVPPSandbox') {
    return Environment.SANDBOX;
  }
  return null;
}

/**
 * Maps a JWS `environment` claim: `Production` to `PRODUCTION`, `Sandbox`
 * to `SANDBOX`, anything else (`Xcode`, `LocalTesting`, a missing claim) to
 * `null`.
 */
export function environmentFromJwsEnvironment(environment: string | null): Environment | null {
  if (environment === 'Production') {
    return Environment.PRODUCTION;
  }
  if (environment === 'Sandbox') {
    return Environment.SANDBOX;
  }
  return null;
}

/**
 * The `status` codes Apple documents for its verifyReceipt endpoint, so
 * callers do not write `21007` by hand. `verifyReceiptEndpoint` returns
 * only `OK`, `MALFORMED_RECEIPT_DATA`, `RECEIPT_NOT_AUTHENTICATED`,
 * `SANDBOX_RECEIPT_ON_PRODUCTION`, `PRODUCTION_RECEIPT_ON_SANDBOX` and
 * `INTERNAL_DATA_ACCESS_ERROR`. Its 21009 is deterministic for the same
 * input, so alert on it rather than retry. It never returns
 * `SERVER_UNAVAILABLE` or the 21100-21199 range, which mean Apple's own
 * servers failed and invite a retry.
 */
export const AppleStatus = {
  OK: 0,
  REQUEST_NOT_POST: 21000,
  NO_LONGER_SENT: 21001,
  MALFORMED_RECEIPT_DATA: 21002,
  RECEIPT_NOT_AUTHENTICATED: 21003,
  SHARED_SECRET_MISMATCH: 21004,
  SERVER_UNAVAILABLE: 21005,
  SUBSCRIPTION_EXPIRED: 21006,
  SANDBOX_RECEIPT_ON_PRODUCTION: 21007,
  PRODUCTION_RECEIPT_ON_SANDBOX: 21008,
  INTERNAL_DATA_ACCESS_ERROR: 21009,
  ACCOUNT_NOT_FOUND: 21010,
  INTERNAL_DATA_ACCESS_ERROR_RANGE_FIRST: 21100,
  INTERNAL_DATA_ACCESS_ERROR_RANGE_LAST: 21199,
} as const;
