// Spike only: the typed surface every prototype package exposes.
export declare class VerificationError extends Error {
  readonly code: number;
  /** Cross-port reason token, e.g. "WRONG_BUNDLE_ID". */
  readonly reason: string;
}
export interface ReceiptOptions { bundleId: string; trustedRoots?: Uint8Array[] }
export interface JwsOptions {
  bundleId: string;
  environments?: Array<'Production' | 'Sandbox' | 'Xcode' | 'LocalTesting'>;
  appAppleId?: bigint;
  trustedRoots?: Uint8Array[];
}
/** Verifies a legacy App Store receipt (DER bytes or base64). Throws VerificationError. */
export declare function verifyReceipt(receipt: Uint8Array | string, options: ReceiptOptions): Record<string, unknown>;
/** Verifies a StoreKit 2 transaction JWS. Throws VerificationError. */
export declare function verifyTransaction(jws: string, options: JwsOptions): Record<string, unknown>;
