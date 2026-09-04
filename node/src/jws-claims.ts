/**
 * The JWS parts of verification that are not cryptography: segment shape,
 * header requirements, claim models, and the bundle-id / environment /
 * app-Apple-id / staleness checks. Shared by both entry points so the two
 * builds return the same reason for the same payload.
 */
import { Environment, Reason, VerificationError } from './errors.js';
import { base64Decode, utf8Decode } from './bytes.js';

/** Apple marker OID: leaf certificate used for App Store signing. */
export const LEAF_OID = '1.2.840.113635.100.6.11.1';
/** Apple marker OID: Worldwide Developer Relations intermediate CA. */
export const INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

const KNOWN_ENVIRONMENTS = new Set<string>(Object.values(Environment));

/** Raw JWS claims — Apple payloads are JSON objects. */
export type Claims = Record<string, unknown>;

/**
 * Decoded `JWSTransactionDecodedPayload` claims this library reads. All
 * other claims stay accessible via index access. Dates are ms since epoch.
 */
export interface TransactionPayload extends Claims {
  bundleId?: string;
  environment?: string;
  productId?: string;
  transactionId?: string;
  originalTransactionId?: string;
  webOrderLineItemId?: string;
  subscriptionGroupIdentifier?: string;
  appAccountToken?: string;
  inAppOwnershipType?: string;
  type?: string;
  transactionReason?: string;
  storefront?: string;
  currency?: string;
  offerIdentifier?: string;
  signedDate?: number;
  purchaseDate?: number;
  originalPurchaseDate?: number;
  expiresDate?: number;
  revocationDate?: number;
  price?: number;
  quantity?: number;
  offerType?: number;
  revocationReason?: number;
}

/** Decoded `AppTransaction` claims; environment lives in `receiptType`. */
export interface AppTransactionPayload extends Claims {
  bundleId?: string;
  receiptType?: string;
  applicationVersion?: string;
  originalApplicationVersion?: string;
  deviceVerification?: string;
  deviceVerificationNonce?: string;
  appTransactionId?: string;
  appAppleId?: number;
  receiptCreationDate?: number;
  originalPurchaseDate?: number;
  preorderDate?: number;
  versionExternalIdentifier?: number;
}

/**
 * Entitlement helper for a verified transaction: not revoked, and (for
 * subscriptions) not expired at `now`. Point-in-time on the signed claims
 * only — later refunds or renewals are invisible to it.
 */
export function isTransactionActiveAt(payload: TransactionPayload, now: Date): boolean {
  const t = now.getTime();
  if (typeof payload.revocationDate === 'number' && t >= payload.revocationDate) {
    return false;
  }
  if (typeof payload.expiresDate === 'number') {
    return t < payload.expiresDate;
  }
  return true;
}

/** The three segments plus the x5c chain, after the ES256/x5c shape checks. */
export interface JwsSegments {
  headerB64: string;
  payloadB64: string;
  signatureB64: string;
  x5c: string[];
}

export function splitJws(jws: string): JwsSegments {
  if (typeof jws !== 'string') {
    throw new VerificationError(Reason.INVALID_JWS_FORMAT, 'jws must be a string');
  }
  const parts = jws.split('.');
  if (parts.length !== 3) {
    throw new VerificationError(
      Reason.INVALID_JWS_FORMAT,
      `expected 3 dot-separated segments, got ${parts.length}`,
    );
  }
  const header = parseJsonSegment(parts[0]!, 'header');
  if (header['alg'] !== 'ES256') {
    throw new VerificationError(
      Reason.INVALID_JWS_FORMAT,
      `alg must be ES256, got ${header['alg']}`,
    );
  }
  const x5c = header['x5c'];
  if (!Array.isArray(x5c) || x5c.length !== 3 || !x5c.every((c) => typeof c === 'string')) {
    throw new VerificationError(
      Reason.INVALID_JWS_FORMAT,
      'x5c must contain exactly 3 certificates',
    );
  }
  return {
    headerB64: parts[0]!,
    payloadB64: parts[1]!,
    signatureB64: parts[2]!,
    x5c: x5c as string[],
  };
}

export function parseJsonSegment(segment: string, what: string): Claims {
  try {
    const parsed: unknown = JSON.parse(utf8Decode(base64Decode(segment)));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('not a JSON object');
    }
    return parsed as Claims;
  } catch (cause) {
    throw new VerificationError(
      Reason.INVALID_JWS_FORMAT,
      `${what} is not valid base64url JSON`,
      cause,
    );
  }
}

/**
 * When the payload says it was signed, in ms — `signedDate` for transactions,
 * `receiptCreationDate` for AppTransactions, null when neither is present.
 * Chain validity is judged at this instant so payloads signed with
 * since-rotated certificates keep verifying (PLAN.md §2.1 step 4).
 */
export function signedAtMillisOf(payload: Claims): number | null {
  if (typeof payload['signedDate'] === 'number') {
    return payload['signedDate'];
  }
  return typeof payload['receiptCreationDate'] === 'number' ? payload['receiptCreationDate'] : null;
}

/**
 * Injectable source of "now". A supplier rather than a fixed timestamp so a
 * long-lived verifier keeps advancing; `Date` rather than a number because
 * it is Node's point-in-time type and is what {@link isTransactionActiveAt}
 * already takes. Omitted (or null), the system clock is used.
 */
export type Clock = () => Date;

/** The default: the system clock, i.e. today's behaviour unchanged. */
export function normalizeClock(clock: Clock | null | undefined): Clock {
  if (clock === null || clock === undefined) {
    return () => new Date();
  }
  if (typeof clock !== 'function') {
    throw new TypeError('clock must be a function returning a Date');
  }
  return clock;
}

export interface ClaimCheckerOptions {
  bundleId: string;
  acceptedEnvironments: Environment[];
  appAppleId?: number | null;
  maxSignedAgeMillis?: number | null;
  clock?: Clock | null;
}

/** The claim checks both entry points run, after the signature is verified. */
export class JwsClaimChecker {
  readonly #bundleId: string;
  readonly #acceptedEnvironments: Set<string>;
  readonly #appAppleId: number | null;
  readonly #maxSignedAgeMillis: number | null;
  readonly #clock: Clock;

  constructor({
    bundleId,
    acceptedEnvironments,
    appAppleId = null,
    maxSignedAgeMillis = null,
    clock = null,
  }: ClaimCheckerOptions) {
    if (typeof bundleId !== 'string' || bundleId.length === 0) {
      throw new TypeError('bundleId is required');
    }
    if (
      !Array.isArray(acceptedEnvironments) ||
      acceptedEnvironments.length === 0 ||
      !acceptedEnvironments.every((e) => KNOWN_ENVIRONMENTS.has(e))
    ) {
      throw new TypeError('acceptedEnvironments must be a non-empty array of known environments');
    }
    this.#bundleId = bundleId;
    this.#acceptedEnvironments = new Set(acceptedEnvironments);
    this.#appAppleId = appAppleId;
    this.#maxSignedAgeMillis = maxSignedAgeMillis;
    this.#clock = normalizeClock(clock);
  }

  requireBundleId(actual: string | undefined): void {
    if (actual !== this.#bundleId) {
      throw new VerificationError(
        Reason.WRONG_BUNDLE_ID,
        `expected ${this.#bundleId} but payload has ${actual}`,
      );
    }
  }

  requireAcceptedEnvironment(claim: string | undefined): string {
    if (
      claim === undefined ||
      !KNOWN_ENVIRONMENTS.has(claim) ||
      !this.#acceptedEnvironments.has(claim)
    ) {
      throw new VerificationError(
        Reason.WRONG_ENVIRONMENT,
        `payload environment ${claim} not in accepted set`,
      );
    }
    return claim;
  }

  /** Production AppTransactions must name the configured app Apple id. */
  requireAppAppleId(environment: string, actual: number | undefined): void {
    if (
      environment === Environment.PRODUCTION &&
      (this.#appAppleId === null || this.#appAppleId !== actual)
    ) {
      throw new VerificationError(
        Reason.WRONG_APP_APPLE_ID,
        `expected ${this.#appAppleId} but payload has ${actual}`,
      );
    }
  }

  /**
   * The one check that legitimately moves with wall-clock time, so the one
   * the injected clock drives. Certificate validity is judged at the
   * payload's signing date instead (PLAN.md §2.1 step 4) and is deliberately
   * left on the system clock in its no-signing-date fallback.
   */
  requireFresh(signedAtMillis: number | null): void {
    if (
      this.#maxSignedAgeMillis !== null &&
      signedAtMillis !== null &&
      this.#clock().getTime() - signedAtMillis > this.#maxSignedAgeMillis
    ) {
      throw new VerificationError(
        Reason.STALE_PAYLOAD,
        `payload signed at ${signedAtMillis} exceeds max age ${this.#maxSignedAgeMillis}ms`,
      );
    }
  }
}
