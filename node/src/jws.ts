import { X509Certificate, verify as cryptoVerify } from 'node:crypto';
import { Environment, Reason, VerificationError } from './errors.js';
import { hasExtension } from './der.js';
import { normalizeRoots, validatePair, type RootInput } from './chain.js';

/** Apple marker OID: leaf certificate used for App Store signing. */
const LEAF_OID = '1.2.840.113635.100.6.11.1';
/** Apple marker OID: Worldwide Developer Relations intermediate CA. */
const INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

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

export interface JwsVerifierOptions {
  /** Pinned roots (production: `appleJwsRoots()`). */
  trustedRoots: RootInput[];
  /** Bundle id every payload must carry. */
  bundleId: string;
  /** Include `'Sandbox'` on endpoints App Review can hit (PLAN.md D3). */
  acceptedEnvironments: Environment[];
  /** Required to accept Production AppTransactions. */
  appAppleId?: number | null;
  /** Reject payloads signed longer ago than this (PLAN.md D5). */
  maxSignedAgeMillis?: number | null;
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

/**
 * Verifies Apple-signed JWS payloads (StoreKit 2 `jwsRepresentation`,
 * `signedTransactionInfo` / `signedRenewalInfo`, Server Notifications V2)
 * completely offline against pinned Apple roots — PLAN.md §2.1, mirroring
 * the Java implementation check-for-check.
 */
export class JwsVerifier {
  #roots: X509Certificate[];
  #bundleId: string;
  #acceptedEnvironments: Set<string>;
  #appAppleId: number | null;
  #maxSignedAgeMillis: number | null;

  constructor({ trustedRoots, bundleId, acceptedEnvironments, appAppleId = null,
    maxSignedAgeMillis = null }: JwsVerifierOptions) {
    this.#roots = normalizeRoots(trustedRoots);
    if (typeof bundleId !== 'string' || bundleId.length === 0) {
      throw new TypeError('bundleId is required');
    }
    if (!Array.isArray(acceptedEnvironments) || acceptedEnvironments.length === 0
      || !acceptedEnvironments.every((e) => KNOWN_ENVIRONMENTS.has(e))) {
      throw new TypeError('acceptedEnvironments must be a non-empty array of known environments');
    }
    this.#bundleId = bundleId;
    this.#acceptedEnvironments = new Set(acceptedEnvironments);
    this.#appAppleId = appAppleId;
    this.#maxSignedAgeMillis = maxSignedAgeMillis;
  }

  /** Verifies a signed transaction and checks bundle id + environment. */
  verifyTransaction(jws: string): TransactionPayload {
    const payload = this.#verifySignature(jws) as TransactionPayload;
    this.#requireBundleId(payload.bundleId);
    this.#requireAcceptedEnvironment(payload.environment);
    return payload;
  }

  /**
   * Verifies a signed AppTransaction and checks bundle id, environment
   * (`receiptType`), and — in Production — the app Apple id.
   */
  verifyAppTransaction(jws: string): AppTransactionPayload {
    const payload = this.#verifySignature(jws) as AppTransactionPayload;
    this.#requireBundleId(payload.bundleId);
    const environment = this.#requireAcceptedEnvironment(payload.receiptType);
    if (environment === Environment.PRODUCTION
      && (this.#appAppleId === null || this.#appAppleId !== payload.appAppleId)) {
      throw new VerificationError(Reason.WRONG_APP_APPLE_ID,
        `expected ${this.#appAppleId} but payload has ${payload.appAppleId}`);
    }
    return payload;
  }

  /**
   * Verifies the signature/chain only and returns the raw claims — for
   * payload types without a dedicated model (renewal info, notification
   * envelopes). The caller must check bundle id / environment / app Apple
   * id in the returned claims itself.
   */
  verifyRaw(jws: string): Claims {
    return this.#verifySignature(jws);
  }

  #verifySignature(jws: string): Claims {
    if (typeof jws !== 'string') {
      throw new VerificationError(Reason.INVALID_JWS_FORMAT, 'jws must be a string');
    }
    const parts = jws.split('.');
    if (parts.length !== 3) {
      throw new VerificationError(Reason.INVALID_JWS_FORMAT,
        `expected 3 dot-separated segments, got ${parts.length}`);
    }
    const header = parseJsonSegment(parts[0]!, 'header');
    if (header['alg'] !== 'ES256') {
      throw new VerificationError(Reason.INVALID_JWS_FORMAT,
        `alg must be ES256, got ${header['alg']}`);
    }
    const x5c = header['x5c'];
    if (!Array.isArray(x5c) || x5c.length !== 3 || !x5c.every((c) => typeof c === 'string')) {
      throw new VerificationError(Reason.INVALID_JWS_FORMAT,
        'x5c must contain exactly 3 certificates');
    }
    let leaf: X509Certificate;
    let intermediate: X509Certificate;
    try {
      leaf = new X509Certificate(Buffer.from(x5c[0] as string, 'base64'));
      intermediate = new X509Certificate(Buffer.from(x5c[1] as string, 'base64'));
    } catch (cause) {
      throw new VerificationError(Reason.INVALID_CERTIFICATE,
        'x5c entry is not a valid certificate', cause);
    }
    if (!safeHasExtension(leaf, LEAF_OID)) {
      throw new VerificationError(Reason.INVALID_CERTIFICATE_PURPOSE,
        `leaf certificate lacks Apple marker OID ${LEAF_OID}`);
    }
    if (!safeHasExtension(intermediate, INTERMEDIATE_OID)) {
      throw new VerificationError(Reason.INVALID_CERTIFICATE_PURPOSE,
        `intermediate certificate lacks Apple marker OID ${INTERMEDIATE_OID}`);
    }

    const payload = parseJsonSegment(parts[1]!, 'payload');
    // Chain validity is checked at signing time so payloads signed with
    // since-rotated certificates keep verifying (PLAN.md §2.1 step 4).
    const signedAtMillis = typeof payload['signedDate'] === 'number' ? payload['signedDate']
      : (typeof payload['receiptCreationDate'] === 'number'
        ? payload['receiptCreationDate'] : null);
    const effectiveDate = signedAtMillis === null ? new Date() : new Date(signedAtMillis);
    validatePair(leaf, intermediate, this.#roots, effectiveDate);

    if (leaf.publicKey.asymmetricKeyType !== 'ec') {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'leaf key is not EC');
    }
    const signature = Buffer.from(parts[2]!, 'base64url');
    if (signature.length !== 64) {
      throw new VerificationError(Reason.INVALID_SIGNATURE,
        `ES256 signature must be 64 bytes, got ${signature.length}`);
    }
    const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`, 'ascii');
    const valid = cryptoVerify('sha256', signingInput,
      { key: leaf.publicKey, dsaEncoding: 'ieee-p1363' }, signature);
    if (!valid) {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'ES256 signature check failed');
    }

    if (this.#maxSignedAgeMillis !== null && signedAtMillis !== null
      && Date.now() - signedAtMillis > this.#maxSignedAgeMillis) {
      throw new VerificationError(Reason.STALE_PAYLOAD,
        `payload signed at ${signedAtMillis} exceeds max age ${this.#maxSignedAgeMillis}ms`);
    }
    return payload;
  }

  #requireBundleId(actual: string | undefined): void {
    if (actual !== this.#bundleId) {
      throw new VerificationError(Reason.WRONG_BUNDLE_ID,
        `expected ${this.#bundleId} but payload has ${actual}`);
    }
  }

  #requireAcceptedEnvironment(claim: string | undefined): string {
    if (claim === undefined || !KNOWN_ENVIRONMENTS.has(claim)
      || !this.#acceptedEnvironments.has(claim)) {
      throw new VerificationError(Reason.WRONG_ENVIRONMENT,
        `payload environment ${claim} not in accepted set`);
    }
    return claim;
  }
}

function parseJsonSegment(segment: string, what: string): Claims {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('not a JSON object');
    }
    return parsed as Claims;
  } catch (cause) {
    throw new VerificationError(Reason.INVALID_JWS_FORMAT,
      `${what} is not valid base64url JSON`, cause);
  }
}

function safeHasExtension(cert: X509Certificate, oid: string): boolean {
  try {
    return hasExtension(cert.raw, oid);
  } catch {
    return false;
  }
}
