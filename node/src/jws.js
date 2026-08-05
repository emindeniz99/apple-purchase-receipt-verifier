import { X509Certificate, verify as cryptoVerify } from 'node:crypto';
import { Environment, Reason, VerificationError } from './errors.js';
import { hasExtension } from './der.js';
import { normalizeRoots, validatePair } from './chain.js';

/** Apple marker OID: leaf certificate used for App Store signing. */
const LEAF_OID = '1.2.840.113635.100.6.11.1';
/** Apple marker OID: Worldwide Developer Relations intermediate CA. */
const INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';

const KNOWN_ENVIRONMENTS = new Set(Object.values(Environment));

/**
 * Verifies Apple-signed JWS payloads (StoreKit 2 `jwsRepresentation`,
 * `signedTransactionInfo` / `signedRenewalInfo`, Server Notifications V2)
 * completely offline against pinned Apple roots — PLAN.md §2.1, mirroring
 * the Java implementation check-for-check.
 */
export class JwsVerifier {
  #roots;
  #bundleId;
  #acceptedEnvironments;
  #appAppleId;
  #maxSignedAgeMillis;

  /**
   * @param {object} options
   * @param {Array} options.trustedRoots pinned roots (prod: `appleJwsRoots()`)
   * @param {string} options.bundleId bundle id every payload must carry
   * @param {string[]} options.acceptedEnvironments e.g. ['Production','Sandbox']
   *   — include Sandbox on endpoints App Review can hit (PLAN.md D3)
   * @param {number} [options.appAppleId] required to accept Production
   *   AppTransactions
   * @param {number} [options.maxSignedAgeMillis] reject payloads signed
   *   longer ago than this (PLAN.md D5)
   */
  constructor({ trustedRoots, bundleId, acceptedEnvironments, appAppleId = null,
    maxSignedAgeMillis = null }) {
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
  verifyTransaction(jws) {
    const payload = this.#verifySignature(jws);
    this.#requireBundleId(payload.bundleId);
    this.#requireAcceptedEnvironment(payload.environment);
    return payload;
  }

  /**
   * Verifies a signed AppTransaction and checks bundle id, environment
   * (`receiptType`), and — in Production — the app Apple id.
   */
  verifyAppTransaction(jws) {
    const payload = this.#verifySignature(jws);
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
  verifyRaw(jws) {
    return this.#verifySignature(jws);
  }

  #verifySignature(jws) {
    if (typeof jws !== 'string') {
      throw new VerificationError(Reason.INVALID_JWS_FORMAT, 'jws must be a string');
    }
    const parts = jws.split('.');
    if (parts.length !== 3) {
      throw new VerificationError(Reason.INVALID_JWS_FORMAT,
        `expected 3 dot-separated segments, got ${parts.length}`);
    }
    const header = parseJsonSegment(parts[0], 'header');
    if (header.alg !== 'ES256') {
      throw new VerificationError(Reason.INVALID_JWS_FORMAT,
        `alg must be ES256, got ${header.alg}`);
    }
    if (!Array.isArray(header.x5c) || header.x5c.length !== 3) {
      throw new VerificationError(Reason.INVALID_JWS_FORMAT,
        'x5c must contain exactly 3 certificates');
    }
    let leaf;
    let intermediate;
    try {
      leaf = new X509Certificate(Buffer.from(header.x5c[0], 'base64'));
      intermediate = new X509Certificate(Buffer.from(header.x5c[1], 'base64'));
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

    const payload = parseJsonSegment(parts[1], 'payload');
    // Chain validity is checked at signing time so payloads signed with
    // since-rotated certificates keep verifying (PLAN.md §2.1 step 4).
    const signedAtMillis = typeof payload.signedDate === 'number' ? payload.signedDate
      : (typeof payload.receiptCreationDate === 'number' ? payload.receiptCreationDate : null);
    const effectiveDate = signedAtMillis === null ? new Date() : new Date(signedAtMillis);
    validatePair(leaf, intermediate, this.#roots, effectiveDate);

    if (leaf.publicKey.asymmetricKeyType !== 'ec') {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'leaf key is not EC');
    }
    const signature = Buffer.from(parts[2], 'base64url');
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

  #requireBundleId(actual) {
    if (actual !== this.#bundleId) {
      throw new VerificationError(Reason.WRONG_BUNDLE_ID,
        `expected ${this.#bundleId} but payload has ${actual}`);
    }
  }

  #requireAcceptedEnvironment(claim) {
    if (!KNOWN_ENVIRONMENTS.has(claim) || !this.#acceptedEnvironments.has(claim)) {
      throw new VerificationError(Reason.WRONG_ENVIRONMENT,
        `payload environment ${claim} not in accepted set`);
    }
    return claim;
  }
}

function parseJsonSegment(segment, what) {
  try {
    const parsed = JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
    if (parsed === null || typeof parsed !== 'object') {
      throw new Error('not a JSON object');
    }
    return parsed;
  } catch (cause) {
    throw new VerificationError(Reason.INVALID_JWS_FORMAT,
      `${what} is not valid base64url JSON`, cause);
  }
}

function safeHasExtension(cert, oid) {
  try {
    return hasExtension(cert.raw, oid);
  } catch {
    return false;
  }
}
