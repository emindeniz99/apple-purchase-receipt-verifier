import { X509Certificate, verify as cryptoVerify } from 'node:crypto';
import { Environment, Reason, VerificationError } from './errors.js';
import {
  hasExtension,
  requireDecodableExtensions,
  requireKnownVersion,
  requireNoDuplicateExtensions,
} from './der.js';
import { normalizeRoots, validatePair, type RootInput } from './chain.js';
import {
  decodeJwsSegment,
  INTERMEDIATE_OID,
  JwsClaimChecker,
  LEAF_OID,
  parseJsonSegment,
  signedAtMillisOf,
  splitJws,
} from './jws-claims.js';

export { isTransactionActiveAt } from './jws-claims.js';
export type { AppTransactionPayload, Claims, Clock, TransactionPayload } from './jws-claims.js';

import type { AppTransactionPayload, Claims, Clock, TransactionPayload } from './jws-claims.js';

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
  /**
   * Optional source of "now" for the checks that depend on wall-clock time
   * (today: the max-signed-age / STALE_PAYLOAD rule). Omitted, the system
   * clock is used and behaviour is unchanged. Certificate validity is NOT
   * driven by it — that is judged at the payload's signing date.
   */
  clock?: Clock | null;
}

/**
 * Verifies Apple-signed JWS payloads (StoreKit 2 `jwsRepresentation`,
 * `signedTransactionInfo` / `signedRenewalInfo`, Server Notifications V2)
 * completely offline against pinned Apple roots — PLAN.md §2.1, mirroring
 * the Java implementation check-for-check.
 */
export class JwsVerifier {
  #roots: X509Certificate[];
  #claims: JwsClaimChecker;

  constructor(options: JwsVerifierOptions) {
    this.#roots = normalizeRoots(options.trustedRoots);
    this.#claims = new JwsClaimChecker(options);
  }

  /** Verifies a signed transaction and checks bundle id + environment. */
  verifyTransaction(jws: string): TransactionPayload {
    const payload = this.#verifySignature(jws) as TransactionPayload;
    this.#claims.requireBundleId(payload.bundleId);
    this.#claims.requireAcceptedEnvironment(payload.environment);
    return payload;
  }

  /**
   * Verifies a signed AppTransaction and checks bundle id, environment
   * (`receiptType`), and — in Production — the app Apple id.
   */
  verifyAppTransaction(jws: string): AppTransactionPayload {
    const payload = this.#verifySignature(jws) as AppTransactionPayload;
    this.#claims.requireBundleId(payload.bundleId);
    const environment = this.#claims.requireAcceptedEnvironment(payload.receiptType);
    this.#claims.requireAppAppleId(environment, payload.appAppleId);
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
    const { headerB64, payloadB64, signatureB64, x5c } = splitJws(jws);
    let leaf: X509Certificate;
    let intermediate: X509Certificate;
    try {
      leaf = new X509Certificate(Buffer.from(x5c[0]!, 'base64'));
      intermediate = new X509Certificate(Buffer.from(x5c[1]!, 'base64'));
      // The third entry is parsed and then dropped. It is the JWS-supplied
      // root: it is never compared to an anchor and never trusted, so
      // swapping in a stranger's root still changes nothing — but an entry
      // that is not a certificate is INVALID_CERTIFICATE at every index
      // (transaction/reject-x5c-root-that-is-not-a-certificate), and java
      // already answered that way when nobody else did.
      const suppliedRoot = new X509Certificate(Buffer.from(x5c[2]!, 'base64'));
      // OpenSSL decodes an x5c entry far more leniently than the checks
      // below assume, so all four of the things it lets past are settled
      // here, while the verdict is still "this is not a certificate":
      //
      //  - the version, which OpenSSL keeps as whatever integer it found and
      //    nothing downstream ever reads (requireKnownVersion);
      //  - a repeated extension, which RFC 5280 4.2 forbids and OpenSSL
      //    reports only by flagging the certificate invalid, so the issuer
      //    check failed and a defect of the certificate came out as a
      //    verdict about the chain (requireNoDuplicateExtensions);
      //  - the public key, which is decoded lazily, so a namedCurve this
      //    runtime does not implement surfaces later as a raw
      //    ERR_OSSL_EVP_DECODE_ERROR out of `.publicKey`. Today the issuer
      //    check happens to fail its name comparison first; reading the key
      //    here means the escape cannot come back if that order changes.
      //  - an extension value that stops decoding partway through, which
      //    OpenSSL never looks inside (requireDecodableExtensions).
      for (const certificate of [leaf, intermediate, suppliedRoot]) {
        requireKnownVersion(certificate.raw);
        requireNoDuplicateExtensions(certificate.raw);
        requireDecodableExtensions(certificate.raw);
        void certificate.publicKey;
      }
    } catch (cause) {
      throw new VerificationError(
        Reason.INVALID_CERTIFICATE,
        'x5c entry is not a valid certificate',
        cause,
      );
    }
    if (!safeHasExtension(leaf, LEAF_OID)) {
      throw new VerificationError(
        Reason.INVALID_CERTIFICATE_PURPOSE,
        `leaf certificate lacks Apple marker OID ${LEAF_OID}`,
      );
    }
    if (!safeHasExtension(intermediate, INTERMEDIATE_OID)) {
      throw new VerificationError(
        Reason.INVALID_CERTIFICATE_PURPOSE,
        `intermediate certificate lacks Apple marker OID ${INTERMEDIATE_OID}`,
      );
    }

    const payload = parseJsonSegment(payloadB64, 'payload');
    // Chain validity is checked at signing time so payloads signed with
    // since-rotated certificates keep verifying (PLAN.md §2.1 step 4).
    const signedAtMillis = signedAtMillisOf(payload);
    const effectiveDate = signedAtMillis === null ? new Date() : new Date(signedAtMillis);
    validatePair(leaf, intermediate, this.#roots, effectiveDate);

    if (leaf.publicKey.asymmetricKeyType !== 'ec') {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'leaf key is not EC');
    }
    const signature = Buffer.from(decodeJwsSegment(signatureB64, 'signature'));
    if (signature.length !== 64) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        `ES256 signature must be 64 bytes, got ${signature.length}`,
      );
    }
    const signingInput = Buffer.from(`${headerB64}.${payloadB64}`, 'ascii');
    // The key goes in as SPKI DER rather than as the KeyObject itself:
    // Cloudflare workerd's node:crypto rejects a KeyObject inside the
    // options form of verify() (the form dsaEncoding needs), while Node,
    // Bun and Deno accept both. Same key, same check.
    const valid = cryptoVerify(
      'sha256',
      signingInput,
      {
        key: leaf.publicKey.export({ type: 'spki', format: 'der' }),
        format: 'der',
        type: 'spki',
        dsaEncoding: 'ieee-p1363',
      },
      signature,
    );
    if (!valid) {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'ES256 signature check failed');
    }

    this.#claims.requireFresh(signedAtMillis);
    return payload;
  }
}

function safeHasExtension(cert: X509Certificate, oid: string): boolean {
  try {
    return hasExtension(cert.raw, oid);
  } catch {
    return false;
  }
}
