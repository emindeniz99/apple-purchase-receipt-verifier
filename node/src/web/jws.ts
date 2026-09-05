import { Environment, Reason, VerificationError } from '../errors.js';
import { asciiEncode, base64Decode } from '../bytes.js';
import { requireDecodableExtensions } from '../der.js';
import { parseCertificate, type ParsedCertificate } from '../x509.js';
import {
  decodeJwsSegment,
  INTERMEDIATE_OID,
  JwsClaimChecker,
  LEAF_OID,
  parseJsonSegment,
  signedAtMillisOf,
  splitJws,
} from '../jws-claims.js';
import { normalizeRoots, validatePair, type RootInput } from './chain.js';
import { verifyEs256 } from './crypto.js';
import { OID_EC_PUBLIC_KEY, requireBuildablePublicKey } from './jwk.js';

export { isTransactionActiveAt } from '../jws-claims.js';
export type { AppTransactionPayload, Claims, Clock, TransactionPayload } from '../jws-claims.js';

import type { AppTransactionPayload, Claims, Clock, TransactionPayload } from '../jws-claims.js';

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
 * The WebCrypto twin of the Node build's {@link JwsVerifier}: same options,
 * same checks in the same order, same {@link VerificationError} reasons —
 * every method returns a Promise because `crypto.subtle` is async.
 */
export class JwsVerifier {
  #roots: ParsedCertificate[];
  #claims: JwsClaimChecker;

  constructor(options: JwsVerifierOptions) {
    this.#roots = normalizeRoots(options.trustedRoots);
    this.#claims = new JwsClaimChecker(options);
  }

  /** Verifies a signed transaction and checks bundle id + environment. */
  async verifyTransaction(jws: string): Promise<TransactionPayload> {
    const payload = (await this.#verifySignature(jws)) as TransactionPayload;
    this.#claims.requireBundleId(payload.bundleId);
    this.#claims.requireAcceptedEnvironment(payload.environment);
    return payload;
  }

  /**
   * Verifies a signed AppTransaction and checks bundle id, environment
   * (`receiptType`), and — in Production — the app Apple id.
   */
  async verifyAppTransaction(jws: string): Promise<AppTransactionPayload> {
    const payload = (await this.#verifySignature(jws)) as AppTransactionPayload;
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
  async verifyRaw(jws: string): Promise<Claims> {
    return this.#verifySignature(jws);
  }

  async #verifySignature(jws: string): Promise<Claims> {
    const { headerB64, payloadB64, signatureB64, x5c } = splitJws(jws);
    let leaf: ParsedCertificate;
    let intermediate: ParsedCertificate;
    try {
      // All three entries, including the third — which is parsed and then
      // dropped. It is never compared to an anchor and never trusted, so
      // swapping in a stranger's root changes nothing, but an entry that is
      // not a certificate is INVALID_CERTIFICATE at every index
      // (transaction/reject-x5c-root-that-is-not-a-certificate).
      //
      // Two defects the parser itself does not reach are settled here, in
      // this catch, so that both builds answer INVALID_CERTIFICATE rather
      // than failing later and differently: an extension VALUE that stops
      // decoding, which is the difference between parsing a certificate and
      // scanning it for a marker OID; and a key on a curve this build
      // cannot import, which building the key is the only way to find.
      //
      // The key check is scoped exactly as the Node build's `.publicKey` is
      // scoped — an RSA or EC key must build, a key of any other algorithm
      // is readable and none of this check's business. Converting every
      // entry unconditionally instead would reject a DSA-keyed x5c[2] the
      // Node build accepts, which the third entry's own rule forbids: it is
      // never trusted and never compared, so it has to BE a certificate and
      // nothing more.
      const parsed = [0, 1, 2].map((index) => {
        const raw = base64Decode(x5c[index]!);
        const certificate = parseCertificate(raw);
        requireDecodableExtensions(raw);
        requireBuildablePublicKey(certificate.publicKeyAlgorithmOid, certificate.spki);
        return certificate;
      });
      leaf = parsed[0]!;
      intermediate = parsed[1]!;
    } catch (cause) {
      throw new VerificationError(
        Reason.INVALID_CERTIFICATE,
        'x5c entry is not a valid certificate',
        cause,
      );
    }
    if (!leaf.hasExtension(LEAF_OID)) {
      throw new VerificationError(
        Reason.INVALID_CERTIFICATE_PURPOSE,
        `leaf certificate lacks Apple marker OID ${LEAF_OID}`,
      );
    }
    if (!intermediate.hasExtension(INTERMEDIATE_OID)) {
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
    await validatePair(leaf, intermediate, this.#roots, effectiveDate);

    if (leaf.publicKeyAlgorithmOid !== OID_EC_PUBLIC_KEY) {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'leaf key is not EC');
    }
    const signature = decodeJwsSegment(signatureB64, 'signature');
    if (signature.length !== 64) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        `ES256 signature must be 64 bytes, got ${signature.length}`,
      );
    }
    const signingInput = asciiEncode(`${headerB64}.${payloadB64}`);
    if (!(await verifyEs256(leaf.spki, signature, signingInput))) {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'ES256 signature check failed');
    }

    this.#claims.requireFresh(signedAtMillis);
    return payload;
  }
}
