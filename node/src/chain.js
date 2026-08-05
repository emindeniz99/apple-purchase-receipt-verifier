import { X509Certificate } from 'node:crypto';
import { Reason, VerificationError } from './errors.js';

/** Normalizes trust-root inputs (X509Certificate | Buffer | PEM string). */
export function normalizeRoots(trustedRoots) {
  if (!Array.isArray(trustedRoots) || trustedRoots.length === 0) {
    throw new TypeError('trustedRoots must be a non-empty array');
  }
  return trustedRoots.map((r) => (r instanceof X509Certificate ? r : new X509Certificate(r)));
}

function validAt(cert, at) {
  const from = new Date(cert.validFrom);
  const to = new Date(cert.validTo);
  return from.getTime() <= at.getTime() && at.getTime() <= to.getTime();
}

function issuedBy(cert, issuer) {
  return cert.checkIssued(issuer) && cert.verify(issuer.publicKey);
}

/**
 * Validates the fixed JWS path leaf → intermediate → (pinned anchor):
 * validity windows at `at`, CA flag on the intermediate, and signature +
 * name chaining at each step. Anchors are trusted by fiat (their own
 * expiry is not checked — standard PKIX trust-anchor semantics).
 */
export function validatePair(leaf, intermediate, anchors, at) {
  if (!validAt(leaf, at) || !validAt(intermediate, at)) {
    throw new VerificationError(Reason.INVALID_CHAIN, 'certificate not valid at signing time');
  }
  if (!intermediate.ca) {
    throw new VerificationError(Reason.INVALID_CHAIN, 'intermediate is not a CA');
  }
  if (!issuedBy(leaf, intermediate)) {
    throw new VerificationError(Reason.INVALID_CHAIN, 'leaf not issued by intermediate');
  }
  if (!anchors.some((anchor) => issuedBy(intermediate, anchor))) {
    throw new VerificationError(Reason.INVALID_CHAIN,
      'intermediate not issued by a pinned root');
  }
}

const MAX_PATH_LENGTH = 6;

/**
 * Builds and validates a path from `target` through `candidates` to one of
 * the pinned `anchors` (receipt chains embed their intermediates in the CMS).
 */
export function buildAndValidatePath(target, candidates, anchors, at) {
  let current = target;
  for (let depth = 0; depth < MAX_PATH_LENGTH; depth++) {
    if (!validAt(current, at)) {
      throw new VerificationError(Reason.INVALID_CHAIN,
        'certificate not valid at signing time');
    }
    if (depth > 0 && !current.ca) {
      throw new VerificationError(Reason.INVALID_CHAIN, 'intermediate is not a CA');
    }
    if (anchors.some((anchor) => issuedBy(current, anchor))) {
      return;
    }
    const issuer = candidates.find(
      (candidate) => candidate !== current && issuedBy(current, candidate),
    );
    if (!issuer) {
      throw new VerificationError(Reason.INVALID_CHAIN,
        'chain does not reach a pinned root');
    }
    current = issuer;
  }
  throw new VerificationError(Reason.INVALID_CHAIN, 'chain exceeds maximum length');
}
