/**
 * Certificate path building and validation — the security core of the Node
 * build. A path is found top-down, from the pinned roots: a certificate's
 * signature is checked with the key of a certificate already vouched for
 * (an anchor, or something an anchor vouched for), never with the key of a
 * certificate nobody has vouched for yet (docs/design/0.7-hardening-parity.md
 * change 1, #161). Only once a path reaches an anchor are the certificates
 * on it checked for their validity window — a certificate outside its
 * window is `INVALID_CERTIFICATE`; a chain that reaches no pinned root is
 * `UNTRUSTED_CHAIN` whatever its dates say (owner, 2026-09-27).
 */
import { base64Decode, bytesEqual } from './bytes.js';
import { requireBuildablePublicKey, verifyCertificateSignature } from './crypto.js';
import { Reason, VerificationError } from './errors.js';
import { pemBody } from './pem.js';
import { KEY_CERT_SIGN_BIT, parseCertificate, type ParsedCertificate } from './x509.js';

/** Accepted trust-root inputs: DER bytes, or a PEM certificate. */
export type RootInput = Uint8Array | string;

/** Normalizes trust-root inputs (DER `Uint8Array` | PEM string). */
export function normalizeRoots(trustedRoots: readonly RootInput[]): ParsedCertificate[] {
  if (!Array.isArray(trustedRoots) || trustedRoots.length === 0) {
    throw new TypeError('trustedRoots must be a non-empty array');
  }
  return trustedRoots.map(toCertificate);
}

function toCertificate(root: RootInput): ParsedCertificate {
  if (typeof root !== 'string') {
    return parseCertificate(root);
  }
  const body = pemBody(root);
  if (body === null) {
    throw new TypeError('a string trust root must be a PEM certificate');
  }
  return parseCertificate(base64Decode(body));
}

function validAt(cert: ParsedCertificate, atMs: number): boolean {
  return cert.notBefore <= atMs && atMs <= cert.notAfter;
}

/**
 * What OpenSSL's `X509_check_issued` accepts, minus the parts that need a
 * name canonicaliser: the names chain by DER equality, the authority key
 * identifier agrees with the issuer's subject key identifier and serial
 * where it names them, and the issuer's keyUsage, if it has one, permits
 * keyCertSign. Comparing names as DER rather than a canonical (case- and
 * whitespace-folded) form is the one deliberate difference, and it is the
 * safe direction.
 */
function checkIssued(cert: ParsedCertificate, issuer: ParsedCertificate): boolean {
  if (!bytesEqual(cert.issuerDer, issuer.subjectDer)) {
    return false;
  }
  if (
    cert.authorityKeyId !== null &&
    issuer.subjectKeyId !== null &&
    !bytesEqual(cert.authorityKeyId, issuer.subjectKeyId)
  ) {
    return false;
  }
  if (
    cert.authorityCertSerial !== null &&
    !bytesEqual(cert.authorityCertSerial, issuer.serialNumber)
  ) {
    return false;
  }
  return issuer.keyUsage === null || issuer.keyUsage[KEY_CERT_SIGN_BIT] === true;
}

function issuedBy(cert: ParsedCertificate, issuer: ParsedCertificate): boolean {
  return checkIssued(cert, issuer) && verifyCertificateSignature(cert, issuer.spki);
}

function issuedByAnyAnchor(
  cert: ParsedCertificate,
  anchors: readonly ParsedCertificate[],
): boolean {
  return anchors.some((anchor) => issuedBy(cert, anchor));
}

/**
 * The extensions a certificate on the path may mark critical: the ones a
 * PKIX validator processes (RFC 5280 §6.1), and for the leaf also
 * cRLDistributionPoints and extKeyUsage. Any other extension marked critical
 * makes the certificate unusable, so the path fails, as a PKIX validator
 * fails it.
 */
const PROCESSED_EXTENSIONS = new Set([
  '2.5.29.15', // keyUsage
  '2.5.29.32', // certificatePolicies
  '2.5.29.33', // policyMappings
  '2.5.29.54', // inhibitAnyPolicy
  '2.5.29.28', // issuingDistributionPoint
  '2.5.29.27', // deltaCRLIndicator
  '2.5.29.36', // policyConstraints
  '2.5.29.19', // basicConstraints
  '2.5.29.17', // subjectAltName
  '2.5.29.30', // nameConstraints
]);
const PROCESSED_LEAF_EXTENSIONS = new Set([
  '2.5.29.31', // cRLDistributionPoints
  '2.5.29.37', // extKeyUsage
]);

/** Whether `cert` marks critical an extension no step here processes. */
function hasUnprocessedCriticalExtension(cert: ParsedCertificate, leaf: boolean): boolean {
  return cert.criticalExtensionOids.some(
    (oid) => !PROCESSED_EXTENSIONS.has(oid) && !(leaf && PROCESSED_LEAF_EXTENSIONS.has(oid)),
  );
}

function unprocessedCriticalExtension(): VerificationError {
  return new VerificationError(
    Reason.UNTRUSTED_CHAIN,
    'a certificate on the path has an unsupported critical extension',
  );
}

/** The longest path the builder will walk, anchor excluded. */
export const MAX_PATH_LENGTH = 6;

/**
 * Validates the fixed JWS path leaf, intermediate, pinned anchor. The two
 * signatures are checked from the anchor down first, so no key an anchor
 * did not vouch for is ever used; then the intermediate's window, its CA
 * flag and the leaf's window, at `atMs`.
 */
export function validatePair(
  leaf: ParsedCertificate,
  intermediate: ParsedCertificate,
  anchors: readonly ParsedCertificate[],
  atMs: number,
): void {
  if (!issuedByAnyAnchor(intermediate, anchors)) {
    throw new VerificationError(
      Reason.UNTRUSTED_CHAIN,
      'intermediate certificate is not signed by a pinned root',
    );
  }
  // Vouched for, and its key is about to check the leaf: an unbuildable key
  // (an unassigned or unimplemented EC curve) is the certificate's defect,
  // not a chain failure.
  requireBuildablePublicKey(intermediate);
  if (!issuedBy(leaf, intermediate)) {
    throw new VerificationError(
      Reason.UNTRUSTED_CHAIN,
      'leaf certificate is not signed by the intermediate',
    );
  }
  if (!validAt(intermediate, atMs)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE,
      'certificate is outside its validity window at the chain instant',
    );
  }
  if (!intermediate.isCa) {
    throw new VerificationError(Reason.UNTRUSTED_CHAIN, 'intermediate is not a CA');
  }
  if (hasUnprocessedCriticalExtension(intermediate, false)) {
    throw unprocessedCriticalExtension();
  }
  if (!validAt(leaf, atMs)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE,
      'certificate is outside its validity window at the chain instant',
    );
  }
  if (hasUnprocessedCriticalExtension(leaf, true)) {
    throw unprocessedCriticalExtension();
  }
}

/**
 * The embedded certificates whose signature verifies under a pinned anchor,
 * or under a certificate already accepted this way, walking down from the
 * anchors in at most {@link MAX_PATH_LENGTH} rounds. Only these are handed
 * to {@link buildAndValidatePath}.
 *
 * Walking down means no key an anchor did not vouch for, directly or
 * through a certificate it vouched for, is ever used to check a signature:
 * a receipt padded with certificates carrying the attacker's own keys costs
 * one name comparison per issuer for each of them, and they are simply left
 * out. An embedded copy of an anchor is the anchor, and is accepted without
 * a signature check.
 */
export function authenticatedTopDown(
  embedded: readonly ParsedCertificate[],
  anchors: readonly ParsedCertificate[],
): ParsedCertificate[] {
  const accepted: ParsedCertificate[] = [];
  let pending: ParsedCertificate[] = [];
  for (const cert of embedded) {
    if (anchors.some((anchor) => bytesEqual(anchor.raw, cert.raw))) {
      accepted.push(cert);
    } else {
      pending.push(cert);
    }
  }
  let issuers: readonly ParsedCertificate[] = [...anchors, ...accepted];
  for (let round = 0; round < MAX_PATH_LENGTH && pending.length > 0; round++) {
    const acceptedThisRound: ParsedCertificate[] = [];
    pending = pending.filter((candidate) => {
      const ok = issuers.some((issuer) => issuedBy(candidate, issuer));
      if (ok) {
        acceptedThisRound.push(candidate);
      }
      return !ok;
    });
    if (acceptedThisRound.length === 0) {
      break;
    }
    accepted.push(...acceptedThisRound);
    issuers = acceptedThisRound;
  }
  return accepted;
}

/**
 * Builds a path from `target` through `candidates` (the ones
 * {@link authenticatedTopDown} accepted) to one of the pinned `anchors`, the
 * shape a legacy receipt uses; then checks every certificate on it is
 * inside its validity window at `atMs`. Returns the path, target first,
 * anchor excluded.
 */
export function buildAndValidatePath(
  target: ParsedCertificate,
  candidates: readonly ParsedCertificate[],
  anchors: readonly ParsedCertificate[],
  atMs: number,
): ParsedCertificate[] {
  const path: ParsedCertificate[] = [target];
  let current = target;
  for (;;) {
    if (path.length > 1 && !current.isCa) {
      throw new VerificationError(Reason.UNTRUSTED_CHAIN, 'an intermediate is not a CA');
    }
    if (issuedByAnyAnchor(current, anchors)) {
      break;
    }
    if (path.length >= MAX_PATH_LENGTH) {
      throw new VerificationError(Reason.UNTRUSTED_CHAIN, 'chain exceeds the maximum length');
    }
    const issuer = candidates.find((c) => !path.includes(c) && issuedBy(current, c));
    if (issuer === undefined) {
      throw new VerificationError(Reason.UNTRUSTED_CHAIN, 'chain does not reach a pinned root');
    }
    path.push(issuer);
    current = issuer;
  }
  if (path.some((c) => !validAt(c, atMs))) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE,
      'certificate is outside its validity window at the chain instant',
    );
  }
  // The leaf is the first certificate on the path; the anchor is not on it.
  if (path.some((c, index) => hasUnprocessedCriticalExtension(c, index === 0))) {
    throw unprocessedCriticalExtension();
  }
  return path;
}
