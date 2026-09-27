/**
 * Certificate path building and validation for the web build — the same
 * rules as the Node build's chain.ts, with `node:crypto` replaced by the
 * repo's own X.509 parsing plus `crypto.subtle`, and every step async
 * because `crypto.subtle.verify` is.
 *
 * A path is found top-down, from the pinned roots: a certificate's
 * signature is checked with the key of a certificate already vouched for,
 * never with the key of a certificate nobody has vouched for yet
 * (#161). Only once a path
 * reaches an anchor are the certificates on it checked for their validity
 * window.
 */
import { base64Decode, bytesEqual } from '../bytes.js';
import { Reason, VerificationError } from '../errors.js';
import { pemBody } from '../pem.js';
import { KEY_CERT_SIGN_BIT, parseCertificate, type ParsedCertificate } from '../x509.js';
import { verifyCertificateSignature } from './crypto.js';
import { requireBuildablePublicKey } from './jwk.js';

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
 * What `X509_check_issued` accepts, minus the parts that need a name
 * canonicaliser: the names chain by DER equality, the authority key
 * identifier agrees with the issuer's subject key identifier and serial
 * where it names them, and the issuer's keyUsage, if it has one, permits
 * keyCertSign.
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

async function issuedBy(cert: ParsedCertificate, issuer: ParsedCertificate): Promise<boolean> {
  return checkIssued(cert, issuer) && (await verifyCertificateSignature(cert, issuer));
}

async function issuedByAnyAnchor(
  cert: ParsedCertificate,
  anchors: readonly ParsedCertificate[],
): Promise<boolean> {
  for (const anchor of anchors) {
    // Deliberate short-circuit: stop at the first matching anchor rather
    // than running every remaining crypto.subtle.verify in parallel.
    // oxlint-disable-next-line no-await-in-loop
    if (await issuedBy(cert, anchor)) {
      return true;
    }
  }
  return false;
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
export async function validatePair(
  leaf: ParsedCertificate,
  intermediate: ParsedCertificate,
  anchors: readonly ParsedCertificate[],
  atMs: number,
): Promise<void> {
  if (!(await issuedByAnyAnchor(intermediate, anchors))) {
    throw new VerificationError(
      Reason.UNTRUSTED_CHAIN,
      'intermediate certificate is not signed by a pinned root',
    );
  }
  // Vouched for, and its key is about to check the leaf: an unbuildable key
  // is the certificate's defect, not a chain failure.
  requireBuildablePublicKey(intermediate.publicKeyAlgorithmOid, intermediate.spki);
  if (!(await issuedBy(leaf, intermediate))) {
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
 */
export async function authenticatedTopDown(
  embedded: readonly ParsedCertificate[],
  anchors: readonly ParsedCertificate[],
): Promise<ParsedCertificate[]> {
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
    const stillPending: ParsedCertificate[] = [];
    for (const candidate of pending) {
      let ok = false;
      for (const issuer of issuers) {
        // oxlint-disable-next-line no-await-in-loop
        if (await issuedBy(candidate, issuer)) {
          ok = true;
          break;
        }
      }
      (ok ? acceptedThisRound : stillPending).push(candidate);
    }
    pending = stillPending;
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
 * {@link authenticatedTopDown} accepted) to one of the pinned `anchors`;
 * then checks every certificate on it is inside its validity window at
 * `atMs`. Returns the path, target first, anchor excluded.
 */
export async function buildAndValidatePath(
  target: ParsedCertificate,
  candidates: readonly ParsedCertificate[],
  anchors: readonly ParsedCertificate[],
  atMs: number,
): Promise<ParsedCertificate[]> {
  const path: ParsedCertificate[] = [target];
  let current = target;
  for (;;) {
    if (path.length > 1 && !current.isCa) {
      throw new VerificationError(Reason.UNTRUSTED_CHAIN, 'an intermediate is not a CA');
    }
    // oxlint-disable-next-line no-await-in-loop
    if (await issuedByAnyAnchor(current, anchors)) {
      break;
    }
    if (path.length >= MAX_PATH_LENGTH) {
      throw new VerificationError(Reason.UNTRUSTED_CHAIN, 'chain exceeds the maximum length');
    }
    let issuer: ParsedCertificate | undefined;
    for (const candidate of candidates) {
      if (path.includes(candidate)) {
        continue;
      }
      // oxlint-disable-next-line no-await-in-loop
      if (await issuedBy(current, candidate)) {
        issuer = candidate;
        break;
      }
    }
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
