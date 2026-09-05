/**
 * Chain building and validation for the web build — the same rules as the
 * Node build's chain.ts, with the OpenSSL calls replaced by the repo's own
 * X.509 parsing plus `crypto.subtle`, and every step async because
 * `crypto.subtle.verify` is.
 *
 * `issuedBy` reproduces what `X509Certificate.checkIssued()` (OpenSSL's
 * X509_check_issued) accepts: the names chain, the authority key identifier
 * agrees with the issuer's subject key identifier and serial when it names
 * them, and the issuer's keyUsage — if it has one — permits keyCertSign.
 *
 * One deliberate difference: names are compared as DER bytes, where OpenSSL
 * compares canonical forms (case- and whitespace-folded). A chain whose
 * issuer and subject names differ only in encoding would be rejected here
 * and accepted there. That is the safe direction, and no chain in the
 * fixture suite — Apple's production roots included — encodes them
 * differently, which the verdict-parity tests are what prove.
 */
import { Reason, VerificationError } from '../errors.js';
import { base64Decode, bytesEqual } from '../bytes.js';
import { KEY_CERT_SIGN_BIT, parseCertificate, type ParsedCertificate } from '../x509.js';
import { verifyCertificateSignature } from './crypto.js';

/** Accepted trust-root inputs: DER bytes, or a PEM certificate. */
export type RootInput = Uint8Array | string;

const PEM_BODY = /-----BEGIN CERTIFICATE-----([\s\S]*?)-----END CERTIFICATE-----/;

/** Normalizes trust-root inputs (DER Uint8Array | PEM string). */
export function normalizeRoots(trustedRoots: RootInput[]): ParsedCertificate[] {
  if (!Array.isArray(trustedRoots) || trustedRoots.length === 0) {
    throw new TypeError('trustedRoots must be a non-empty array');
  }
  return trustedRoots.map(toCertificate);
}

function toCertificate(root: RootInput): ParsedCertificate {
  if (typeof root !== 'string') {
    return parseCertificate(root);
  }
  const body = PEM_BODY.exec(root);
  if (body === null) {
    throw new TypeError('a string trust root must be a PEM certificate');
  }
  return parseCertificate(base64Decode(body[1]!));
}

function validAt(cert: ParsedCertificate, at: Date): boolean {
  return cert.notBefore <= at.getTime() && at.getTime() <= cert.notAfter;
}

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

async function anyIssued(cert: ParsedCertificate, anchors: ParsedCertificate[]): Promise<boolean> {
  for (const anchor of anchors) {
    // Deliberate short-circuit: stop at the first matching anchor rather than
    // running every remaining crypto.subtle.verify in parallel once a match
    // is already found.
    // oxlint-disable-next-line no-await-in-loop
    if (await issuedBy(cert, anchor)) {
      return true;
    }
  }
  return false;
}

/**
 * Validates the fixed JWS path leaf → intermediate → (pinned anchor):
 * validity windows at `at`, CA flag on the intermediate, and signature +
 * name chaining at each step. Anchors are trusted by fiat (their own
 * expiry is not checked — standard PKIX trust-anchor semantics).
 */
export async function validatePair(
  leaf: ParsedCertificate,
  intermediate: ParsedCertificate,
  anchors: ParsedCertificate[],
  at: Date,
): Promise<void> {
  if (!validAt(leaf, at) || !validAt(intermediate, at)) {
    throw new VerificationError(Reason.INVALID_CHAIN, 'certificate not valid at signing time');
  }
  if (!intermediate.isCa) {
    throw new VerificationError(Reason.INVALID_CHAIN, 'intermediate is not a CA');
  }
  if (!(await issuedBy(leaf, intermediate))) {
    throw new VerificationError(Reason.INVALID_CHAIN, 'leaf not issued by intermediate');
  }
  if (!(await anyIssued(intermediate, anchors))) {
    throw new VerificationError(Reason.INVALID_CHAIN, 'intermediate not issued by a pinned root');
  }
}

const MAX_PATH_LENGTH = 6;

/**
 * Builds and validates a path from `target` through `candidates` to one of
 * the pinned `anchors` (receipt chains embed their intermediates in the CMS).
 */
export async function buildAndValidatePath(
  target: ParsedCertificate,
  candidates: ParsedCertificate[],
  anchors: ParsedCertificate[],
  at: Date,
): Promise<void> {
  let current = target;
  for (let depth = 0; depth < MAX_PATH_LENGTH; depth++) {
    if (!validAt(current, at)) {
      throw new VerificationError(Reason.INVALID_CHAIN, 'certificate not valid at signing time');
    }
    if (depth > 0 && !current.isCa) {
      throw new VerificationError(Reason.INVALID_CHAIN, 'intermediate is not a CA');
    }
    // Deliberate short-circuit, as in anyIssued above.
    // oxlint-disable-next-line no-await-in-loop
    if (await anyIssued(current, anchors)) {
      return;
    }
    let issuer: ParsedCertificate | undefined;
    for (const candidate of candidates) {
      // Same short-circuit: stop at the first candidate that issued `current`
      // rather than checking every remaining one.
      // oxlint-disable-next-line no-await-in-loop
      if (candidate !== current && (await issuedBy(current, candidate))) {
        issuer = candidate;
        break;
      }
    }
    if (!issuer) {
      throw new VerificationError(Reason.INVALID_CHAIN, 'chain does not reach a pinned root');
    }
    current = issuer;
  }
  throw new VerificationError(Reason.INVALID_CHAIN, 'chain exceeds maximum length');
}
