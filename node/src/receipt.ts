/**
 * `verifyReceipt(base64)`: legacy PKCS#7 app receipts, verified offline
 * against the pinned roots.
 *
 * Checks, in order: strict base64, the CMS envelope, the chain to a pinned
 * root walked top-down (docs/design/0.7-hardening-parity.md change 1,
 * #161), Apple's marker OIDs on both the leaf (receipt signing) and the
 * WWDR intermediate, certificate validity at the receipt's creation date,
 * and last the signature. Several SignerInfos: the receipt verifies when at
 * least one verifies under a pinned chain; when none does, the first
 * SignerInfo's failure is the verdict.
 */
import { createHash } from 'node:crypto';
import { base64Decode, isCanonicalBase64, timingSafeBytesEqual } from './bytes.js';
import { callClock } from './call-clock.js';
import { authenticatedTopDown, buildAndValidatePath } from './chain.js';
import {
  parseCms,
  requireAttributeSetSyntax,
  signedAttributeValues,
  signedAttrsSignedBytes,
  type CmsSignerInfo,
  type ParsedCms,
} from './cms.js';
import { digestForOid, requireBuildablePublicKey, verifySignerSignature } from './crypto.js';
import { ParseError } from './der.js';
import { Reason, VerificationError } from './errors.js';
import { MAX_RECEIPT_BYTES, utf8LengthExceeds } from './limits.js';
import { parseReceiptPayload, readCreationDate, type ReceiptPayload } from './receipt-payload.js';
import { parse as parseAsn1, Tag } from './der.js';
import { bytesEqual } from './bytes.js';
import { parseCertificate, type ParsedCertificate } from './x509.js';

export { MAX_RECEIPT_BYTES };

const RECEIPT_SIGNER_OID = '1.2.840.113635.100.6.11.1';
const WWDR_INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';
const MAX_EMBEDDED_CERTIFICATES = 10;
const MAX_SIGNER_INFOS = 4;

/**
 * Names only the exception's class (docs/design/0.7-hardening-parity.md
 * change 6: "catch-all guards name only the exception class"), never its
 * message: an unexpected error here runs on input nobody has vouched for,
 * so its message may itself quote that input.
 */
function describeError(e: unknown): string {
  if (e instanceof Error) {
    return e.constructor.name;
  }
  return typeof e;
}

/**
 * Decodes the base64 text a client sends as `receipt-data`, the rule
 * Apple's verifyReceipt applies: non-empty, standard alphabet, exactly the
 * canonical `=` padding, nothing else. Exported so a decodeBase64
 * conformance case can reach it directly.
 */
export function decodeReceiptBase64(receipt: string): Uint8Array {
  if (!isCanonicalBase64(receipt)) {
    throw new VerificationError(
      Reason.MALFORMED,
      'receipt is not canonically padded standard base64',
    );
  }
  return base64Decode(receipt);
}

export function verifyReceipt(
  base64: string,
  anchors: readonly ParsedCertificate[],
  now: () => number,
): ReceiptPayload {
  if (base64 === '') {
    throw new VerificationError(Reason.MALFORMED, 'receipt is empty');
  }
  // Before the decode, which would otherwise allocate the bytes it decodes to.
  if (utf8LengthExceeds(base64, MAX_RECEIPT_BYTES)) {
    throw new VerificationError(
      Reason.TOO_LARGE,
      `receipt exceeds the maximum accepted size of ${MAX_RECEIPT_BYTES} bytes`,
    );
  }
  const der = decodeReceiptBase64(base64);
  const clock = callClock(now);
  let content: Uint8Array;
  try {
    content = verifySignature(der, anchors, clock);
  } catch (cause) {
    if (cause instanceof VerificationError) {
      throw cause;
    }
    // Contains any unexpected error before the signature has verified
    // (docs/design/0.7-hardening-parity.md change 4): everything up to here
    // runs on input nobody has vouched for, so it is MALFORMED, never
    // INTERNAL_ERROR, which would let anyone raise that alert at will.
    throw new VerificationError(
      Reason.MALFORMED,
      `unexpected error: ${describeError(cause)}`,
      cause,
    );
  }
  try {
    return parseReceiptPayload(content);
  } catch (cause) {
    // A trusted signer signed these bytes, so a payload this library
    // cannot read is the library's failure or a format Apple added, not
    // the client's.
    throw new VerificationError(
      Reason.UNREADABLE_PAYLOAD,
      'signed receipt content could not be read',
      cause,
    );
  }
}

/** Every check up to and including a signature; returns the signed payload, not yet decoded. */
function verifySignature(
  der: Uint8Array,
  anchors: readonly ParsedCertificate[],
  now: () => number,
): Uint8Array {
  let cms: ParsedCms;
  try {
    cms = parseCms(der);
  } catch (cause) {
    if (cause instanceof ParseError) {
      throw new VerificationError(
        Reason.MALFORMED,
        `malformed CMS structure: ${cause.message}`,
        cause,
      );
    }
    throw cause;
  }
  if (cms.signerInfos.length === 0) {
    throw new VerificationError(Reason.MALFORMED, 'no signer info');
  }
  if (cms.signerInfos.length > MAX_SIGNER_INFOS) {
    throw new VerificationError(
      Reason.MALFORMED,
      `receipt carries ${cms.signerInfos.length} SignerInfos, more than the maximum of ${MAX_SIGNER_INFOS}`,
    );
  }
  // Judged for every SignerInfo before any key is used, so a malformed
  // signedAttrs is MALFORMED regardless of signer order.
  for (const info of cms.signerInfos) {
    if (info.signedAttrs !== null) {
      try {
        requireAttributeSetSyntax(info.signedAttrs);
      } catch (cause) {
        if (cause instanceof ParseError) {
          throw new VerificationError(Reason.MALFORMED, cause.message, cause);
        }
        throw cause;
      }
    }
  }
  // Bounded before a single embedded certificate is decoded, all of which
  // an unverified receipt would otherwise get to pay for out of the
  // caller's CPU.
  if (cms.certificateEntries.length > MAX_EMBEDDED_CERTIFICATES) {
    throw new VerificationError(
      Reason.MALFORMED,
      `receipt embeds ${cms.certificateEntries.length} certificates, more than the maximum of ${MAX_EMBEDDED_CERTIFICATES}`,
    );
  }

  // Only the creation date is read before trust is established, because
  // chain validity is anchored at signing time; nothing else in the
  // payload is decoded until the chain and a signature have passed.
  const creationDate = readCreationDate(cms.content);

  const embedded = decodeEmbedded(cms.certificateEntries);
  // Signer-independent, so walked once for all SignerInfos, and only once
  // one of them has named an embedded certificate that decodes.
  let authenticated: ParsedCertificate[] | null = null;
  let firstFailure: VerificationError | null = null;
  for (const info of cms.signerInfos) {
    try {
      const candidates = signerCertificates(info, embedded);
      const atMs = creationDate ?? now();
      authenticated ??= authenticatedTopDown(embedded.decoded, anchors);
      // The certificate bag is unsigned, so more than one embedded
      // certificate can carry the signer's issuer and serial: a twin on
      // another key, self-signed, ahead of the genuine one. Each match is
      // tried the way the SignerInfos already are: one passing is enough,
      // and only when none does is the first match's failure the verdict.
      let firstMatchFailure: VerificationError | undefined;
      for (const signer of candidates) {
        try {
          verifySigner(cms, info, signer, authenticated, anchors, atMs);
          return cms.content;
        } catch (matchCause) {
          if (!(matchCause instanceof VerificationError)) {
            throw matchCause;
          }
          firstMatchFailure ??= matchCause;
        }
      }
      throw (
        firstMatchFailure ??
        new VerificationError(Reason.MALFORMED, 'signer certificate not embedded')
      );
    } catch (cause) {
      if (!(cause instanceof VerificationError)) {
        throw cause;
      }
      // Every SignerInfo signs the same content, so another one passing
      // proves the same bytes; only when none does is the first one's
      // failure the verdict.
      firstFailure ??= cause;
    }
  }
  throw firstFailure ?? new VerificationError(Reason.MALFORMED, 'no signer info');
}

interface EmbeddedCertificates {
  decoded: ParsedCertificate[];
  unreadable: Uint8Array[];
}

function decodeEmbedded(entries: readonly Uint8Array[]): EmbeddedCertificates {
  const decoded: ParsedCertificate[] = [];
  const unreadable: Uint8Array[] = [];
  for (const raw of entries) {
    try {
      decoded.push(parseCertificate(raw));
    } catch {
      unreadable.push(raw);
    }
  }
  return { decoded, unreadable };
}

/**
 * Whether `raw` carries the issuer Name and serialNumber `info` names, read
 * as generic ASN.1 because the entries asked about are the ones
 * {@link parseCertificate} refused.
 */
function namesTheSigner(raw: Uint8Array, info: CmsSignerInfo): boolean {
  try {
    const certificate = parseAsn1(raw);
    if (certificate.tag !== Tag.SEQUENCE) {
      return false;
    }
    const tbs = certificate.children?.[0];
    if (tbs?.tag !== Tag.SEQUENCE) {
      return false;
    }
    const fields = tbs.children ?? [];
    const index = fields[0]?.tag === Tag.CONTEXT_0 ? 1 : 0;
    const serial = fields[index];
    const issuer = fields[index + 2];
    if (serial?.tag !== Tag.INTEGER || issuer?.tag !== Tag.SEQUENCE) {
      return false;
    }
    return (
      bytesEqual(serial.contents, info.serialContents) && bytesEqual(issuer.raw, info.issuerRaw)
    );
  } catch {
    return false;
  }
}

/**
 * Every embedded certificate carrying the issuer and serial `info` names, in
 * bag order and never empty, or the verdict for the bag. The bag is
 * unsigned, so more than one can match: a certificate with the signer's
 * identity on another key can sit ahead of the genuine one, and the caller
 * tries each. The signer's own entry not decoding is INVALID_CERTIFICATE, as
 * an unreadable x5c entry is on the JWS path; any other entry not decoding
 * is MALFORMED, because the bag is unsigned. A broken signer outranks a
 * broken stranger.
 */
function signerCertificates(
  info: CmsSignerInfo,
  embedded: EmbeddedCertificates,
): ParsedCertificate[] {
  for (const raw of embedded.unreadable) {
    if (namesTheSigner(raw, info)) {
      throw new VerificationError(
        Reason.INVALID_CERTIFICATE,
        'receipt signer certificate does not decode',
      );
    }
  }
  if (embedded.unreadable.length > 0) {
    throw new VerificationError(
      Reason.MALFORMED,
      'an embedded certificate is not a valid certificate',
    );
  }
  const matches = embedded.decoded.filter(
    (c) =>
      bytesEqual(c.serialNumber, info.serialContents) && bytesEqual(c.issuerDer, info.issuerRaw),
  );
  if (matches.length === 0) {
    throw new VerificationError(Reason.MALFORMED, 'signer certificate not embedded');
  }
  return matches;
}

function verifySigner(
  cms: ParsedCms,
  info: CmsSignerInfo,
  signer: ParsedCertificate,
  authenticated: readonly ParsedCertificate[],
  anchors: readonly ParsedCertificate[],
  atMs: number,
): void {
  const path = buildAndValidatePath(signer, authenticated, anchors, atMs);
  // Checked after the chain, so a foreign chain still reports
  // UNTRUSTED_CHAIN rather than INVALID_CERTIFICATE_PURPOSE.
  if (!signer.hasExtension(RECEIPT_SIGNER_OID)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE_PURPOSE,
      `receipt signer certificate lacks Apple receipt-signing marker OID ${RECEIPT_SIGNER_OID}`,
    );
  }
  // The certificate after the signer on the path. A signer issued straight
  // by a root has no WWDR certificate to carry the marker.
  const intermediate = path[1];
  if (intermediate === undefined || !intermediate.hasExtension(WWDR_INTERMEDIATE_OID)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE_PURPOSE,
      `receipt intermediate certificate lacks Apple WWDR marker OID ${WWDR_INTERMEDIATE_OID}`,
    );
  }
  // The signer's key is about to check the CMS signature; judged only
  // once the chain has vouched for it.
  requireBuildablePublicKey(signer);
  // The chain is checked BEFORE the signature on purpose: checking the
  // signature first would run the attacker's own key (their choice of RSA
  // size and exponent) before anything about it is trusted.
  verifyCmsSignature(cms, info, signer);
}

/**
 * No algorithm or key-type allowlist beyond what `node:crypto` implements:
 * the signer is already pinned to an Apple root and carries Apple's
 * receipt-signing marker, so a change of algorithm on Apple's side does not
 * reject genuine receipts (docs/design/0.7-hardening-parity.md change 3).
 */
function verifyCmsSignature(cms: ParsedCms, info: CmsSignerInfo, signer: ParsedCertificate): void {
  let signedBytes: Uint8Array;
  if (info.signedAttrs !== null) {
    const digest = digestForOid(info.digestAlgorithmOid);
    if (digest === null) {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'unsupported digest algorithm');
    }
    // RFC 5652 §5.3: contentType and messageDigest are mandatory whenever
    // signedAttrs are present. A set missing either cannot be checked, so
    // it fails as a signature rather than as a format defect: genuine
    // receipts carry no signedAttrs, and only this check refuses a forgery
    // that copies the content under a re-tagged signedAttrs SET.
    const { messageDigest, contentTypeValue, duplicate } = signedAttributeValues(info.signedAttrs);
    if (contentTypeValue === null) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'signedAttrs lack a contentType attribute',
      );
    }
    if (messageDigest === null) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'signedAttrs lack a messageDigest attribute',
      );
    }
    // RFC 5652 §11: at most one instance of each attribute; a duplicate
    // makes which copy the signer meant ambiguous, so it is refused before
    // either value is trusted.
    if (duplicate) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'signedAttrs carry a contentType or messageDigest attribute twice',
      );
    }
    // RFC 5652 §11.1: the contentType attribute names the content the
    // signature covers, so one that names another type is a signature over
    // something else.
    if (!bytesEqual(contentTypeValue, cms.contentType)) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'contentType attribute differs from the eContentType',
      );
    }
    const contentDigest = createHash(digest).update(cms.content).digest();
    if (!timingSafeBytesEqual(messageDigest, contentDigest)) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'messageDigest attribute does not match content',
      );
    }
    signedBytes = signedAttrsSignedBytes(info.signedAttrs.raw);
  } else {
    signedBytes = cms.content;
  }
  const valid = verifySignerSignature(
    signer.spki,
    signer.publicKeyAlgorithmOid,
    info.digestAlgorithmOid,
    info.signatureAlgorithmOid,
    info.signatureAlgorithmParams,
    info.signature,
    signedBytes,
  );
  if (!valid) {
    throw new VerificationError(
      Reason.INVALID_SIGNATURE,
      "CMS signature does not match the signer certificate's key",
    );
  }
}
