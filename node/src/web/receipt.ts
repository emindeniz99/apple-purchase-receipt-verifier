/**
 * `verifyReceipt(base64)` for the web build — the same algorithm as the
 * Node build's receipt.ts, async because `crypto.subtle` is.
 */
import { base64Decode, bytesEqual, isCanonicalBase64, timingSafeBytesEqual } from '../bytes.js';
import { callClock } from '../call-clock.js';
import {
  parseCms,
  requireAttributeSetSyntax,
  signedAttributeValues,
  signedAttrsSignedBytes,
  type CmsSignerInfo,
  type ParsedCms,
} from '../cms.js';
import { parse as parseAsn1, ParseError, Tag } from '../der.js';
import { Reason, VerificationError } from '../errors.js';
import { MAX_RECEIPT_BYTES, utf8LengthExceeds } from '../limits.js';
import { parseReceiptPayload, readCreationDate, type ReceiptPayload } from '../receipt-payload.js';
import { parseCertificate, type ParsedCertificate } from '../x509.js';
import { authenticatedTopDown, buildAndValidatePath } from './chain.js';
import { digest, nodeDigestNameForOid, verifySignerSignature } from './crypto.js';
import { requireBuildablePublicKey } from './jwk.js';

export { MAX_RECEIPT_BYTES };

const RECEIPT_SIGNER_OID = '1.2.840.113635.100.6.11.1';
const WWDR_INTERMEDIATE_OID = '1.2.840.113635.100.6.2.1';
const MAX_EMBEDDED_CERTIFICATES = 10;
const MAX_SIGNER_INFOS = 4;

function describeError(e: unknown): string {
  if (e instanceof Error) {
    return e.constructor.name;
  }
  return typeof e;
}

/** Decodes the base64 text a client sends as `receipt-data`, Apple's own rule. */
export function decodeReceiptBase64(receipt: string): Uint8Array {
  if (!isCanonicalBase64(receipt)) {
    throw new VerificationError(
      Reason.MALFORMED,
      'receipt is not canonically padded standard base64',
    );
  }
  return base64Decode(receipt);
}

export async function verifyReceipt(
  base64: string,
  anchors: readonly ParsedCertificate[],
  now: () => number,
): Promise<ReceiptPayload> {
  if (base64 === '') {
    throw new VerificationError(Reason.MALFORMED, 'receipt is empty');
  }
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
    content = await verifySignature(der, anchors, clock);
  } catch (cause) {
    if (cause instanceof VerificationError) {
      throw cause;
    }
    throw new VerificationError(
      Reason.MALFORMED,
      `unexpected error: ${describeError(cause)}`,
      cause,
    );
  }
  try {
    return parseReceiptPayload(content);
  } catch (cause) {
    throw new VerificationError(
      Reason.UNREADABLE_PAYLOAD,
      'signed receipt content could not be read',
      cause,
    );
  }
}

async function verifySignature(
  der: Uint8Array,
  anchors: readonly ParsedCertificate[],
  now: () => number,
): Promise<Uint8Array> {
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
  if (cms.certificateEntries.length > MAX_EMBEDDED_CERTIFICATES) {
    throw new VerificationError(
      Reason.MALFORMED,
      `receipt embeds ${cms.certificateEntries.length} certificates, more than the maximum of ${MAX_EMBEDDED_CERTIFICATES}`,
    );
  }

  const creationDate = readCreationDate(cms.content);
  const embedded = decodeEmbedded(cms.certificateEntries);
  let authenticated: ParsedCertificate[] | null = null;
  let firstFailure: VerificationError | null = null;
  for (const info of cms.signerInfos) {
    try {
      const candidates = signerCertificates(info, embedded);
      const atMs = creationDate ?? now();
      // oxlint-disable-next-line no-await-in-loop
      authenticated ??= await authenticatedTopDown(embedded.decoded, anchors);
      // The certificate bag is unsigned, so more than one embedded
      // certificate can carry the signer's issuer and serial: a twin on
      // another key, self-signed, ahead of the genuine one. Each match is
      // tried the way the SignerInfos already are: one passing is enough,
      // and only when none does is the first match's failure the verdict.
      let firstMatchFailure: VerificationError | undefined;
      for (const signer of candidates) {
        try {
          // oxlint-disable-next-line no-await-in-loop
          await verifySigner(cms, info, signer, authenticated, anchors, atMs);
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
 * tries each.
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

async function verifySigner(
  cms: ParsedCms,
  info: CmsSignerInfo,
  signer: ParsedCertificate,
  authenticated: readonly ParsedCertificate[],
  anchors: readonly ParsedCertificate[],
  atMs: number,
): Promise<void> {
  const path = await buildAndValidatePath(signer, authenticated, anchors, atMs);
  if (!signer.hasExtension(RECEIPT_SIGNER_OID)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE_PURPOSE,
      `receipt signer certificate lacks Apple receipt-signing marker OID ${RECEIPT_SIGNER_OID}`,
    );
  }
  const intermediate = path[1];
  if (intermediate === undefined || !intermediate.hasExtension(WWDR_INTERMEDIATE_OID)) {
    throw new VerificationError(
      Reason.INVALID_CERTIFICATE_PURPOSE,
      `receipt intermediate certificate lacks Apple WWDR marker OID ${WWDR_INTERMEDIATE_OID}`,
    );
  }
  requireBuildablePublicKey(signer.publicKeyAlgorithmOid, signer.spki);
  await verifyCmsSignature(cms, info, signer);
}

async function verifyCmsSignature(
  cms: ParsedCms,
  info: CmsSignerInfo,
  signer: ParsedCertificate,
): Promise<void> {
  let signedBytes: Uint8Array;
  if (info.signedAttrs !== null) {
    const digestName = nodeDigestNameForOid(info.digestAlgorithmOid);
    if (digestName === null) {
      throw new VerificationError(Reason.INVALID_SIGNATURE, 'unsupported digest algorithm');
    }
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
    if (duplicate) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'signedAttrs carry a contentType or messageDigest attribute twice',
      );
    }
    if (!bytesEqual(contentTypeValue, cms.contentType)) {
      throw new VerificationError(
        Reason.INVALID_SIGNATURE,
        'contentType attribute differs from the eContentType',
      );
    }
    const contentDigest = await digest(digestName, cms.content);
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
  const valid = await verifySignerSignature(
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
