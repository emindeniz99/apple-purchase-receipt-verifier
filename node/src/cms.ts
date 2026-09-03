/**
 * CMS/PKCS#7 SignedData structure walking for legacy app receipts — the part
 * of receipt verification that is pure DER work, shared by both entry points
 * so the two builds cannot disagree about what a receipt says. Bytes in,
 * bytes out: the crypto lives in the entry points.
 */
import { Reason, VerificationError } from './errors.js';
import { bytesEqual, concatBytes, toHex } from './bytes.js';
import {
  ParseError, Tag, encodeOidContents, isOctetString, octetStringValue, parse, tbsParts,
  type ASN1Node,
} from './der.js';

const OID_SIGNED_DATA = encodeOidContents('1.2.840.113549.1.7.2');
const OID_MESSAGE_DIGEST = encodeOidContents('1.2.840.113549.1.9.4');

// Only the digests Apple uses for receipts (SHA-1 / SHA-256), matching the
// other three implementations; anything else is rejected.
const DIGEST_ALGORITHMS = new Map<string, string>([
  ['1.3.14.3.2.26', 'sha1'],
  ['2.16.840.1.101.3.4.2.1', 'sha256'],
].map(([oid, name]) => [toHex(encodeOidContents(oid!)), name!]));

export interface CmsSignerInfo {
  issuerRaw: Uint8Array;
  serialContents: Uint8Array;
  /** 'sha1' | 'sha256' — the digest the signature is over. */
  digest: string;
  signedAttrs: ASN1Node | null;
  signature: Uint8Array;
}

export interface ParsedCms {
  content: Uint8Array;
  certificates: Uint8Array[];
  signerInfo: CmsSignerInfo;
}

function children(node: ASN1Node): ASN1Node[] {
  return node.children ?? [];
}

export function parseCms(der: Uint8Array): ParsedCms {
  let contentInfo: ASN1Node;
  try {
    contentInfo = parse(der);
  } catch (cause) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'not parseable ASN.1', cause);
  }
  try {
    const info = children(contentInfo);
    if (contentInfo.tag !== Tag.SEQUENCE
      || !bytesEqual(info[0]!.contents, OID_SIGNED_DATA)
      || info[1]!.tag !== Tag.CONTEXT_0) {
      throw new ParseError('not a CMS SignedData');
    }
    const signedData = children(children(info[1]!)[0]!);
    const encap = children(signedData[2]!);
    if (encap.length < 2 || encap[1]!.tag !== Tag.CONTEXT_0) {
      throw new ParseError('no encapsulated payload');
    }
    const contentNode = children(encap[1]!)[0]!;
    if (!isOctetString(contentNode)) {
      throw new ParseError('encapsulated payload is not an OCTET STRING');
    }
    const content = octetStringValue(contentNode);

    let certificates: Uint8Array[] = [];
    for (const child of signedData.slice(3, signedData.length - 1)) {
      if (child.tag === Tag.CONTEXT_0) {
        certificates = children(child).map((c) => c.raw);
      }
    }
    const signerInfos = signedData[signedData.length - 1]!;
    if (signerInfos.tag !== Tag.SET || children(signerInfos).length === 0) {
      throw new ParseError('no signer info');
    }
    const signerInfo = parseSignerInfo(children(signerInfos)[0]!);
    return { content, certificates, signerInfo };
  } catch (cause) {
    if (cause instanceof VerificationError) {
      throw cause;
    }
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'malformed CMS structure', cause);
  }
}

function parseSignerInfo(node: ASN1Node): CmsSignerInfo {
  const fields = children(node);
  const sid = children(fields[1]!);
  const issuerRaw = sid[0]!.raw;
  const serialContents = sid[1]!.contents;
  const digestOidHex = toHex(children(fields[2]!)[0]!.contents);
  let index = 3;
  let signedAttrs: ASN1Node | null = null;
  if (fields[index]!.tag === Tag.CONTEXT_0) {
    signedAttrs = fields[index]!;
    index += 1;
  }
  index += 1; // signatureAlgorithm — RSA PKCS#1 v1.5 assumed, digest drives the hash
  const signature = fields[index]!.contents;
  const digest = DIGEST_ALGORITHMS.get(digestOidHex);
  if (!digest) {
    throw new ParseError('unsupported digest algorithm');
  }
  return { issuerRaw, serialContents, digest, signedAttrs, signature };
}

/**
 * Index of the embedded certificate the SignerInfo names by
 * issuerAndSerialNumber, or -1. Unparseable entries are skipped.
 */
export function findSignerCertIndex(cms: ParsedCms): number {
  for (let i = 0; i < cms.certificates.length; i++) {
    try {
      const { serialNumber, issuer } = tbsParts(cms.certificates[i]!);
      if (bytesEqual(serialNumber.contents, cms.signerInfo.serialContents)
        && bytesEqual(issuer.raw, cms.signerInfo.issuerRaw)) {
        return i;
      }
    } catch {
      // skip unparseable embedded certificate
    }
  }
  return -1;
}

export function findMessageDigestAttribute(signedAttrs: ASN1Node): Uint8Array | null {
  for (const attr of children(signedAttrs)) {
    // Every signed attribute is SEQUENCE { OID, SET OF value }; a shape that
    // is missing either part is a malformed structure rather than an
    // attribute we simply are not looking for.
    const [type, values] = children(attr);
    const value = values === undefined ? undefined : children(values)[0];
    if (type === undefined || value === undefined) {
      throw new ParseError('malformed signed attribute');
    }
    if (bytesEqual(type.contents, OID_MESSAGE_DIGEST)) {
      return value.contents;
    }
  }
  return null;
}

/**
 * The bytes a SignerInfo signature covers when signedAttrs are present:
 * the attributes re-encoded as an explicit SET (RFC 5652 §5.4) — swap the
 * IMPLICIT [0] tag for SET.
 */
export function signedAttrsSignedBytes(signedAttrs: ASN1Node): Uint8Array {
  return concatBytes([Uint8Array.of(Tag.SET), signedAttrs.raw.subarray(1)]);
}
