/**
 * CMS/PKCS#7 SignedData structure walking for legacy app receipts — the part
 * of receipt verification that is pure DER work, shared by both entry
 * points and both builds so they cannot disagree about what a receipt says.
 * Bytes in, bytes and OIDs out: no cryptography lives here (see crypto.ts /
 * web/crypto.ts).
 */
import { bytesEqual, concatBytes } from './bytes.js';
import { ParseError, Tag, isOctetString, octetStringValue, parse, type ASN1Node } from './der.js';
import { oidString } from './x509.js';

const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';
const OID_MESSAGE_DIGEST = '1.2.840.113549.1.9.4';
const OID_CONTENT_TYPE = '1.2.840.113549.1.9.3';

export interface CmsSignerInfo {
  /** issuerAndSerialNumber.issuer, the Name TLV — matches an embedded certificate's issuerDer. */
  issuerRaw: Uint8Array;
  serialContents: Uint8Array;
  digestAlgorithmOid: string;
  signatureAlgorithmOid: string;
  /** The signatureAlgorithm's parameters TLV (needed for RSASSA-PSS), or null. */
  signatureAlgorithmParams: ASN1Node | null;
  /** signedAttrs [0] IMPLICIT, re-tagged as a SET so its children are the attribute SEQUENCEs; null when absent. */
  signedAttrs: ASN1Node | null;
  signature: Uint8Array;
}

export interface ParsedCms {
  content: Uint8Array;
  /** eContentType OID contents octets — what a signedAttrs contentType attribute must match. */
  contentType: Uint8Array;
  /** Raw TLV bytes of every embedded certificate entry, decoded or not. */
  certificateEntries: Uint8Array[];
  signerInfos: CmsSignerInfo[];
}

function children(node: ASN1Node): ASN1Node[] {
  return node.children ?? [];
}

function malformed(message: string): never {
  throw new ParseError(message);
}

export function parseCms(der: Uint8Array): ParsedCms {
  const contentInfo = parse(der);
  const info = children(contentInfo);
  if (
    contentInfo.tag !== Tag.SEQUENCE ||
    info[0]?.tag !== 0x06 /* OID */ ||
    oidString(info[0].contents) !== OID_SIGNED_DATA ||
    info[1]?.tag !== Tag.CONTEXT_0
  ) {
    malformed('not a CMS SignedData');
  }
  const signedDataOuter = children(info[1]!)[0];
  if (signedDataOuter === undefined || signedDataOuter.tag !== Tag.SEQUENCE) {
    malformed('not a CMS SignedData');
  }
  const signedData = children(signedDataOuter);
  if (signedData.length < 5) {
    malformed('malformed SignedData');
  }
  const encap = children(signedData[2]!);
  if (
    signedData[2]!.tag !== Tag.SEQUENCE ||
    encap.length < 2 ||
    encap[0]?.tag !== 0x06 /* OID */ ||
    encap[1]!.tag !== Tag.CONTEXT_0
  ) {
    malformed('no encapsulated payload');
  }
  const contentType = encap[0]!.contents;
  const contentNode = children(encap[1]!)[0];
  if (contentNode === undefined || !isOctetString(contentNode)) {
    malformed('encapsulated payload is not an OCTET STRING');
  }
  const content = octetStringValue(contentNode);

  let certificateEntries: Uint8Array[] = [];
  let signerInfosNode: ASN1Node | undefined;
  for (const field of signedData.slice(3)) {
    if (field.tag === Tag.CONTEXT_0) {
      certificateEntries = children(field).map((c) => c.raw);
    } else if (field.tag === Tag.SET) {
      signerInfosNode = field;
    }
  }
  if (signerInfosNode === undefined) {
    malformed('no SignerInfos');
  }
  const signerInfos = children(signerInfosNode).map(parseSignerInfo);
  return { content, contentType, certificateEntries, signerInfos };
}

function algorithmIdentifier(node: ASN1Node): { oid: string; params: ASN1Node | null } {
  const parts = children(node);
  if (node.tag !== Tag.SEQUENCE || parts[0]?.tag !== 0x06) {
    malformed('malformed AlgorithmIdentifier');
  }
  return { oid: oidString(parts[0]!.contents), params: parts[1] ?? null };
}

function parseSignerInfo(node: ASN1Node): CmsSignerInfo {
  const fields = children(node);
  if (node.tag !== Tag.SEQUENCE || fields.length < 5) {
    malformed('malformed SignerInfo');
  }
  const sid = children(fields[1]!);
  if (fields[1]!.tag !== Tag.SEQUENCE || sid[0]?.tag !== Tag.SEQUENCE || sid[1]?.tag !== 0x02) {
    malformed('SignerInfo sid is not issuerAndSerialNumber');
  }
  const issuerRaw = sid[0]!.raw;
  const serialContents = sid[1]!.contents;
  const digest = algorithmIdentifier(fields[2]!);
  let index = 3;
  let signedAttrs: ASN1Node | null = null;
  if (fields[index]?.tag === Tag.CONTEXT_0) {
    // Re-tagged as an explicit SET (RFC 5652 §5.4) so its children read the
    // same way a signedAttrs SET OF Attribute would.
    signedAttrs = {
      tag: Tag.SET,
      constructed: true,
      raw: fields[index]!.raw,
      contents: fields[index]!.contents,
      children: fields[index]!.children,
    };
    index += 1;
  }
  const signatureAlgorithm = fields[index];
  if (signatureAlgorithm === undefined) {
    malformed('malformed SignerInfo');
  }
  const sigAlg = algorithmIdentifier(signatureAlgorithm);
  index += 1;
  const signatureNode = fields[index];
  if (signatureNode === undefined || !isOctetString(signatureNode)) {
    malformed('malformed SignerInfo signature');
  }
  return {
    issuerRaw,
    serialContents,
    digestAlgorithmOid: digest.oid,
    signatureAlgorithmOid: sigAlg.oid,
    signatureAlgorithmParams: sigAlg.params,
    signedAttrs,
    signature: octetStringValue(signatureNode),
  };
}

/**
 * The syntax of one SignerInfo's signedAttrs, judged before any key is
 * used: RFC 5652's attribute set, `SEQUENCE { OID, SET OF value }` with at
 * least one value, for every element. A well-formed set lacking
 * contentType or messageDigest is left to the signature check.
 */
export function requireAttributeSetSyntax(signedAttrs: ASN1Node): void {
  for (const attr of children(signedAttrs)) {
    const parts = children(attr);
    if (
      attr.tag !== Tag.SEQUENCE ||
      parts.length < 2 ||
      parts[0]!.tag !== 0x06 ||
      parts[1]!.tag !== Tag.SET ||
      children(parts[1]!).length === 0
    ) {
      malformed('malformed signedAttrs: not an attribute set');
    }
    // The readers decode every attribute's type, so a type whose OID does
    // not decode (empty, or ending mid-arc) is refused here as MALFORMED
    // rather than escaping from them later. Java's DER parser refuses the
    // same bytes before it reaches the SignerInfo.
    try {
      oidString(parts[0]!.contents);
    } catch {
      malformed('malformed signedAttrs: attribute type is not a valid OBJECT IDENTIFIER');
    }
  }
}

export interface SignedAttributeValues {
  /** The messageDigest attribute's value, or null when absent. */
  readonly messageDigest: Uint8Array | null;
  /**
   * The contentType attribute's value OID contents, or null when the
   * attribute is absent. A value that is not an OID reads as an empty
   * array, which no eContentType matches.
   */
  readonly contentTypeValue: Uint8Array | null;
  /** Whether contentType or messageDigest was present more than once. */
  readonly duplicate: boolean;
}

/**
 * The messageDigest and contentType attribute values from a signedAttrs SET
 * whose syntax {@link requireAttributeSetSyntax} has already checked, and
 * whether either attribute was carried more than once. RFC 5652 §11 allows
 * at most one instance of each; a duplicate is caught here rather than
 * silently reading the first (or last) copy, so the same bytes cannot mean
 * two different things to two readers.
 */
export function signedAttributeValues(signedAttrs: ASN1Node): SignedAttributeValues {
  let messageDigest: Uint8Array | null = null;
  let contentTypeValue: Uint8Array | null = null;
  let duplicate = false;
  for (const attr of children(signedAttrs)) {
    const [type, values] = children(attr);
    if (type === undefined) {
      continue;
    }
    const oid = oidString(type.contents);
    if (oid !== OID_CONTENT_TYPE && oid !== OID_MESSAGE_DIGEST) {
      continue;
    }
    const value = values === undefined ? undefined : children(values)[0];
    if (oid === OID_CONTENT_TYPE) {
      duplicate ||= contentTypeValue !== null;
      contentTypeValue =
        value !== undefined && value.tag === 0x06 /* OID */ ? value.contents : new Uint8Array(0);
    } else {
      duplicate ||= messageDigest !== null;
      messageDigest = value === undefined ? new Uint8Array(0) : value.contents;
    }
  }
  return { messageDigest, contentTypeValue, duplicate };
}

/**
 * The bytes a SignerInfo signature covers when signedAttrs are present: the
 * attributes re-encoded as an explicit SET (RFC 5652 §5.4) — swap the
 * IMPLICIT [0] tag for SET. `signedAttrs.raw` already carries the [0] tag
 * byte from the original encoding, so only that byte changes.
 */
export function signedAttrsSignedBytes(signedAttrsOriginalRaw: Uint8Array): Uint8Array {
  return concatBytes([Uint8Array.of(Tag.SET), signedAttrsOriginalRaw.subarray(1)]);
}

export { bytesEqual };
