import { X509Certificate, createHash, timingSafeEqual, verify as cryptoVerify } from 'node:crypto';
import { Reason, VerificationError } from './errors.js';
import {
  ParseError, Tag, encodeOidContents, isOctetString, octetStringValue, parse, tbsParts,
  type ASN1Node,
} from './der.js';
import { buildAndValidatePath, normalizeRoots, type RootInput } from './chain.js';

const OID_SIGNED_DATA = encodeOidContents('1.2.840.113549.1.7.2');
const OID_MESSAGE_DIGEST = encodeOidContents('1.2.840.113549.1.9.4');

const DIGEST_ALGORITHMS = new Map<string, string>([
  ['1.3.14.3.2.26', 'sha1'],
  ['2.16.840.1.101.3.4.2.1', 'sha256'],
  ['2.16.840.1.101.3.4.2.2', 'sha384'],
  ['2.16.840.1.101.3.4.2.3', 'sha512'],
].map(([oid, name]) => [encodeOidContents(oid!).toString('hex'), name!]));

// Receipt attribute types — Apple, "Validating receipts on the device",
// plus two community-established ones (0: receipt type, 18: original
// purchase date) needed for verifyReceipt response compatibility.
const ATTR = {
  RECEIPT_TYPE: 0, BUNDLE_ID: 2, APP_VERSION: 3, OPAQUE_VALUE: 4, SHA1_HASH: 5,
  CREATION_DATE: 12, IN_APP: 17, ORIGINAL_PURCHASE_DATE: 18,
  ORIGINAL_APP_VERSION: 19, EXPIRATION_DATE: 21,
} as const;
const IAP = {
  QUANTITY: 1701, PRODUCT_ID: 1702, TRANSACTION_ID: 1703, PURCHASE_DATE: 1704,
  ORIGINAL_TRANSACTION_ID: 1705, ORIGINAL_PURCHASE_DATE: 1706, EXPIRES_DATE: 1708,
  WEB_ORDER_LINE_ITEM_ID: 1711, CANCELLATION_DATE: 1712, IS_IN_INTRO_OFFER_PERIOD: 1719,
} as const;

/** One in-app purchase from a legacy app receipt (attribute 17). */
export interface InAppPurchase {
  /** Raw unmodeled attributes by type — forward compatibility (PLAN D10). */
  unknownAttributes: Map<number, Buffer[]>;
  quantity: number | null;
  productId: string | null;
  transactionId: string | null;
  originalTransactionId: string | null;
  purchaseDate: Date | null;
  originalPurchaseDate: Date | null;
  expiresDate: Date | null;
  cancellationDate: Date | null;
  webOrderLineItemId: number | null;
  isInIntroOfferPeriod: number | null;
}

/**
 * A verified legacy app receipt. Only receipts returned by
 * {@link ReceiptVerifier} (or {@link verifyReceiptCore}) should be trusted.
 */
export interface AppReceipt {
  /**
   * Raw values of attribute types this library does not model, keyed by
   * type — forward compatibility for fields Apple may add (PLAN D10).
   * Values are the raw octet-string contents, verified but undecoded.
   */
  unknownAttributes: Map<number, Buffer[]>;
  /** Attribute 0, e.g. "Production" / "ProductionSandbox" (undocumented). */
  receiptType: string | null;
  bundleId: string | null;
  /** Raw DER bytes of attribute 2 — input to the device-hash check. */
  bundleIdBytes: Buffer | null;
  appVersion: string | null;
  opaqueValue: Buffer | null;
  sha1Hash: Buffer | null;
  creationDate: Date | null;
  /** Attribute 18 (undocumented; community-established). */
  originalPurchaseDate: Date | null;
  originalAppVersion: string | null;
  expirationDate: Date | null;
  inAppPurchases: InAppPurchase[];
}

export interface ReceiptVerifierOptions {
  /** Pinned roots (production: `appleReceiptRoots()`). */
  trustedRoots: RootInput[];
  /** Bundle id the receipt must carry. */
  bundleId: string;
}

/**
 * Chain + signature verification WITHOUT the bundle-id claim check — the
 * primitive under both {@link ReceiptVerifier} and the verifyReceipt-compat
 * endpoint (which, like Apple's endpoint, accepts any bundle). Callers that
 * unlock products must check `bundleId` themselves or use ReceiptVerifier.
 */
export function verifyReceiptCore(der: Buffer, trustedRoots: RootInput[]): AppReceipt {
  const roots = normalizeRoots(trustedRoots);
  if (!Buffer.isBuffer(der) || der.length === 0) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'receipt is empty');
  }
  const cms = parseCms(der);

  // Parsed before signature verification only to learn the creation date
  // (chain validity anchors at signing time); nothing from it is trusted
  // until the chain + signature checks pass.
  const fields = parsePayload(cms.content);
  const at = fields.creationDate === null ? new Date() : fields.creationDate;

  const embedded = cms.certificates.map((raw) => new X509Certificate(raw));
  const signerCert = findSignerCert(cms, embedded);
  buildAndValidatePath(signerCert, embedded, roots, at);
  verifyCmsSignature(cms, signerCert);
  return fields;
}

/**
 * Verifies legacy PKCS#7 app receipts completely offline against the pinned
 * Apple Inc. Root CA — the server-side port of Apple's "Validating receipts
 * on the device" procedure (PLAN.md §2.2), mirroring the Java implementation.
 */
export class ReceiptVerifier {
  #roots: RootInput[];
  #bundleId: string;

  constructor({ trustedRoots, bundleId }: ReceiptVerifierOptions) {
    normalizeRoots(trustedRoots); // validate eagerly
    if (typeof bundleId !== 'string' || bundleId.length === 0) {
      throw new TypeError('bundleId is required');
    }
    this.#roots = trustedRoots;
    this.#bundleId = bundleId;
  }

  /**
   * Verifies a receipt (DER Buffer, or its base64 string — the usual client
   * transport form). Passing `deviceGuid` additionally enforces the
   * device-hash binding: SHA1(guid ‖ opaqueValue ‖ bundleIdBytes) must equal
   * attribute 5 (optional — PLAN.md D4).
   */
  verify(receipt: Buffer | string, deviceGuid: Buffer | null = null): AppReceipt {
    const der = typeof receipt === 'string' ? Buffer.from(receipt, 'base64') : receipt;
    const fields = verifyReceiptCore(der, this.#roots);
    if (fields.bundleId !== this.#bundleId) {
      throw new VerificationError(Reason.WRONG_BUNDLE_ID,
        `expected ${this.#bundleId} but receipt has ${fields.bundleId}`);
    }
    if (deviceGuid !== null) {
      verifyDeviceHash(fields, deviceGuid);
    }
    return fields;
  }
}

interface SignerInfo {
  issuerRaw: Buffer;
  serialContents: Buffer;
  digest: string;
  signedAttrs: ASN1Node | null;
  signature: Buffer;
}

interface ParsedCms {
  content: Buffer;
  certificates: Buffer[];
  signerInfo: SignerInfo;
}

function children(node: ASN1Node): ASN1Node[] {
  return node.children ?? [];
}

function parseCms(der: Buffer): ParsedCms {
  let contentInfo: ASN1Node;
  try {
    contentInfo = parse(der);
  } catch (cause) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'not parseable ASN.1', cause);
  }
  try {
    const info = children(contentInfo);
    if (contentInfo.tag !== Tag.SEQUENCE
      || !info[0]!.contents.equals(OID_SIGNED_DATA)
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

    let certificates: Buffer[] = [];
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

function parseSignerInfo(node: ASN1Node): SignerInfo {
  const fields = children(node);
  const sid = children(fields[1]!);
  const issuerRaw = sid[0]!.raw;
  const serialContents = sid[1]!.contents;
  const digestOidHex = children(fields[2]!)[0]!.contents.toString('hex');
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

function findSignerCert(cms: ParsedCms, embedded: X509Certificate[]): X509Certificate {
  for (let i = 0; i < cms.certificates.length; i++) {
    try {
      const { serialNumber, issuer } = tbsParts(cms.certificates[i]!);
      if (serialNumber.contents.equals(cms.signerInfo.serialContents)
        && issuer.raw.equals(cms.signerInfo.issuerRaw)) {
        return embedded[i]!;
      }
    } catch {
      // skip unparseable embedded certificate
    }
  }
  throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'signer certificate not embedded');
}

function verifyCmsSignature(cms: ParsedCms, signerCert: X509Certificate): void {
  const { digest, signedAttrs, signature } = cms.signerInfo;
  let valid: boolean;
  if (signedAttrs !== null) {
    const contentDigest = createHash(digest).update(cms.content).digest();
    const messageDigest = findMessageDigestAttribute(signedAttrs);
    if (messageDigest === null || !timingSafeEqualPadded(messageDigest, contentDigest)) {
      throw new VerificationError(Reason.INVALID_SIGNATURE,
        'messageDigest attribute does not match content');
    }
    // Signature covers the signedAttrs re-encoded as an explicit SET
    // (RFC 5652 §5.4): swap the IMPLICIT [0] tag for SET.
    const signedBytes = Buffer.concat([Buffer.from([Tag.SET]), signedAttrs.raw.subarray(1)]);
    valid = cryptoVerify(digest, signedBytes, signerCert.publicKey, signature);
  } else {
    valid = cryptoVerify(digest, cms.content, signerCert.publicKey, signature);
  }
  if (!valid) {
    throw new VerificationError(Reason.INVALID_SIGNATURE, 'CMS signature check failed');
  }
}

function findMessageDigestAttribute(signedAttrs: ASN1Node): Buffer | null {
  for (const attr of children(signedAttrs)) {
    if (children(attr)[0]!.contents.equals(OID_MESSAGE_DIGEST)) {
      return children(children(attr)[1]!)[0]!.contents;
    }
  }
  return null;
}

function timingSafeEqualPadded(a: Buffer, b: Buffer): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

function verifyDeviceHash(fields: AppReceipt, deviceGuid: Buffer): void {
  if (fields.opaqueValue === null || fields.sha1Hash === null || fields.bundleIdBytes === null) {
    throw new VerificationError(Reason.DEVICE_HASH_MISMATCH,
      'receipt lacks the attributes needed for the device-hash check');
  }
  const computed = createHash('sha1')
    .update(deviceGuid).update(fields.opaqueValue).update(fields.bundleIdBytes).digest();
  if (!timingSafeEqualPadded(computed, fields.sha1Hash)) {
    throw new VerificationError(Reason.DEVICE_HASH_MISMATCH,
      'computed device hash does not match attribute 5');
  }
}

// --- ASN.1 payload parsing ---------------------------------------------

function parsePayload(content: Buffer): AppReceipt {
  const attributes = parseAttributeSet(content, 'receipt payload');
  const fields: AppReceipt = {
    unknownAttributes: new Map(),
    receiptType: null, bundleId: null, bundleIdBytes: null, appVersion: null,
    opaqueValue: null, sha1Hash: null, creationDate: null, originalPurchaseDate: null,
    originalAppVersion: null, expirationDate: null, inAppPurchases: [],
  };
  for (const { type, value } of attributes) {
    switch (type) {
      case ATTR.RECEIPT_TYPE: fields.receiptType = decodeString(value); break;
      case ATTR.BUNDLE_ID:
        fields.bundleId = decodeString(value);
        fields.bundleIdBytes = value;
        break;
      case ATTR.APP_VERSION: fields.appVersion = decodeString(value); break;
      case ATTR.OPAQUE_VALUE: fields.opaqueValue = value; break;
      case ATTR.SHA1_HASH: fields.sha1Hash = value; break;
      case ATTR.CREATION_DATE: fields.creationDate = decodeDate(value); break;
      case ATTR.IN_APP: fields.inAppPurchases.push(parseInApp(value)); break;
      case ATTR.ORIGINAL_PURCHASE_DATE: fields.originalPurchaseDate = decodeDate(value); break;
      case ATTR.ORIGINAL_APP_VERSION: fields.originalAppVersion = decodeString(value); break;
      case ATTR.EXPIRATION_DATE: fields.expirationDate = decodeDate(value); break;
      default: recordUnknown(fields.unknownAttributes, type, value); break;
    }
  }
  return fields;
}

function recordUnknown(unknown: Map<number, Buffer[]>, type: number, value: Buffer): void {
  const values = unknown.get(type) ?? [];
  values.push(value);
  unknown.set(type, values);
}

function parseInApp(value: Buffer): InAppPurchase {
  const attributes = parseAttributeSet(value, 'in-app purchase attribute');
  const purchase: InAppPurchase = {
    unknownAttributes: new Map(),
    quantity: null, productId: null, transactionId: null, originalTransactionId: null,
    purchaseDate: null, originalPurchaseDate: null, expiresDate: null,
    cancellationDate: null, webOrderLineItemId: null, isInIntroOfferPeriod: null,
  };
  for (const { type, value: v } of attributes) {
    switch (type) {
      case IAP.QUANTITY: purchase.quantity = decodeInteger(v); break;
      case IAP.PRODUCT_ID: purchase.productId = decodeString(v); break;
      case IAP.TRANSACTION_ID: purchase.transactionId = decodeString(v); break;
      case IAP.PURCHASE_DATE: purchase.purchaseDate = decodeDate(v); break;
      case IAP.ORIGINAL_TRANSACTION_ID: purchase.originalTransactionId = decodeString(v); break;
      case IAP.ORIGINAL_PURCHASE_DATE: purchase.originalPurchaseDate = decodeDate(v); break;
      case IAP.EXPIRES_DATE: purchase.expiresDate = decodeDate(v); break;
      case IAP.WEB_ORDER_LINE_ITEM_ID: purchase.webOrderLineItemId = decodeInteger(v); break;
      case IAP.CANCELLATION_DATE: purchase.cancellationDate = decodeDate(v); break;
      case IAP.IS_IN_INTRO_OFFER_PERIOD: purchase.isInIntroOfferPeriod = decodeInteger(v); break;
      default: recordUnknown(purchase.unknownAttributes, type, v); break;
    }
  }
  return purchase;
}

function parseAttributeSet(der: Buffer, what: string): Array<{ type: number; value: Buffer }> {
  let node: ASN1Node;
  try {
    node = parse(der);
  } catch (cause) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT,
      `${what} is not valid ASN.1`, cause);
  }
  if (isOctetString(node)) {
    // Xcode receipts double-wrap the payload in an extra OCTET STRING.
    try {
      node = parse(octetStringValue(node));
    } catch (cause) {
      throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT,
        `${what} double-wrap is not valid ASN.1`, cause);
    }
  }
  if (node.tag !== Tag.SET) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, `${what} is not an ASN.1 SET`);
  }
  const attributes: Array<{ type: number; value: Buffer }> = [];
  for (const child of children(node)) {
    const fields = children(child);
    if (child.tag !== Tag.SEQUENCE || fields.length < 3
      || fields[0]!.tag !== Tag.INTEGER || !isOctetString(fields[2]!)) {
      throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'malformed receipt attribute');
    }
    attributes.push({
      type: integerValue(fields[0]!),
      value: octetStringValue(fields[2]!),
    });
  }
  return attributes;
}

function integerValue(node: ASN1Node): number {
  // 8-byte cap: real receipts carry 7-byte integers (web_order_line_item_id).
  if (node.contents.length > 8) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'attribute integer out of range');
  }
  // Negative attribute types/values never occur in receipts; reject them.
  if (node.contents.length > 0 && node.contents[0]! >= 0x80) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'negative receipt integer');
  }
  let value = 0n;
  for (const byte of node.contents) {
    value = value * 256n + BigInt(byte);
  }
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT,
      'receipt integer exceeds JS safe-integer range');
  }
  return Number(value);
}

function decodeNested(der: Buffer, what: string): ASN1Node {
  try {
    return parse(der);
  } catch (cause) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT,
      `${what} is not valid ASN.1`, cause);
  }
}

function decodeString(der: Buffer): string {
  const node = decodeNested(der, 'attribute value');
  if (node.tag !== Tag.UTF8_STRING && node.tag !== Tag.IA5_STRING) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT,
      'attribute value is not an ASN.1 string');
  }
  return node.contents.toString('utf8');
}

function decodeInteger(der: Buffer): number {
  const node = decodeNested(der, 'attribute value');
  if (node.tag !== Tag.INTEGER) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT,
      'attribute value is not an ASN.1 integer');
  }
  return integerValue(node);
}

/** RFC 3339 date in an IA5String; empty means absent (real receipts do this). */
function decodeDate(der: Buffer): Date | null {
  const text = decodeString(der);
  if (text === '') {
    return null;
  }
  const date = new Date(text);
  if (!/^\d{4}-\d{2}-\d{2}T/.test(text) || Number.isNaN(date.getTime())) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT,
      `unparseable receipt date: ${text}`);
  }
  return date;
}
