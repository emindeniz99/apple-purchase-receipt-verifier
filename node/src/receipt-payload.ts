/**
 * The receipt payload attribute grammar (Apple, "Validating receipts on the
 * device"), shared by both entry points. Pure DER decoding over Uint8Array:
 * the verified bytes go in, the modelled fields come out. The Node build
 * re-presents the byte fields as Buffers; the web build hands them out as
 * they are.
 */
import { Reason, VerificationError } from './errors.js';
import { utf8Decode } from './bytes.js';
import { Tag, isOctetString, octetStringValue, parse, type ASN1Node } from './der.js';

// Receipt attribute types — Apple, "Validating receipts on the device",
// plus two community-established ones (0: receipt type, 18: original
// purchase date) needed for verifyReceipt response compatibility.
//
// Types 1, 15, 16 and 1713 are on none of those pages either. They were
// established by decoding a genuine production receipt and lining its
// attributes up against the answer Apple's verifyReceipt endpoint gives for
// the same receipt (measured 2026-09-21):
//
//   1     app item id                -> adam_id AND app_item_id
//   15    download id                -> download_id
//   16    version external id        -> version_external_identifier
//   1713  is trial period (in-app)   -> is_trial_period
//
// All four are INTEGER attributes. Apple renders the three app-level ids as
// JSON numbers and 1713 as the string "true"/"false", exactly as it renders
// 1719.
const ATTR = {
  RECEIPT_TYPE: 0,
  APP_ITEM_ID: 1,
  BUNDLE_ID: 2,
  APP_VERSION: 3,
  OPAQUE_VALUE: 4,
  SHA1_HASH: 5,
  CREATION_DATE: 12,
  DOWNLOAD_ID: 15,
  VERSION_EXTERNAL_IDENTIFIER: 16,
  IN_APP: 17,
  ORIGINAL_PURCHASE_DATE: 18,
  ORIGINAL_APP_VERSION: 19,
  EXPIRATION_DATE: 21,
} as const;
const IAP = {
  QUANTITY: 1701,
  PRODUCT_ID: 1702,
  TRANSACTION_ID: 1703,
  PURCHASE_DATE: 1704,
  ORIGINAL_TRANSACTION_ID: 1705,
  ORIGINAL_PURCHASE_DATE: 1706,
  EXPIRES_DATE: 1708,
  WEB_ORDER_LINE_ITEM_ID: 1711,
  CANCELLATION_DATE: 1712,
  IS_TRIAL_PERIOD: 1713,
  IS_IN_INTRO_OFFER_PERIOD: 1719,
} as const;

/** One in-app purchase from a legacy app receipt (attribute 17). */
export interface RawInAppPurchase {
  /** Raw unmodeled attributes by type — forward compatibility (PLAN D10). */
  unknownAttributes: Map<number, Uint8Array[]>;
  quantity: number | null;
  productId: string | null;
  transactionId: string | null;
  originalTransactionId: string | null;
  purchaseDate: Date | null;
  originalPurchaseDate: Date | null;
  expiresDate: Date | null;
  cancellationDate: Date | null;
  webOrderLineItemId: number | null;
  /**
   * Attribute 1713 (undocumented) — 1 while the purchase is inside a free
   * trial, 0 otherwise. Carried as the integer it is, like
   * {@link isInIntroOfferPeriod}, which Apple's verifyReceipt answer renders
   * as the string "true"/"false".
   */
  isTrialPeriod: number | null;
  isInIntroOfferPeriod: number | null;
}

/** The modelled fields of a legacy app receipt, byte fields undecoded. */
export interface RawAppReceipt {
  /**
   * Raw values of attribute types this library does not model, keyed by
   * type — forward compatibility for fields Apple may add (PLAN D10).
   * Values are the raw octet-string contents, verified but undecoded.
   */
  unknownAttributes: Map<number, Uint8Array[]>;
  /** Attribute 0, e.g. "Production" / "ProductionSandbox" (undocumented). */
  receiptType: string | null;
  bundleId: string | null;
  /** Raw DER bytes of attribute 2 — input to the device-hash check. */
  bundleIdBytes: Uint8Array | null;
  appVersion: string | null;
  opaqueValue: Uint8Array | null;
  sha1Hash: Uint8Array | null;
  creationDate: Date | null;
  /** Attribute 18 (undocumented; community-established). */
  originalPurchaseDate: Date | null;
  originalAppVersion: string | null;
  expirationDate: Date | null;
  /**
   * Attribute 1 (undocumented) — the app's App Store item identifier, which
   * Apple's verifyReceipt answer echoes under BOTH `adam_id` and
   * `app_item_id`. Zero in sandbox receipts, since a sandbox purchase is not
   * tied to a storefront item. A `bigint` because real values of the three
   * ids below run past `Number.MAX_SAFE_INTEGER` — see {@link downloadId}.
   */
  appItemId: bigint | null;
  /**
   * Attribute 15 (undocumented) — identifies the App Store download this
   * receipt came from. Apple's are eighteen digits, well past the range a
   * JavaScript number holds exactly, so this is a `bigint`: a `number` would
   * silently round the id it is meant to identify a download by.
   */
  downloadId: bigint | null;
  /** Attribute 16 (undocumented) — the App Store's own id for this app version. */
  versionExternalIdentifier: bigint | null;
  inAppPurchases: RawInAppPurchase[];
}

function children(node: ASN1Node): ASN1Node[] {
  return node.children ?? [];
}

/**
 * The receipt creation date (attribute 12), read the only way anything in a
 * payload is read before its signer is trusted: the top-level attribute SET
 * is walked shallowly, each entry's type is read, and only the value of type
 * 12 is decoded.
 *
 * `null` means "judge the chain at now": no attribute 12, an empty one, one
 * that does not decode, more than one, or a walk that fails anywhere. An
 * entry the walk cannot read fails it as a whole rather than being skipped,
 * since that entry might have been a second attribute 12. Never throws:
 * nothing is trusted yet, so nothing here can blame anyone.
 */
export function readCreationDate(content: Uint8Array): Date | null {
  try {
    const dates = parseAttributeSet(content, 'receipt payload').filter(
      ({ type }) => type === ATTR.CREATION_DATE,
    );
    return dates.length === 1 ? decodeDate(dates[0]!.value) : null;
  } catch {
    return null;
  }
}

/**
 * The full payload parse, run only after the chain and the signature have
 * passed. A trusted signer signed these bytes, so anything that stops the
 * parse (this library's grammar, a bound, an unexpected error) is the
 * library's failure or a format Apple added, not the client's:
 * INTERNAL_ERROR with the parser's error as its cause, never
 * INVALID_RECEIPT_FORMAT, which the endpoint answers as 21002 and an app
 * server reads as "deny".
 */
export function parseSignedReceiptPayload(content: Uint8Array): RawAppReceipt {
  try {
    return parseReceiptPayload(content);
  } catch (cause) {
    const detail = cause instanceof Error ? cause.message : String(cause);
    throw new VerificationError(
      Reason.INTERNAL_ERROR,
      `signed receipt content could not be read: ${detail}`,
      cause,
    );
  }
}

export function parseReceiptPayload(content: Uint8Array): RawAppReceipt {
  const attributes = parseAttributeSet(content, 'receipt payload');
  const fields: RawAppReceipt = {
    unknownAttributes: new Map(),
    receiptType: null,
    bundleId: null,
    bundleIdBytes: null,
    appVersion: null,
    opaqueValue: null,
    sha1Hash: null,
    creationDate: null,
    originalPurchaseDate: null,
    originalAppVersion: null,
    expirationDate: null,
    appItemId: null,
    downloadId: null,
    versionExternalIdentifier: null,
    inAppPurchases: [],
  };
  for (const { type, value } of attributes) {
    switch (type) {
      case ATTR.RECEIPT_TYPE:
        fields.receiptType = decodeString(value);
        break;
      case ATTR.APP_ITEM_ID:
        fields.appItemId = decodeBigInteger(value);
        break;
      case ATTR.BUNDLE_ID:
        fields.bundleId = decodeString(value);
        fields.bundleIdBytes = value;
        break;
      case ATTR.APP_VERSION:
        fields.appVersion = decodeString(value);
        break;
      case ATTR.OPAQUE_VALUE:
        fields.opaqueValue = value;
        break;
      case ATTR.SHA1_HASH:
        fields.sha1Hash = value;
        break;
      case ATTR.CREATION_DATE:
        fields.creationDate = decodeDate(value);
        break;
      case ATTR.DOWNLOAD_ID:
        fields.downloadId = decodeBigInteger(value);
        break;
      case ATTR.VERSION_EXTERNAL_IDENTIFIER:
        fields.versionExternalIdentifier = decodeBigInteger(value);
        break;
      case ATTR.IN_APP:
        fields.inAppPurchases.push(parseInApp(value));
        break;
      case ATTR.ORIGINAL_PURCHASE_DATE:
        fields.originalPurchaseDate = decodeDate(value);
        break;
      case ATTR.ORIGINAL_APP_VERSION:
        fields.originalAppVersion = decodeString(value);
        break;
      case ATTR.EXPIRATION_DATE:
        fields.expirationDate = decodeDate(value);
        break;
      default:
        recordUnknown(fields.unknownAttributes, type, value);
        break;
    }
  }
  return fields;
}

function recordUnknown(unknown: Map<number, Uint8Array[]>, type: number, value: Uint8Array): void {
  const values = unknown.get(type) ?? [];
  values.push(value);
  unknown.set(type, values);
}

function parseInApp(value: Uint8Array): RawInAppPurchase {
  const attributes = parseAttributeSet(value, 'in-app purchase attribute');
  const purchase: RawInAppPurchase = {
    unknownAttributes: new Map(),
    quantity: null,
    productId: null,
    transactionId: null,
    originalTransactionId: null,
    purchaseDate: null,
    originalPurchaseDate: null,
    expiresDate: null,
    cancellationDate: null,
    webOrderLineItemId: null,
    isTrialPeriod: null,
    isInIntroOfferPeriod: null,
  };
  for (const { type, value: v } of attributes) {
    switch (type) {
      case IAP.QUANTITY:
        purchase.quantity = decodeInteger(v);
        break;
      case IAP.PRODUCT_ID:
        purchase.productId = decodeString(v);
        break;
      case IAP.TRANSACTION_ID:
        purchase.transactionId = decodeString(v);
        break;
      case IAP.PURCHASE_DATE:
        purchase.purchaseDate = decodeDate(v);
        break;
      case IAP.ORIGINAL_TRANSACTION_ID:
        purchase.originalTransactionId = decodeString(v);
        break;
      case IAP.ORIGINAL_PURCHASE_DATE:
        purchase.originalPurchaseDate = decodeDate(v);
        break;
      case IAP.EXPIRES_DATE:
        purchase.expiresDate = decodeDate(v);
        break;
      case IAP.WEB_ORDER_LINE_ITEM_ID:
        purchase.webOrderLineItemId = decodeInteger(v);
        break;
      case IAP.CANCELLATION_DATE:
        purchase.cancellationDate = decodeDate(v);
        break;
      case IAP.IS_TRIAL_PERIOD:
        purchase.isTrialPeriod = decodeInteger(v);
        break;
      case IAP.IS_IN_INTRO_OFFER_PERIOD:
        purchase.isInIntroOfferPeriod = decodeInteger(v);
        break;
      default:
        recordUnknown(purchase.unknownAttributes, type, v);
        break;
    }
  }
  return purchase;
}

function parseAttributeSet(
  der: Uint8Array,
  what: string,
): Array<{ type: number; value: Uint8Array }> {
  let node: ASN1Node;
  try {
    node = parse(der);
  } catch (cause) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, `${what} is not valid ASN.1`, cause);
  }
  if (isOctetString(node)) {
    // Xcode receipts double-wrap the payload in an extra OCTET STRING.
    try {
      node = parse(octetStringValue(node));
    } catch (cause) {
      throw new VerificationError(
        Reason.INVALID_RECEIPT_FORMAT,
        `${what} double-wrap is not valid ASN.1`,
        cause,
      );
    }
  }
  if (node.tag !== Tag.SET) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, `${what} is not an ASN.1 SET`);
  }
  const attributes: Array<{ type: number; value: Uint8Array }> = [];
  for (const child of children(node)) {
    const fields = children(child);
    if (
      child.tag !== Tag.SEQUENCE ||
      fields.length < 3 ||
      fields[0]!.tag !== Tag.INTEGER ||
      !isOctetString(fields[2]!)
    ) {
      throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, 'malformed receipt attribute');
    }
    attributes.push({
      type: attributeType(fields[0]!),
      value: octetStringValue(fields[2]!),
    });
  }
  return attributes;
}

// Attribute *types* are a 32-bit signed space: every type Apple has ever
// issued is a small number, and a value above 2^31-1 cannot be represented
// by ports whose attribute-type field is an int. Mapping such a type onto a
// sentinel (-1) and filing it under unknownAttributes would let two ports
// disagree about what the same receipt says, so an unrepresentable type is
// a malformed receipt in every port. Attribute *values* keep the wider
// 2^53-1 range: web_order_line_item_id is genuinely a 7-byte integer. The
// three app-level ids are the exception and are decoded as bigint, because
// Apple's download ids are eighteen digits and a number would round them.
const MAX_ATTRIBUTE_TYPE = 2147483647;

function attributeType(node: ASN1Node): number {
  const type = integerValue(node);
  if (type > MAX_ATTRIBUTE_TYPE) {
    throw new VerificationError(
      Reason.INVALID_RECEIPT_FORMAT,
      `receipt attribute type ${type} exceeds the 32-bit signed range`,
    );
  }
  return type;
}

/** The exact value of an attribute INTEGER, bounds-checked but not narrowed. */
function bigIntegerValue(node: ASN1Node): bigint {
  // 8-byte cap: real receipts carry 7-byte integers (web_order_line_item_id)
  // and 8-byte ones (download_id).
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
  return value;
}

function integerValue(node: ASN1Node): number {
  const value = bigIntegerValue(node);
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new VerificationError(
      Reason.INVALID_RECEIPT_FORMAT,
      'receipt integer exceeds JS safe-integer range',
    );
  }
  return Number(value);
}

function decodeNested(der: Uint8Array, what: string): ASN1Node {
  try {
    return parse(der);
  } catch (cause) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, `${what} is not valid ASN.1`, cause);
  }
}

function decodeString(der: Uint8Array): string {
  const node = decodeNested(der, 'attribute value');
  if (node.tag !== Tag.UTF8_STRING && node.tag !== Tag.IA5_STRING) {
    throw new VerificationError(
      Reason.INVALID_RECEIPT_FORMAT,
      'attribute value is not an ASN.1 string',
    );
  }
  return utf8Decode(node.contents);
}

function integerNode(der: Uint8Array): ASN1Node {
  const node = decodeNested(der, 'attribute value');
  if (node.tag !== Tag.INTEGER) {
    throw new VerificationError(
      Reason.INVALID_RECEIPT_FORMAT,
      'attribute value is not an ASN.1 integer',
    );
  }
  return node;
}

function decodeInteger(der: Uint8Array): number {
  return integerValue(integerNode(der));
}

/**
 * The same attribute INTEGER, kept exact. Same tag, 8-byte and non-negative
 * checks as {@link decodeInteger}; what it drops is that function's
 * safe-integer ceiling, which a genuine `download_id` sits above — rejecting
 * one as malformed would turn a real production receipt away.
 */
function decodeBigInteger(der: Uint8Array): bigint {
  return bigIntegerValue(integerNode(der));
}

// The timezone designator is mandatory: `new Date` reads a naive date as the
// server's LOCAL time, and the creation date is the instant the chain's
// validity is judged at, so the same receipt would verify on one host and
// fail on another. Java (Instant.parse) and Swift (ISO8601DateFormatter)
// reject a naive date too — requiring it here keeps all four in agreement.
const RFC_3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

/** RFC 3339 date in an IA5String; empty means absent (real receipts do this). */
function decodeDate(der: Uint8Array): Date | null {
  const text = decodeString(der);
  if (text === '') {
    return null;
  }
  const date = new Date(text);
  if (!RFC_3339.test(text) || Number.isNaN(date.getTime())) {
    throw new VerificationError(Reason.INVALID_RECEIPT_FORMAT, `unparseable receipt date: ${text}`);
  }
  return date;
}
