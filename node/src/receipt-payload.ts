/**
 * The receipt payload attribute grammar (Apple, "Validating receipts on the
 * device"), shared by both entry points and both builds. Pure DER decoding
 * over Uint8Array, run only after the chain and the signature have
 * verified: everything here that fails to parse becomes UNREADABLE_PAYLOAD
 * at the caller, or, for one known attribute's value, a `null` typed field
 * with the raw octets kept in `unknownAttributes`.
 *
 * Decode rules (docs/design/0.7-api.md): a missing attribute is `null`; the
 * first occurrence of a known attribute wins, for the typed field and for
 * the chain date; every attribute that does not end up in a typed field
 * (an attribute type this library does not model, a later copy of a known
 * attribute, a known attribute whose value does not parse) goes raw into
 * `unknownAttributes`; a date's empty string means "not set" (`null`, not
 * kept raw); a non-empty date string that is not exactly
 * `YYYY-MM-DDTHH:MM:SSZ` is `null` and kept raw; an IA5String holding a byte
 * at or above 0x80, and an INTEGER that is not DER, do not parse either.
 */
import { base64Encode } from './bytes.js';
import { Tag, isOctetString, octetStringValue, parse, ParseError, type ASN1Node } from './der.js';
import { decodeStrictUtf8 } from './strict-utf8.js';

// Receipt attribute types — Apple, "Validating receipts on the device", plus
// community-established ones; see RECEIPT-FIELDS.md for the provenance of
// each. All four undocumented app-level/in-app ids (1, 15, 16, 1713) are
// INTEGER attributes established by decoding a genuine production receipt.
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

const TOP_LEVEL = new Set<number>(Object.values(ATTR).filter((v) => v !== ATTR.IN_APP));
const IN_APP_TYPES = new Set<number>(Object.values(IAP));

export type RawAttributes = ReadonlyMap<number, readonly Uint8Array[]>;

export interface InAppPurchase {
  readonly quantity: number | null;
  readonly productId: string | null;
  readonly transactionId: string | null;
  readonly purchaseDateMs: number | null;
  readonly originalTransactionId: string | null;
  readonly originalPurchaseDateMs: number | null;
  readonly expiresDateMs: number | null;
  /** 64-bit id, as a decimal string (Node cannot hold an 18-digit id in a number). */
  readonly webOrderLineItemId: string | null;
  readonly cancellationDateMs: number | null;
  readonly isTrialPeriod: boolean | null;
  readonly isInIntroOfferPeriod: boolean | null;
  readonly unknownAttributes: RawAttributes;
}

export interface ReceiptPayload {
  readonly receiptType: string | null;
  /** 64-bit id, as a decimal string. */
  readonly appItemId: string | null;
  readonly bundleId: string | null;
  /** The attribute 2 value octets exactly as they sit in the receipt. */
  readonly bundleIdBytes: Uint8Array | null;
  readonly applicationVersion: string | null;
  readonly opaqueValue: Uint8Array | null;
  readonly sha1Hash: Uint8Array | null;
  readonly receiptCreationDateMs: number | null;
  /** 64-bit id, as a decimal string. */
  readonly downloadId: string | null;
  /** 64-bit id, as a decimal string. */
  readonly versionExternalIdentifier: string | null;
  readonly inApp: readonly InAppPurchase[];
  readonly originalPurchaseDateMs: number | null;
  readonly originalApplicationVersion: string | null;
  readonly expirationDateMs: number | null;
  readonly unknownAttributes: RawAttributes;
  /** This payload as JSON, for logging and storage: docs/design/0.7-api.md "Our JSON". */
  toJson(): string;
}

function decodeStrictUtf8OrThrow(bytes: Uint8Array): string {
  try {
    return decodeStrictUtf8(bytes);
  } catch {
    throw new ParseError('not valid UTF-8');
  }
}

/**
 * The exact signed value of a DER INTEGER's contents, or throws if the
 * encoding is not DER-minimal (empty, or a redundant leading octet).
 */
function derIntegerValue(contents: Uint8Array): bigint {
  if (contents.length === 0) {
    throw new ParseError('empty INTEGER');
  }
  if (contents.length > 1) {
    const b0 = contents[0]!;
    const b1 = contents[1]!;
    if ((b0 === 0x00 && (b1 & 0x80) === 0) || (b0 === 0xff && (b1 & 0x80) !== 0)) {
      throw new ParseError('non-minimal INTEGER encoding');
    }
  }
  let value = 0n;
  for (const byte of contents) {
    value = (value << 8n) | BigInt(byte);
  }
  if (contents[0]! & 0x80) {
    value -= 1n << BigInt(contents.length * 8);
  }
  return value;
}

// --- date grammar ----------------------------------------------------------

const DATE_PATTERN = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z$/;

function isLeapYear(y: number): boolean {
  return (y % 4 === 0 && y % 100 !== 0) || y % 400 === 0;
}

const DAYS_IN_MONTH = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/**
 * Days since the epoch for a proleptic-Gregorian date, valid across the
 * whole 0000-9999 range (Howard Hinnant's `days_from_civil`, matching
 * `java.time.LocalDate.toEpochDay()`). Not `Date.UTC`: its year parameter
 * treats 0-99 as 1900-1999 (a spec quirk from the era of two-digit years),
 * which would corrupt every date whose year is below 100.
 */
function epochDay(y: number, m: number, d: number): number {
  const yy = m <= 2 ? y - 1 : y;
  const era = Math.floor((yy >= 0 ? yy : yy - 399) / 400);
  const yoe = yy - era * 400; // [0, 399]
  const mp = (m + 9) % 12; // [0, 11]
  const doy = Math.floor((153 * mp + 2) / 5) + d - 1; // [0, 365]
  const doe = yoe * 365 + Math.floor(yoe / 4) - Math.floor(yoe / 100) + doy; // [0, 146096]
  return era * 146097 + doe - 719468;
}

/**
 * Exactly `YYYY-MM-DDTHH:MM:SSZ`: a four-digit year 0000-9999, uppercase T
 * and Z, a real calendar date (leap years included), hours 00-23, minutes
 * and seconds 00-59, no fraction and no offset. `null` for anything else.
 */
export function parseExactDate(text: string): number | null {
  const m = DATE_PATTERN.exec(text);
  if (m === null) {
    return null;
  }
  const year = Number(m[1]);
  const month = Number(m[2]);
  const day = Number(m[3]);
  const hour = Number(m[4]);
  const minute = Number(m[5]);
  const second = Number(m[6]);
  if (month < 1 || month > 12) {
    return null;
  }
  const maxDay = month === 2 && isLeapYear(year) ? 29 : DAYS_IN_MONTH[month - 1]!;
  if (day < 1 || day > maxDay || hour > 23 || minute > 59 || second > 59) {
    return null;
  }
  return ((epochDay(year, month, day) * 24 + hour) * 60 + minute) * 60_000 + second * 1000;
}

// --- attribute walk ----------------------------------------------------

interface RawAttribute {
  type: number;
  value: Uint8Array;
}

function children(node: ASN1Node): ASN1Node[] {
  return node.children ?? [];
}

const MAX_ATTRIBUTE_TYPE = 2147483647; // 2^31 - 1

/**
 * `ReceiptAttribute ::= SEQUENCE { type INTEGER, version INTEGER, value
 * OCTET STRING, ... }`. Throws (fatal to the whole payload, per the design)
 * for a shape this is not, or a type outside the 32-bit signed range —
 * narrowing it onto a sentinel would let two ports disagree about what the
 * same receipt says.
 */
function parseAttributeSet(der: Uint8Array, what: string): RawAttribute[] {
  let node: ASN1Node;
  try {
    node = parse(der);
  } catch (cause) {
    throw new ParseError(`${what} is not valid ASN.1: ${(cause as Error).message}`);
  }
  if (isOctetString(node)) {
    // Xcode receipts double-wrap the payload in an extra OCTET STRING.
    try {
      node = parse(octetStringValue(node));
    } catch (cause) {
      throw new ParseError(`${what} double-wrap is not valid ASN.1: ${(cause as Error).message}`);
    }
  }
  if (node.tag !== Tag.SET) {
    throw new ParseError(`${what} is not an ASN.1 SET`);
  }
  const attributes: RawAttribute[] = [];
  for (const child of children(node)) {
    const fields = children(child);
    if (child.tag !== Tag.SEQUENCE || fields.length < 3 || fields[0]!.tag !== Tag.INTEGER) {
      throw new ParseError('malformed receipt attribute');
    }
    const valueField = fields[2]!;
    if (!isOctetString(valueField)) {
      throw new ParseError('malformed receipt attribute');
    }
    const type = derIntegerValue(fields[0]!.contents);
    if (type < 0n || type > BigInt(MAX_ATTRIBUTE_TYPE)) {
      throw new ParseError('receipt attribute type out of range');
    }
    attributes.push({ type: Number(type), value: octetStringValue(valueField) });
  }
  return attributes;
}

/**
 * The receipt creation date (attribute 12), read the only way anything in a
 * payload is read before its signer is trusted. `null` means "judge the
 * chain at now": no attribute 12, an empty one, one that does not decode,
 * or a walk that fails anywhere. Never throws.
 */
export function readCreationDate(content: Uint8Array): number | null {
  try {
    for (const { type, value } of parseAttributeSet(content, 'receipt payload')) {
      if (type === ATTR.CREATION_DATE) {
        // First attribute 12 decides, whether or not it decodes.
        return decodeDateOrNull(value);
      }
    }
    return null;
  } catch {
    return null;
  }
}

function decodeString(der: Uint8Array): string {
  const node = parse(der);
  if (node.tag !== Tag.UTF8_STRING && node.tag !== Tag.IA5_STRING) {
    throw new ParseError('attribute value is not a UTF8String or IA5String');
  }
  if (node.tag === Tag.IA5_STRING) {
    for (const byte of node.contents) {
      if (byte >= 0x80) {
        throw new ParseError('IA5String attribute value is not seven-bit');
      }
    }
  }
  return decodeStrictUtf8OrThrow(node.contents);
}

/** The bundle id string, or `null` when it does not decode; its octets are kept either way. */
function decodeStringOrNull(der: Uint8Array): string | null {
  try {
    return decodeString(der);
  } catch {
    return null;
  }
}

const MIN_I64 = -9223372036854775808n;
const MAX_I64 = 9223372036854775807n;

function integerNode(der: Uint8Array): ASN1Node {
  const node = parse(der);
  if (node.tag !== Tag.INTEGER) {
    throw new ParseError('attribute value is not an ASN.1 integer');
  }
  return node;
}

/** An INTEGER that fits a signed 64-bit value, negative values included. */
function decodeSigned64(der: Uint8Array): bigint {
  const value = derIntegerValue(integerNode(der).contents);
  if (value < MIN_I64 || value > MAX_I64) {
    throw new ParseError('receipt integer out of range');
  }
  return value;
}

function decodeNumberField(der: Uint8Array): number {
  return Number(decodeSigned64(der));
}

function decodeIdField(der: Uint8Array): string {
  return decodeSigned64(der).toString();
}

function decodeFlag(der: Uint8Array): boolean {
  return decodeSigned64(der) !== 0n;
}

/** A date: `null` when the string is empty (not kept raw); throws when it does not parse. */
function decodeDate(der: Uint8Array): number | null {
  const text = decodeString(der);
  if (text === '') {
    return null;
  }
  const ms = parseExactDate(text);
  if (ms === null) {
    throw new ParseError('attribute value is not a YYYY-MM-DDTHH:MM:SSZ date');
  }
  return ms;
}

function decodeDateOrNull(der: Uint8Array): number | null {
  try {
    return decodeDate(der);
  } catch {
    return null;
  }
}

function recordUnknown(unknown: Map<number, Uint8Array[]>, type: number, value: Uint8Array): void {
  const values = unknown.get(type);
  if (values === undefined) {
    unknown.set(type, [value]);
  } else {
    values.push(value);
  }
}

interface MutableInApp {
  quantity: number | null;
  productId: string | null;
  transactionId: string | null;
  purchaseDateMs: number | null;
  originalTransactionId: string | null;
  originalPurchaseDateMs: number | null;
  expiresDateMs: number | null;
  webOrderLineItemId: string | null;
  cancellationDateMs: number | null;
  isTrialPeriod: boolean | null;
  isInIntroOfferPeriod: boolean | null;
}

function parseInApp(value: Uint8Array): InAppPurchase {
  const fields: MutableInApp = {
    quantity: null,
    productId: null,
    transactionId: null,
    purchaseDateMs: null,
    originalTransactionId: null,
    originalPurchaseDateMs: null,
    expiresDateMs: null,
    webOrderLineItemId: null,
    cancellationDateMs: null,
    isTrialPeriod: null,
    isInIntroOfferPeriod: null,
  };
  const unknown = new Map<number, Uint8Array[]>();
  const seen = new Set<number>();
  for (const { type, value: v } of parseAttributeSet(value, 'in-app purchase attribute')) {
    if (IN_APP_TYPES.has(type) && seen.has(type)) {
      recordUnknown(unknown, type, v);
      continue;
    }
    if (IN_APP_TYPES.has(type)) {
      seen.add(type);
    }
    try {
      switch (type) {
        case IAP.QUANTITY:
          fields.quantity = decodeNumberField(v);
          break;
        case IAP.PRODUCT_ID:
          fields.productId = decodeString(v);
          break;
        case IAP.TRANSACTION_ID:
          fields.transactionId = decodeString(v);
          break;
        case IAP.PURCHASE_DATE:
          fields.purchaseDateMs = decodeDate(v);
          break;
        case IAP.ORIGINAL_TRANSACTION_ID:
          fields.originalTransactionId = decodeString(v);
          break;
        case IAP.ORIGINAL_PURCHASE_DATE:
          fields.originalPurchaseDateMs = decodeDate(v);
          break;
        case IAP.EXPIRES_DATE:
          fields.expiresDateMs = decodeDate(v);
          break;
        case IAP.WEB_ORDER_LINE_ITEM_ID:
          fields.webOrderLineItemId = decodeIdField(v);
          break;
        case IAP.CANCELLATION_DATE:
          fields.cancellationDateMs = decodeDate(v);
          break;
        case IAP.IS_TRIAL_PERIOD:
          fields.isTrialPeriod = decodeFlag(v);
          break;
        case IAP.IS_IN_INTRO_OFFER_PERIOD:
          fields.isInIntroOfferPeriod = decodeFlag(v);
          break;
        default:
          recordUnknown(unknown, type, v);
          break;
      }
    } catch {
      recordUnknown(unknown, type, v);
    }
  }
  return { ...fields, unknownAttributes: unknown };
}

interface MutableReceipt {
  receiptType: string | null;
  appItemId: string | null;
  bundleId: string | null;
  bundleIdBytes: Uint8Array | null;
  applicationVersion: string | null;
  opaqueValue: Uint8Array | null;
  sha1Hash: Uint8Array | null;
  receiptCreationDateMs: number | null;
  downloadId: string | null;
  versionExternalIdentifier: string | null;
  originalPurchaseDateMs: number | null;
  originalApplicationVersion: string | null;
  expirationDateMs: number | null;
}

/**
 * The full payload parse, run only after the chain and the signature have
 * passed. Throws {@link ParseError} for a defect that makes the whole
 * payload unreadable (a malformed attribute SET); a known attribute whose
 * value does not decode is instead kept raw with its typed field `null`.
 */
export function parseReceiptPayload(content: Uint8Array): ReceiptPayload {
  const fields: MutableReceipt = {
    receiptType: null,
    appItemId: null,
    bundleId: null,
    bundleIdBytes: null,
    applicationVersion: null,
    opaqueValue: null,
    sha1Hash: null,
    receiptCreationDateMs: null,
    downloadId: null,
    versionExternalIdentifier: null,
    originalPurchaseDateMs: null,
    originalApplicationVersion: null,
    expirationDateMs: null,
  };
  const inApp: InAppPurchase[] = [];
  const unknown = new Map<number, Uint8Array[]>();
  const seen = new Set<number>();
  for (const { type, value } of parseAttributeSet(content, 'receipt payload')) {
    if (TOP_LEVEL.has(type) && seen.has(type)) {
      recordUnknown(unknown, type, value);
      continue;
    }
    if (TOP_LEVEL.has(type)) {
      seen.add(type);
    }
    try {
      switch (type) {
        case ATTR.RECEIPT_TYPE:
          fields.receiptType = decodeString(value);
          break;
        case ATTR.APP_ITEM_ID:
          fields.appItemId = decodeIdField(value);
          break;
        case ATTR.BUNDLE_ID:
          // The raw octets are a typed field of their own (bundleIdBytes),
          // so a string decode failure here leaves the typed string null
          // without also recording the value under unknownAttributes —
          // nothing would be gained, since bundleIdBytes already keeps it.
          fields.bundleIdBytes = value;
          fields.bundleId = decodeStringOrNull(value);
          break;
        case ATTR.APP_VERSION:
          fields.applicationVersion = decodeString(value);
          break;
        case ATTR.OPAQUE_VALUE:
          fields.opaqueValue = value;
          break;
        case ATTR.SHA1_HASH:
          fields.sha1Hash = value;
          break;
        case ATTR.CREATION_DATE:
          fields.receiptCreationDateMs = decodeDate(value);
          break;
        case ATTR.DOWNLOAD_ID:
          fields.downloadId = decodeIdField(value);
          break;
        case ATTR.VERSION_EXTERNAL_IDENTIFIER:
          fields.versionExternalIdentifier = decodeIdField(value);
          break;
        case ATTR.IN_APP:
          inApp.push(parseInApp(value));
          break;
        case ATTR.ORIGINAL_PURCHASE_DATE:
          fields.originalPurchaseDateMs = decodeDate(value);
          break;
        case ATTR.ORIGINAL_APP_VERSION:
          fields.originalApplicationVersion = decodeString(value);
          break;
        case ATTR.EXPIRATION_DATE:
          fields.expirationDateMs = decodeDate(value);
          break;
        default:
          recordUnknown(unknown, type, value);
          break;
      }
    } catch {
      // BUNDLE_ID never throws (decodeStringOrNull), so it never reaches here.
      recordUnknown(unknown, type, value);
    }
  }
  return buildReceiptPayload(fields, inApp, unknown);
}

// --- JSON --------------------------------------------------------------
//
// `JSON.stringify` writes the design's value (docs/design/0.7-api.md
// "Our JSON"); ports agree on the parsed value, not on the bytes.

function base64(bytes: Uint8Array | null): string | null {
  return bytes === null ? null : base64Encode(bytes);
}

function unknownAttributesJson(attrs: RawAttributes): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [type, values] of attrs) {
    out[String(type)] = values.map((v) => base64Encode(v));
  }
  return out;
}

function inAppJson(purchase: InAppPurchase): Record<string, unknown> {
  return {
    quantity: purchase.quantity,
    product_id: purchase.productId,
    transaction_id: purchase.transactionId,
    purchase_date_ms: purchase.purchaseDateMs,
    original_transaction_id: purchase.originalTransactionId,
    original_purchase_date_ms: purchase.originalPurchaseDateMs,
    expires_date_ms: purchase.expiresDateMs,
    web_order_line_item_id: purchase.webOrderLineItemId,
    cancellation_date_ms: purchase.cancellationDateMs,
    is_trial_period: purchase.isTrialPeriod,
    is_in_intro_offer_period: purchase.isInIntroOfferPeriod,
    unknown_attributes: unknownAttributesJson(purchase.unknownAttributes),
  };
}

function toJson(receipt: ReceiptPayload): string {
  return JSON.stringify({
    receipt_type: receipt.receiptType,
    app_item_id: receipt.appItemId,
    bundle_id: receipt.bundleId,
    bundle_id_bytes: base64(receipt.bundleIdBytes),
    application_version: receipt.applicationVersion,
    opaque_value: base64(receipt.opaqueValue),
    sha1_hash: base64(receipt.sha1Hash),
    receipt_creation_date_ms: receipt.receiptCreationDateMs,
    download_id: receipt.downloadId,
    version_external_identifier: receipt.versionExternalIdentifier,
    in_app: receipt.inApp.map(inAppJson),
    original_purchase_date_ms: receipt.originalPurchaseDateMs,
    original_application_version: receipt.originalApplicationVersion,
    expiration_date_ms: receipt.expirationDateMs,
    unknown_attributes: unknownAttributesJson(receipt.unknownAttributes),
  });
}

function buildReceiptPayload(
  fields: MutableReceipt,
  inApp: InAppPurchase[],
  unknown: Map<number, Uint8Array[]>,
): ReceiptPayload {
  const payload: ReceiptPayload = {
    ...fields,
    inApp,
    unknownAttributes: unknown,
    toJson(): string {
      return toJson(payload);
    },
  };
  return payload;
}

/** Builds a {@link ReceiptPayload} by hand, for callers' own tests. Fields default to absent. */
export function createReceiptPayload(
  fields: Partial<Omit<ReceiptPayload, 'toJson'>>,
): ReceiptPayload {
  const base: MutableReceipt = {
    receiptType: fields.receiptType ?? null,
    appItemId: fields.appItemId ?? null,
    bundleId: fields.bundleId ?? null,
    bundleIdBytes: fields.bundleIdBytes ?? null,
    applicationVersion: fields.applicationVersion ?? null,
    opaqueValue: fields.opaqueValue ?? null,
    sha1Hash: fields.sha1Hash ?? null,
    receiptCreationDateMs: fields.receiptCreationDateMs ?? null,
    downloadId: fields.downloadId ?? null,
    versionExternalIdentifier: fields.versionExternalIdentifier ?? null,
    originalPurchaseDateMs: fields.originalPurchaseDateMs ?? null,
    originalApplicationVersion: fields.originalApplicationVersion ?? null,
    expirationDateMs: fields.expirationDateMs ?? null,
  };
  return buildReceiptPayload(
    base,
    fields.inApp ? [...fields.inApp] : [],
    copyUnknownAttributes(fields.unknownAttributes),
  );
}

function copyUnknownAttributes(attrs: RawAttributes | undefined): Map<number, Uint8Array[]> {
  const copy = new Map<number, Uint8Array[]>();
  for (const [type, values] of attrs ?? []) {
    copy.set(type, [...values]);
  }
  return copy;
}

/** Builds an {@link InAppPurchase} by hand, for callers' own tests. Fields default to absent. */
export function createInAppPurchase(fields: Partial<InAppPurchase>): InAppPurchase {
  return {
    quantity: fields.quantity ?? null,
    productId: fields.productId ?? null,
    transactionId: fields.transactionId ?? null,
    purchaseDateMs: fields.purchaseDateMs ?? null,
    originalTransactionId: fields.originalTransactionId ?? null,
    originalPurchaseDateMs: fields.originalPurchaseDateMs ?? null,
    expiresDateMs: fields.expiresDateMs ?? null,
    webOrderLineItemId: fields.webOrderLineItemId ?? null,
    cancellationDateMs: fields.cancellationDateMs ?? null,
    isTrialPeriod: fields.isTrialPeriod ?? null,
    isInIntroOfferPeriod: fields.isInIntroOfferPeriod ?? null,
    unknownAttributes: copyUnknownAttributes(fields.unknownAttributes),
  };
}
