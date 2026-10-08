/**
 * The 0.7 payload types, their hand-built constructors for callers' tests,
 * `toJson()`, and the conversion of aprv.wasm's payload JSON into them.
 *
 * Nothing here decides anything about a receipt. The module has already
 * verified it and decoded every field; this file moves the values it
 * reports into JavaScript types: bytes arrive as padded standard base64
 * and become `Uint8Array`s, 64-bit ids stay decimal strings, dates stay
 * epoch-millisecond numbers, and a missing field is `null`
 * (docs/design/0.7-api.md "Our JSON"). A value of the wrong type means the
 * module and this package disagree about the wire, which the caller sees
 * as `INTERNAL_ERROR`.
 */

import type { Environment } from './environment.js';

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
  readonly cancellationReason?: string | null;
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
  /** Attribute 32, the pre-order date. */
  readonly preorderDateMs: number | null;
  readonly originalApplicationVersion: string | null;
  readonly expirationDateMs: number | null;
  readonly unknownAttributes: RawAttributes;
  /**
   * The environment {@link receiptType} names, as the module states it:
   * `Production` and `ProductionVPP` are `Environment.PRODUCTION`,
   * `ProductionSandbox` and `ProductionVPPSandbox` `Environment.SANDBOX`,
   * anything else (`Xcode`, a missing value) `null`. Not part of
   * {@link toJson}.
   */
  readonly environment: Environment | null;
  /**
   * This payload as JSON: docs/design/0.7-api.md "Our JSON". It holds the
   * full purchase data; the caller decides what to write where.
   */
  toJson(): string;
}

/** A verified JWS payload: the JSON object Apple signed, unchanged, and the environment it names. */
export interface JsonPayload {
  readonly json: string;
  /**
   * The environment the payload names, as the module states it: from the
   * first of the top-level `environment` (a transaction, renewal info),
   * `data.environment` (an App Store Server Notification V2) and
   * `summary.environment` (a summary notification) that is present.
   * `Production` is `Environment.PRODUCTION` and `Sandbox`
   * `Environment.SANDBOX`; anything else there (`Xcode`, `LocalTesting`, a
   * value that is not a string), or none of the three, is `null`.
   */
  readonly environment: Environment | null;
}

/**
 * Builds a {@link JsonPayload} by hand, for callers' own tests. The
 * payload states the `environment` given, `null` when left out; nothing
 * reads it from `json`.
 */
export function createJsonPayload(
  json: string,
  environment: Environment | null = null,
): JsonPayload {
  return { json, environment };
}

type ReceiptFields = Omit<ReceiptPayload, 'toJson' | 'inApp' | 'unknownAttributes'>;

// --- bytes <-> base64, for values the module produced ----------------------
//
// `atob` and `btoa` exist on every runtime this package supports. They are
// used only on base64 the module wrote, or to write this package's own
// JSON; input from a caller never passes through them.

function bytesFromBase64(text: string): Uint8Array {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function base64FromBytes(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(binary);
}

// --- toJson -----------------------------------------------------------------

function base64OrNull(bytes: Uint8Array | null): string | null {
  return bytes === null ? null : base64FromBytes(bytes);
}

function unknownAttributesJson(attrs: RawAttributes): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [type, values] of attrs) {
    out[String(type)] = values.map(base64FromBytes);
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
    ...(purchase.cancellationReason == null
      ? {}
      : { cancellation_reason: purchase.cancellationReason }),
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
    bundle_id_bytes: base64OrNull(receipt.bundleIdBytes),
    application_version: receipt.applicationVersion,
    opaque_value: base64OrNull(receipt.opaqueValue),
    sha1_hash: base64OrNull(receipt.sha1Hash),
    receipt_creation_date_ms: receipt.receiptCreationDateMs,
    download_id: receipt.downloadId,
    version_external_identifier: receipt.versionExternalIdentifier,
    in_app: receipt.inApp.map(inAppJson),
    original_purchase_date_ms: receipt.originalPurchaseDateMs,
    preorder_date_ms: receipt.preorderDateMs,
    original_application_version: receipt.originalApplicationVersion,
    expiration_date_ms: receipt.expirationDateMs,
    unknown_attributes: unknownAttributesJson(receipt.unknownAttributes),
  });
}

function buildReceiptPayload(
  fields: ReceiptFields,
  inApp: InAppPurchase[],
  unknownAttributes: Map<number, Uint8Array[]>,
): ReceiptPayload {
  const payload: ReceiptPayload = {
    ...fields,
    inApp,
    unknownAttributes,
    toJson(): string {
      return toJson(payload);
    },
  };
  return payload;
}

function copyUnknownAttributes(attrs: RawAttributes | undefined): Map<number, Uint8Array[]> {
  const copy = new Map<number, Uint8Array[]>();
  for (const [type, values] of attrs ?? []) {
    copy.set(type, [...values]);
  }
  return copy;
}

/** Builds a {@link ReceiptPayload} by hand, for callers' own tests. Fields default to absent. */
export function createReceiptPayload(
  fields: Partial<Omit<ReceiptPayload, 'toJson'>>,
): ReceiptPayload {
  return buildReceiptPayload(
    {
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
      preorderDateMs: fields.preorderDateMs ?? null,
      originalApplicationVersion: fields.originalApplicationVersion ?? null,
      expirationDateMs: fields.expirationDateMs ?? null,
      environment: fields.environment ?? null,
    },
    fields.inApp ? [...fields.inApp] : [],
    copyUnknownAttributes(fields.unknownAttributes),
  );
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
    cancellationReason: fields.cancellationReason ?? null,
    isTrialPeriod: fields.isTrialPeriod ?? null,
    isInIntroOfferPeriod: fields.isInIntroOfferPeriod ?? null,
    unknownAttributes: copyUnknownAttributes(fields.unknownAttributes),
  };
}

// --- the module's payload JSON -> ReceiptPayload ----------------------------

/** The module's answer does not have the shape this package reads. */
export class WireError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'WireError';
  }
}

type Json = Record<string, unknown>;

function object(value: unknown, where: string): Json {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new WireError(`${where} is not an object`);
  }
  return value as Json;
}

function field<T>(obj: Json, key: string, kind: 'string' | 'number' | 'boolean'): T | null {
  const value = obj[key];
  if (value === null) {
    return null;
  }
  if (typeof value !== kind) {
    throw new WireError(`${key} is not a ${kind} or null`);
  }
  return value as T;
}

const str = (obj: Json, key: string): string | null => field<string>(obj, key, 'string');
const num = (obj: Json, key: string): number | null => field<number>(obj, key, 'number');
const bool = (obj: Json, key: string): boolean | null => field<boolean>(obj, key, 'boolean');

function bytesField(obj: Json, key: string): Uint8Array | null {
  const text = str(obj, key);
  return text === null ? null : bytesFromBase64(text);
}

function unknownAttributesField(obj: Json): Map<number, Uint8Array[]> {
  const out = new Map<number, Uint8Array[]>();
  for (const [key, values] of Object.entries(
    object(obj['unknown_attributes'], 'unknown_attributes'),
  )) {
    const type = Number(key);
    if (!Number.isSafeInteger(type) || String(type) !== key || !Array.isArray(values)) {
      throw new WireError('unknown_attributes has an entry that is not a type and a list');
    }
    out.set(
      type,
      values.map((v: unknown) => {
        if (typeof v !== 'string') {
          throw new WireError('an unknown attribute value is not a string');
        }
        return bytesFromBase64(v);
      }),
    );
  }
  return out;
}

function inAppFromWire(value: unknown): InAppPurchase {
  const obj = object(value, 'an in_app entry');
  return {
    quantity: num(obj, 'quantity'),
    productId: str(obj, 'product_id'),
    transactionId: str(obj, 'transaction_id'),
    purchaseDateMs: num(obj, 'purchase_date_ms'),
    originalTransactionId: str(obj, 'original_transaction_id'),
    originalPurchaseDateMs: num(obj, 'original_purchase_date_ms'),
    expiresDateMs: num(obj, 'expires_date_ms'),
    webOrderLineItemId: str(obj, 'web_order_line_item_id'),
    cancellationDateMs: num(obj, 'cancellation_date_ms'),
    cancellationReason:
      obj.cancellation_reason === undefined ? null : str(obj, 'cancellation_reason'),
    isTrialPeriod: bool(obj, 'is_trial_period'),
    isInIntroOfferPeriod: bool(obj, 'is_in_intro_offer_period'),
    unknownAttributes: unknownAttributesField(obj),
  };
}

/**
 * A {@link ReceiptPayload} from the `payload` member of a verified receipt
 * answer and the `environment` member beside it.
 */
export function receiptPayloadFromWire(
  value: unknown,
  environment: Environment | null,
): ReceiptPayload {
  const obj = object(value, 'the receipt payload');
  const inApp = obj['in_app'];
  if (!Array.isArray(inApp)) {
    throw new WireError('in_app is not a list');
  }
  return buildReceiptPayload(
    {
      receiptType: str(obj, 'receipt_type'),
      appItemId: str(obj, 'app_item_id'),
      bundleId: str(obj, 'bundle_id'),
      bundleIdBytes: bytesField(obj, 'bundle_id_bytes'),
      applicationVersion: str(obj, 'application_version'),
      opaqueValue: bytesField(obj, 'opaque_value'),
      sha1Hash: bytesField(obj, 'sha1_hash'),
      receiptCreationDateMs: num(obj, 'receipt_creation_date_ms'),
      downloadId: str(obj, 'download_id'),
      versionExternalIdentifier: str(obj, 'version_external_identifier'),
      originalPurchaseDateMs: num(obj, 'original_purchase_date_ms'),
      preorderDateMs: num(obj, 'preorder_date_ms'),
      originalApplicationVersion: str(obj, 'original_application_version'),
      expirationDateMs: num(obj, 'expiration_date_ms'),
      environment,
    },
    inApp.map(inAppFromWire),
    unknownAttributesField(obj),
  );
}

/** The `root` bytes as the padded standard base64 `init` reads. */
export function rootToBase64(root: Uint8Array): string {
  return base64FromBytes(root);
}
