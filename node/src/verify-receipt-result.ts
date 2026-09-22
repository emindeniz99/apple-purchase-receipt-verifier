import { formatGmt, formatPacific } from './apple-date.js';
import { Reason, VerificationError } from './errors.js';
import type { RawAppReceipt, RawInAppPurchase } from './receipt-payload.js';

/**
 * The outcome type both `VerifyReceiptEndpoint`s return, and the rendering
 * of Apple's response body it carries. Runtime-neutral: the default and the
 * web entry point share this module, so the two answer the same bytes.
 */

/** https://developer.apple.com/documentation/appstorereceipts/requestbody */
export interface VerifyReceiptRequestBody {
  'receipt-data': string;
  /** Accepted for compatibility; cannot be validated locally (see COMPARISON.md). */
  password?: string;
  /** Accepted for compatibility; no effect (we never produce latest_receipt_info). */
  'exclude-old-transactions'?: boolean;
}

/** https://developer.apple.com/documentation/appstorereceipts/responsebody */
export interface VerifyReceiptResponseBody {
  status: number;
  environment?: 'Production' | 'Sandbox';
  receipt?: Record<string, unknown>;
}

/** Apple status codes this local implementation can produce. */
export const Status = {
  OK: 0,
  /** Malformed request or receipt-data property. */
  MALFORMED: 21002,
  /** Receipt could not be authenticated. */
  NOT_AUTHENTICATED: 21003,
  /** Sandbox receipt sent to the production environment. */
  SANDBOX_RECEIPT_ON_PRODUCTION: 21007,
  /** Production receipt sent to the sandbox environment. */
  PRODUCTION_RECEIPT_ON_SANDBOX: 21008,
  /** Internal error. */
  INTERNAL: 21009,
} as const;

/** The two environments Apple's endpoint exists in. */
export type EndpointEnvironment = 'Production' | 'Sandbox';

/** The receipt fields a response renders; both builds' receipt types have them. */
type RenderedReceipt = Omit<
  RawAppReceipt,
  'unknownAttributes' | 'bundleIdBytes' | 'opaqueValue' | 'sha1Hash' | 'inAppPurchases'
> & { inAppPurchases: Omit<RawInAppPurchase, 'unknownAttributes'>[] };

interface VerifyReceiptResultMembers {
  /** The Apple status for the endpoint's own environment. */
  readonly status: number;
  /**
   * The instant rendered as `request_date`, fixed when the call was made. A
   * new `Date` on every read, so the result cannot be changed through it.
   */
  readonly requestDate: Date;
  /**
   * The response an endpoint of `environment` (default: the endpoint's own)
   * answers, as a new object on each call. A production receipt answers 0
   * on Production and 21008 on Sandbox; any other receipt answers 21007 on
   * Production and 0 on Sandbox; a failed result answers its own status on
   * both. Throws a TypeError for any other environment, as the endpoint
   * constructor does.
   */
  toResponse(environment?: EndpointEnvironment): VerifyReceiptResponseBody;
  /**
   * {@link toResponse} as the JSON response body, with the receipt ids
   * written with every digit.
   */
  toJson(environment?: EndpointEnvironment): string;
}

/**
 * The receipt verified. `receipt` is set for 21007 and 21008 too: those say
 * the receipt belongs to the other environment, not that it failed.
 */
export interface VerifiedReceiptResult<R> extends VerifyReceiptResultMembers {
  readonly verified: true;
  readonly receipt: R;
  readonly failureReason: null;
  readonly failureCause: null;
}

/** The receipt did not verify, or the request carried none. */
export interface FailedReceiptResult extends VerifyReceiptResultMembers {
  readonly verified: false;
  readonly receipt: null;
  /** Why there is no receipt. */
  readonly failureReason: Reason;
  /** The value caught behind {@link Reason.INTERNAL_ERROR}; null for every other reason. */
  readonly failureCause: unknown;
}

/**
 * The outcome of one `VerifyReceiptEndpoint` call: the Apple status, the
 * verified receipt or the reason there is none, and the Apple-shaped
 * response, rendered only when asked for. `if (result.verified)` narrows to
 * the receipt. Immutable; only the endpoint creates one.
 */
export type VerifyReceiptResult<R> = VerifiedReceiptResult<R> | FailedReceiptResult;

// Held only by this module, so `new result.constructor(...)` cannot fabricate
// a status-0 result from outside it.
const CONSTRUCT = Symbol('VerifyReceiptResult');

class Result<R extends RenderedReceipt> {
  readonly verified: boolean;
  readonly receipt: R | null;
  readonly failureReason: Reason | null;
  readonly failureCause: unknown;
  readonly status: number;
  readonly #environment: EndpointEnvironment;
  readonly #requestDateMs: number;
  // Captured once: the status routing never re-reads the receipt object,
  // which is a plain object a caller could write to.
  readonly #productionReceipt: boolean;

  constructor(
    token: typeof CONSTRUCT,
    environment: EndpointEnvironment,
    receipt: R | null,
    failureReason: Reason | null,
    failureCause: unknown,
    requestDateMs: number,
  ) {
    if (token !== CONSTRUCT) {
      throw new TypeError('only VerifyReceiptEndpoint creates a VerifyReceiptResult');
    }
    this.verified = receipt !== null;
    this.receipt = receipt;
    this.failureReason = failureReason;
    this.failureCause = failureCause;
    this.#environment = environment;
    this.#requestDateMs = requestDateMs;
    // 21007/21008 environment routing from the receipt_type attribute.
    // Production types are exactly "Production" and "ProductionVPP";
    // everything else ("ProductionSandbox", "ProductionVPPSandbox",
    // "Xcode", or a missing attribute) fails closed as non-production.
    // "Xcode" is listed for completeness only: an Xcode-generated receipt
    // is not Apple-signed, so it fails chain verification with 21003 and
    // never gets here.
    this.#productionReceipt =
      receipt !== null &&
      (receipt.receiptType === 'Production' || receipt.receiptType === 'ProductionVPP');
    this.status = this.#statusFor(environment);
    Object.freeze(this);
  }

  get requestDate(): Date {
    return new Date(this.#requestDateMs);
  }

  toResponse(environment: EndpointEnvironment = this.#environment): VerifyReceiptResponseBody {
    const status = this.#statusFor(environment);
    if (status !== Status.OK || this.receipt === null) {
      return { status };
    }
    try {
      return {
        status,
        environment,
        receipt: receiptJson(this.receipt, this.requestDate),
      };
    } catch {
      // A date outside the range apple-date.ts formats itself (an invalid
      // request date among them) goes through Intl, which throws on a
      // runtime without it or without full ICU. The endpoint has always
      // answered 21009 for that rather than letting the throw escape.
      return { status: Status.INTERNAL };
    }
  }

  toJson(environment: EndpointEnvironment = this.#environment): string {
    return stringifyResponse(this.toResponse(environment));
  }

  #statusFor(environment: EndpointEnvironment): number {
    requireEndpointEnvironment(environment);
    if (this.receipt === null) {
      switch (this.failureReason) {
        case Reason.MALFORMED_REQUEST:
        case Reason.INVALID_RECEIPT_FORMAT:
          return Status.MALFORMED;
        case Reason.INTERNAL_ERROR:
          return Status.INTERNAL;
        default:
          return Status.NOT_AUTHENTICATED;
      }
    }
    if (environment === 'Production' && !this.#productionReceipt) {
      return Status.SANDBOX_RECEIPT_ON_PRODUCTION;
    }
    if (environment === 'Sandbox' && this.#productionReceipt) {
      return Status.PRODUCTION_RECEIPT_ON_SANDBOX;
    }
    return Status.OK;
  }
}

/** Refuses an environment Apple's endpoint does not exist in. */
export function requireEndpointEnvironment(
  environment: unknown,
): asserts environment is EndpointEnvironment {
  if (environment !== 'Production' && environment !== 'Sandbox') {
    throw new TypeError("environment must be 'Production' or 'Sandbox'");
  }
}

/** A verified result. For the endpoints only. */
export function verifiedResult<R extends RenderedReceipt>(
  environment: EndpointEnvironment,
  receipt: R,
  requestDateMs: number,
): VerifyReceiptResult<R> {
  return new Result(
    CONSTRUCT,
    environment,
    receipt,
    null,
    null,
    requestDateMs,
  ) as unknown as VerifyReceiptResult<R>;
}

/**
 * The result for a caught error: its reason when it is a
 * {@link VerificationError}, INTERNAL_ERROR with the error kept otherwise.
 * For the endpoints only.
 */
export function failedResult(
  environment: EndpointEnvironment,
  error: unknown,
  requestDateMs: number,
): FailedReceiptResult {
  const internal = !(error instanceof VerificationError);
  return new Result<RenderedReceipt>(
    CONSTRUCT,
    environment,
    null,
    internal ? Reason.INTERNAL_ERROR : error.reason,
    internal ? error : null,
    requestDateMs,
  ) as unknown as FailedReceiptResult;
}

/** A request that carries no usable receipt-data. For the endpoints only. */
export function malformedRequest(
  environment: EndpointEnvironment,
  requestDateMs: number,
): FailedReceiptResult {
  return new Result<RenderedReceipt>(
    CONSTRUCT,
    environment,
    null,
    Reason.MALFORMED_REQUEST,
    null,
    requestDateMs,
  ) as unknown as FailedReceiptResult;
}

/**
 * The request_date instant as epoch milliseconds: the explicit one when
 * given, the clock otherwise. Read once per call, before anything else.
 */
export function requestInstant(requestDate: Date | null | undefined, clock: () => Date): number {
  return (requestDate ?? clock()).getTime();
}

/**
 * `receipt-data` of a request object, or undefined when the request is not
 * an object. A getter that throws is left to throw: the caller turns that
 * into INTERNAL_ERROR.
 */
export function receiptDataOf(requestBody: unknown): unknown {
  if (typeof requestBody !== 'object' || requestBody === null) {
    return undefined;
  }
  return (requestBody as Partial<VerifyReceiptRequestBody>)['receipt-data'];
}

/**
 * Parses a raw JSON request body. A body that is not a string, not JSON, or
 * not a JSON object (null, an array, a scalar) comes back as undefined, the
 * value that answers 21002. Apple has no status code for "that wasn't JSON";
 * 21002 ("The data in the receipt-data property was malformed or missing") is
 * the closest, and it is what a JSON object without usable `receipt-data`
 * gets anyway.
 */
export function parseRequestJson(body: unknown): object | undefined {
  if (typeof body !== 'string') {
    return undefined;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(body);
  } catch {
    return undefined;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return undefined;
  }
  return parsed;
}

// The keys whose values are bigints, and therefore the only places the
// quote-stripping below may fire. A string anywhere in the response cannot
// impersonate one: a quote inside a JSON string is escaped, so `\"download_id\":`
// in someone's product id does not match.
const QUOTED_ID = /("(?:adam_id|app_item_id|download_id|version_external_identifier)":)"(\d+)"/g;

/**
 * `JSON.stringify` for a response whose ids are bigints. `JSON.stringify`
 * refuses a bigint outright, and Node 20 (this package's engines floor)
 * has no `JSON.rawJSON` to hand it an exact number with, so the text is
 * built in two deterministic steps: the replacer renders each bigint as its
 * decimal digits inside a JSON string, then the quotes come back off at
 * exactly the four keys that carry one. Spreading first drops the receipt's
 * `toJSON` (see {@link receiptJson}), whose whole job is to flatten those
 * bigints to doubles for callers who serialize the object themselves.
 */
function stringifyResponse(response: VerifyReceiptResponseBody): string {
  const exact =
    response.receipt === undefined ? response : { ...response, receipt: { ...response.receipt } };
  return JSON.stringify(exact, (_key: string, value: unknown): unknown =>
    typeof value === 'bigint' ? value.toString() : value,
  ).replace(QUOTED_ID, '$1$2');
}

function receiptJson(fields: RenderedReceipt, requestDate: Date): Record<string, unknown> {
  const receipt: Record<string, unknown> = {};
  put(receipt, 'receipt_type', fields.receiptType);
  // Apple echoes attribute 1 under both names — its response reference
  // defines adam_id as "See app_item_id" — and as JSON numbers, not as the
  // strings the in-app integers are rendered with.
  put(receipt, 'adam_id', fields.appItemId);
  put(receipt, 'app_item_id', fields.appItemId);
  put(receipt, 'bundle_id', fields.bundleId);
  put(receipt, 'application_version', fields.appVersion);
  put(receipt, 'download_id', fields.downloadId);
  put(receipt, 'version_external_identifier', fields.versionExternalIdentifier);
  put(receipt, 'original_application_version', fields.originalAppVersion);
  appleDates(receipt, 'receipt_creation_date', fields.creationDate);
  appleDates(receipt, 'request_date', requestDate);
  appleDates(receipt, 'original_purchase_date', fields.originalPurchaseDate);
  appleDates(receipt, 'expiration_date', fields.expirationDate);
  receipt['in_app'] = fields.inAppPurchases.map(inAppJson);
  // Plain `JSON.stringify(response)` must not throw on the bigint ids, so
  // the receipt renders itself: each id becomes a JSON number, which is
  // exactly what `JSON.parse` of Apple's own answer produces in JavaScript.
  // Beyond 2^53 that rounds; `toJson` is the way to the exact digits, and
  // the bigints themselves stay on this object.
  Object.defineProperty(receipt, 'toJSON', {
    value: (): Record<string, unknown> =>
      Object.fromEntries(
        Object.entries(receipt).map(([key, value]) => [
          key,
          typeof value === 'bigint' ? Number(value) : value,
        ]),
      ),
  });
  return receipt;
}

function inAppJson(purchase: Omit<RawInAppPurchase, 'unknownAttributes'>): Record<string, unknown> {
  const entry: Record<string, unknown> = {};
  put(entry, 'quantity', purchase.quantity === null ? null : String(purchase.quantity));
  put(entry, 'product_id', purchase.productId);
  put(entry, 'transaction_id', purchase.transactionId);
  put(entry, 'original_transaction_id', purchase.originalTransactionId);
  appleDates(entry, 'purchase_date', purchase.purchaseDate);
  appleDates(entry, 'original_purchase_date', purchase.originalPurchaseDate);
  appleDates(entry, 'expires_date', purchase.expiresDate);
  appleDates(entry, 'cancellation_date', purchase.cancellationDate);
  put(
    entry,
    'web_order_line_item_id',
    purchase.webOrderLineItemId === null ? null : String(purchase.webOrderLineItemId),
  );
  put(
    entry,
    'is_trial_period',
    purchase.isTrialPeriod === null ? null : String(purchase.isTrialPeriod === 1),
  );
  put(
    entry,
    'is_in_intro_offer_period',
    purchase.isInIntroOfferPeriod === null ? null : String(purchase.isInIntroOfferPeriod === 1),
  );
  return entry;
}

function put(target: Record<string, unknown>, key: string, value: unknown): void {
  if (value !== null && value !== undefined) {
    target[key] = value;
  }
}

/** Apple's three date renderings: `x` (GMT), `x_ms` (epoch ms), `x_pst`. */
function appleDates(target: Record<string, unknown>, prefix: string, date: Date | null): void {
  if (date === null) {
    return;
  }
  target[prefix] = formatGmt(date);
  target[`${prefix}_ms`] = String(date.getTime());
  target[`${prefix}_pst`] = formatPacific(date);
}
