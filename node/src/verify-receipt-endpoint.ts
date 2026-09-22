import { Reason, VerificationError } from './errors.js';
import { normalizeRoots, type RootInput } from './chain.js';
import { normalizeClock, type Clock } from './jws-claims.js';
import {
  decodeReceiptDataString,
  verifyReceiptCore,
  type AppReceipt,
  type InAppPurchase,
} from './receipt.js';

/**
 * Drop-in local replacement for Apple's deprecated `verifyReceipt` endpoint:
 * same request body, same response body shape, same status codes — but
 * verified offline against the pinned Apple root instead of by calling
 * Apple. Field-by-field fidelity and the unavoidable gaps (fields that only
 * exist in Apple's server-side subscription database, like
 * `latest_receipt_info` / `pending_renewal_info`) are documented in
 * COMPARISON.md.
 *
 * Like Apple's endpoint, this does NOT check the bundle id — the caller
 * compares `receipt.bundle_id`, exactly as with the real endpoint.
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

const MALFORMED_JSON = `{"status":${Status.MALFORMED}}`;

export interface VerifyReceiptEndpointOptions {
  /** Pinned roots (production: `appleReceiptRoots()`). */
  trustedRoots: RootInput[];
  /** Which environment this endpoint instance emulates (21007/21008 routing). */
  environment: 'Production' | 'Sandbox';
  /**
   * Optional source of "now", the same option the JWS verifier takes.
   * The only wall-clock-dependent output here is the `request_date*` triple
   * (the instant the request was answered), so that is what it drives.
   * Omitted, the system clock is used.
   */
  clock?: Clock | null;
}

export class VerifyReceiptEndpoint {
  #roots: RootInput[];
  #environment: 'Production' | 'Sandbox';
  #clock: Clock;

  constructor({ trustedRoots, environment, clock = null }: VerifyReceiptEndpointOptions) {
    normalizeRoots(trustedRoots); // validate eagerly
    if (environment !== 'Production' && environment !== 'Sandbox') {
      throw new TypeError("environment must be 'Production' or 'Sandbox'");
    }
    this.#roots = trustedRoots;
    this.#environment = environment;
    this.#clock = normalizeClock(clock);
  }

  /**
   * Handles one verifyReceipt request body. Never throws — like the real
   * endpoint, failures are reported through `status`.
   *
   * `adam_id`, `app_item_id`, `download_id` and
   * `version_external_identifier` come back as **bigints**: Apple's download
   * ids are eighteen digits, so a `number` would hand back a rounded id.
   * Plain `JSON.stringify` on this object still works — the receipt carries
   * a `toJSON` that renders them as JSON numbers, which is what
   * `JSON.parse` of Apple's own answer yields in JavaScript anyway. Use
   * {@link verifyReceiptJson} when the digits past 2^53 have to survive
   * into the wire text.
   */
  verifyReceipt(requestBody: unknown): VerifyReceiptResponseBody {
    const receiptData = (requestBody as VerifyReceiptRequestBody | null)?.['receipt-data'];
    if (
      typeof requestBody !== 'object' ||
      requestBody === null ||
      typeof receiptData !== 'string' ||
      receiptData.length === 0
    ) {
      return { status: Status.MALFORMED };
    }
    try {
      const fields: AppReceipt = verifyReceiptCore(
        decodeReceiptDataString(receiptData),
        this.#roots,
      );

      // 21007/21008 environment routing from the receipt_type attribute.
      // Production types are exactly "Production" and "ProductionVPP";
      // everything else ("ProductionSandbox", "ProductionVPPSandbox",
      // "Xcode", or a missing attribute) fails closed as non-production.
      // "Xcode" is listed for completeness only: an Xcode-generated
      // receipt is not Apple-signed, so it fails chain verification with
      // 21003 above and never reaches this branch.
      const productionReceipt =
        fields.receiptType === 'Production' || fields.receiptType === 'ProductionVPP';
      if (this.#environment === 'Production' && !productionReceipt) {
        return { status: Status.SANDBOX_RECEIPT_ON_PRODUCTION };
      }
      if (this.#environment === 'Sandbox' && productionReceipt) {
        return { status: Status.PRODUCTION_RECEIPT_ON_SANDBOX };
      }
      // Building the response stays inside the guard: receiptJson formats
      // dates through Intl.DateTimeFormat with named time zones, which
      // throws on a Node built without full ICU. Any such throw becomes
      // 21009 instead of escaping the documented "never throws" contract.
      return {
        status: Status.OK,
        environment: this.#environment,
        receipt: receiptJson(fields, this.#clock()),
      };
    } catch (error) {
      if (error instanceof VerificationError) {
        return {
          status:
            error.reason === Reason.INVALID_RECEIPT_FORMAT
              ? Status.MALFORMED
              : Status.NOT_AUTHENTICATED,
        };
      }
      return { status: Status.INTERNAL };
    }
  }

  /**
   * Handles one verifyReceipt request body in its raw wire form: the JSON
   * request body in, the JSON response body out, so an HTTP framework's
   * body can be piped straight through without a DTO in between. A thin
   * wrapper over `verifyReceipt` — every verification decision is made
   * there.
   *
   * A body that is not a JSON object (unparseable, `null`, an array, a
   * scalar) answers `{"status":21002}`. Apple has no status code for "that
   * wasn't JSON"; 21002 ("The data in the receipt-data property was
   * malformed or missing") is the closest, and it is what a JSON object
   * without usable `receipt-data` gets anyway.
   *
   * Output is deterministic — the response object preserves insertion
   * order, so equal inputs serialize to equal bytes. Key order is not part
   * of the JSON contract.
   *
   * This is the entry point that emits the four id keys with every digit
   * intact (`"download_id":9223372036854775807`), which no `JSON.stringify` of
   * the object form can do on Node 20 — see {@link stringifyResponse}.
   */
  verifyReceiptJson(body: string): string {
    let parsed: unknown;
    try {
      parsed = JSON.parse(body);
    } catch {
      return MALFORMED_JSON;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      return MALFORMED_JSON;
    }
    return stringifyResponse(this.verifyReceipt(parsed));
  }
}

// The keys whose values are bigints, and therefore the only places the
// quote-stripping below may fire. A string anywhere in the response cannot
// impersonate one: a quote inside a JSON string is escaped, so `\"download_id\":`
// in someone's product id does not match.
const QUOTED_ID = /("(?:adam_id|app_item_id|download_id|version_external_identifier)":)"(\d+)"/g;

/**
 * `JSON.stringify` for a response whose ids are bigints. `JSON.stringify`
 * refuses a bigint outright, and Node 20 — this package's engines floor —
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

function receiptJson(fields: AppReceipt, requestDate: Date): Record<string, unknown> {
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
  // Beyond 2^53 that rounds — `verifyReceiptJson` is the way to the exact
  // digits, and the bigints themselves stay on this object.
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

function inAppJson(purchase: InAppPurchase): Record<string, unknown> {
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
  target[prefix] = formatInZone(date, 'UTC', 'Etc/GMT');
  target[`${prefix}_ms`] = String(date.getTime());
  target[`${prefix}_pst`] = formatInZone(date, 'America/Los_Angeles', 'America/Los_Angeles');
}

function formatInZone(date: Date, timeZone: string, label: string): string {
  const parts = new Intl.DateTimeFormat('en-CA', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(date);
  const get = (type: string): string => parts.find((p) => p.type === type)?.value ?? '00';
  return (
    `${get('year')}-${get('month')}-${get('day')} ` +
    `${get('hour')}:${get('minute')}:${get('second')} ${label}`
  );
}
