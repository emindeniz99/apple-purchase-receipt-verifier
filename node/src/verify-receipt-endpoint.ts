/**
 * `verifyReceiptEndpoint(environment, requestJson)`: a local stand-in for
 * Apple's deprecated verifyReceipt endpoint. Same request body, same
 * response body, same status codes, but verified offline against the
 * pinned roots instead of by calling Apple. Fields that exist only in
 * Apple's server-side database (`latest_receipt_info`,
 * `pending_renewal_info`, `latest_receipt`) are never produced
 * (COMPARISON.md). Like Apple's endpoint, this checks no bundle id — the
 * caller compares `receipt.bundle_id`.
 *
 * The response is assembled by hand rather than through `JSON.stringify`:
 * `adam_id`, `app_item_id`, `download_id` and `version_external_identifier`
 * are Apple's own JSON *numbers*, and this library's ids are decimal
 * strings precisely so no digit is lost to a `number` — writing them
 * unquoted here keeps every digit on the wire the way Apple's own endpoint
 * does.
 */
import { formatGmt, formatPacific } from './apple-date.js';
import { callClock } from './call-clock.js';
import { AppleStatus, Environment, environmentFromReceiptType } from './environment.js';
import { Reason, VerificationError } from './errors.js';
import { JsonError, asString, parseOneValue } from './json.js';
import { MAX_REQUEST_BYTES, utf8LengthExceeds } from './limits.js';
import type { InAppPurchase, ReceiptPayload } from './receipt-payload.js';
import { verifyReceipt } from './receipt.js';
import type { ParsedCertificate } from './x509.js';

export { MAX_REQUEST_BYTES };

function statusForReason(reason: Reason): number {
  switch (reason) {
    case Reason.MALFORMED:
    case Reason.TOO_LARGE:
      return AppleStatus.MALFORMED_RECEIPT_DATA;
    case Reason.INVALID_SIGNATURE:
    case Reason.UNTRUSTED_CHAIN:
    case Reason.INVALID_CERTIFICATE:
    case Reason.INVALID_CERTIFICATE_PURPOSE:
      return AppleStatus.RECEIPT_NOT_AUTHENTICATED;
    default: // UNREADABLE_PAYLOAD, INTERNAL_ERROR
      return AppleStatus.INTERNAL_DATA_ACCESS_ERROR;
  }
}

/**
 * The `receipt-data` string of a request body. A body over
 * {@link MAX_REQUEST_BYTES} is TOO_LARGE; a body that is not a JSON object
 * (unparseable, empty, an array, a scalar), or that nests deeper than 64,
 * and a `receipt-data` that is missing or not a string, are MALFORMED.
 * `password` and `exclude-old-transactions` are read and ignored — by not
 * being read at all. The last `receipt-data` member wins, as in a map;
 * anything after the top-level object is not read.
 */
function receiptDataOf(requestJson: string): string {
  if (requestJson === '') {
    throw new VerificationError(Reason.MALFORMED, 'request body is empty');
  }
  if (utf8LengthExceeds(requestJson, MAX_REQUEST_BYTES)) {
    throw new VerificationError(
      Reason.TOO_LARGE,
      `request body exceeds the maximum of ${MAX_REQUEST_BYTES} bytes`,
    );
  }
  let value;
  try {
    ({ value } = parseOneValue(requestJson));
  } catch (cause) {
    if (cause instanceof JsonError) {
      throw new VerificationError(Reason.MALFORMED, 'request body is not valid JSON', cause);
    }
    throw cause;
  }
  if (value.kind !== 'object') {
    throw new VerificationError(Reason.MALFORMED, 'request body is not a JSON object');
  }
  const receiptData = asString(value.members.get('receipt-data'));
  if (receiptData === null) {
    throw new VerificationError(Reason.MALFORMED, 'receipt-data is missing or not a string');
  }
  return receiptData;
}

export function respond(
  environment: Environment,
  requestJson: string,
  anchors: readonly ParsedCertificate[],
  rawClock: () => number,
): string {
  // One memoized clock for the whole call, shared with the internal
  // verifyReceipt so a receipt with no creation date and `request_date`
  // see the same instant, and read at most once.
  const clock = callClock(rawClock);
  let status: number;
  let receipt: ReceiptPayload | null = null;
  let requestDateMs = 0;
  try {
    const receiptData = receiptDataOf(typeof requestJson === 'string' ? requestJson : '');
    receipt = verifyReceipt(receiptData, anchors, clock);
    status = statusForEnvironment(environment, receipt);
    if (status === AppleStatus.OK) {
      requestDateMs = clock();
    }
  } catch (cause) {
    // Never let an unexpected error escape the endpoint; it always answers
    // a status, never throws.
    status =
      cause instanceof VerificationError
        ? statusForReason(cause.reason)
        : AppleStatus.INTERNAL_DATA_ACCESS_ERROR;
  }
  return renderResponse(status, environment, receipt, requestDateMs);
}

function statusForEnvironment(environment: Environment, receipt: ReceiptPayload): number {
  const productionReceipt =
    environmentFromReceiptType(receipt.receiptType) === Environment.PRODUCTION;
  if (environment === Environment.PRODUCTION && !productionReceipt) {
    return AppleStatus.SANDBOX_RECEIPT_ON_PRODUCTION;
  }
  if (environment === Environment.SANDBOX && productionReceipt) {
    return AppleStatus.PRODUCTION_RECEIPT_ON_SANDBOX;
  }
  return AppleStatus.OK;
}

function jsonString(value: string | null): string | null {
  return value === null ? null : JSON.stringify(value);
}

/** `value` is already a clean base-10 integer (or null); embedded unquoted, it is a JSON number. */
function jsonRawNumber(value: string | null): string | null {
  return value;
}

function field(key: string, jsonValue: string | null): string | null {
  return jsonValue === null ? null : `${JSON.stringify(key)}:${jsonValue}`;
}

/** Apple's three date renderings: `x` (GMT), `x_ms`, `x_pst`. Omitted together when `ms` is null. */
function appleDateFields(prefix: string, ms: number | null): (string | null)[] {
  if (ms === null) {
    return [];
  }
  const date = new Date(ms);
  return [
    field(prefix, jsonString(formatGmt(date))),
    field(`${prefix}_ms`, jsonString(String(ms))),
    field(`${prefix}_pst`, jsonString(formatPacific(date))),
  ];
}

function objectOf(parts: readonly (string | null)[]): string {
  return `{${parts.filter((p): p is string => p !== null).join(',')}}`;
}

function purchaseJson(purchase: InAppPurchase): string {
  return objectOf([
    field('quantity', jsonString(purchase.quantity === null ? null : String(purchase.quantity))),
    field('product_id', jsonString(purchase.productId)),
    field('transaction_id', jsonString(purchase.transactionId)),
    field('original_transaction_id', jsonString(purchase.originalTransactionId)),
    ...appleDateFields('purchase_date', purchase.purchaseDateMs),
    ...appleDateFields('original_purchase_date', purchase.originalPurchaseDateMs),
    ...appleDateFields('expires_date', purchase.expiresDateMs),
    ...appleDateFields('cancellation_date', purchase.cancellationDateMs),
    // Apple omits the key when attribute 1711 is 0, as it does for consumables.
    purchase.webOrderLineItemId !== null && purchase.webOrderLineItemId !== '0'
      ? field('web_order_line_item_id', jsonString(purchase.webOrderLineItemId))
      : null,
    purchase.isTrialPeriod !== null
      ? field('is_trial_period', jsonString(String(purchase.isTrialPeriod)))
      : null,
    purchase.isInIntroOfferPeriod !== null
      ? field('is_in_intro_offer_period', jsonString(String(purchase.isInIntroOfferPeriod)))
      : null,
  ]);
}

function receiptJson(receipt: ReceiptPayload, requestDateMs: number): string {
  return objectOf([
    field('receipt_type', jsonString(receipt.receiptType)),
    // Apple echoes attribute 1 under both names as JSON numbers.
    field('adam_id', jsonRawNumber(receipt.appItemId)),
    field('app_item_id', jsonRawNumber(receipt.appItemId)),
    field('bundle_id', jsonString(receipt.bundleId)),
    field('application_version', jsonString(receipt.applicationVersion)),
    field('download_id', jsonRawNumber(receipt.downloadId)),
    field('version_external_identifier', jsonRawNumber(receipt.versionExternalIdentifier)),
    field('original_application_version', jsonString(receipt.originalApplicationVersion)),
    ...appleDateFields('receipt_creation_date', receipt.receiptCreationDateMs),
    ...appleDateFields('request_date', requestDateMs),
    ...appleDateFields('original_purchase_date', receipt.originalPurchaseDateMs),
    ...appleDateFields('expiration_date', receipt.expirationDateMs),
    `"in_app":[${receipt.inApp.map(purchaseJson).join(',')}]`,
  ]);
}

function renderResponse(
  status: number,
  environment: Environment,
  receipt: ReceiptPayload | null,
  requestDateMs: number,
): string {
  if (status !== AppleStatus.OK || receipt === null) {
    return `{"status":${status}}`;
  }
  return `{"status":${status},"environment":${JSON.stringify(environment)},"receipt":${receiptJson(receipt, requestDateMs)}}`;
}
