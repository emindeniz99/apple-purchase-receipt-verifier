/**
 * `verifyReceiptEndpoint(environment, requestJson)` for the web build —
 * the same rendering as the Node build's verify-receipt-endpoint.ts, async
 * because the receipt verification underneath it is.
 */
import { formatGmt, formatPacific } from '../apple-date.js';
import { callClock } from '../call-clock.js';
import { AppleStatus, Environment, environmentFromReceiptType } from '../environment.js';
import { Reason, VerificationError } from '../errors.js';
import { JsonError, asString, parseOneValue } from '../json.js';
import { MAX_REQUEST_BYTES, utf8LengthExceeds } from '../limits.js';
import type { InAppPurchase, ReceiptPayload } from '../receipt-payload.js';
import type { ParsedCertificate } from '../x509.js';
import { verifyReceipt } from './receipt.js';

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
    default:
      return AppleStatus.INTERNAL_DATA_ACCESS_ERROR;
  }
}

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

export async function respond(
  environment: Environment,
  requestJson: string,
  anchors: readonly ParsedCertificate[],
  rawClock: () => number,
): Promise<string> {
  const clock = callClock(rawClock);
  let status: number;
  let receipt: ReceiptPayload | null = null;
  let requestDateMs = 0;
  try {
    const receiptData = receiptDataOf(typeof requestJson === 'string' ? requestJson : '');
    receipt = await verifyReceipt(receiptData, anchors, clock);
    status = statusForEnvironment(environment, receipt);
    if (status === AppleStatus.OK) {
      requestDateMs = clock();
    }
  } catch (cause) {
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

function jsonRawNumber(value: string | null): string | null {
  return value;
}

function field(key: string, jsonValue: string | null): string | null {
  return jsonValue === null ? null : `${JSON.stringify(key)}:${jsonValue}`;
}

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
