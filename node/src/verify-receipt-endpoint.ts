import { normalizeRoots, type RootInput } from './chain.js';
import { normalizeClock, type Clock } from './jws-claims.js';
import { MAX_REQUEST_BYTES } from './limits.js';
import { decodeReceiptDataString, verifyReceiptCore, type AppReceipt } from './receipt.js';
import {
  failedResult,
  malformedRequest,
  parseRequestJson,
  receiptDataOf,
  requestInstant,
  requireEndpointEnvironment,
  verifiedResult,
  type EndpointEnvironment,
  type VerifyReceiptResult as SharedVerifyReceiptResult,
} from './verify-receipt-result.js';

export {
  Status,
  type VerifyReceiptRequestBody,
  type VerifyReceiptResponseBody,
} from './verify-receipt-result.js';

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

/**
 * The outcome of one {@link VerifyReceiptEndpoint} call. `if
 * (result.verified)` narrows `result.receipt` to the verified
 * {@link AppReceipt}; otherwise `result.failureReason` says why there is
 * none.
 */
export type VerifyReceiptResult = SharedVerifyReceiptResult<AppReceipt>;

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
  /**
   * Ceiling on a raw JSON request body, in UTF-8 bytes, checked before it is
   * parsed. A larger body, or one nesting JSON more than 64 levels deep,
   * answers 21002 with `MALFORMED_REQUEST`. Deliberately below
   * `ReceiptVerifier.MAX_RECEIPT_BYTES`: the JSON path parses the body as
   * well as decoding the receipt. A body passed as an object is not measured.
   */
  static readonly MAX_REQUEST_BYTES = MAX_REQUEST_BYTES;

  #roots: RootInput[];
  #environment: EndpointEnvironment;
  #clock: Clock;

  constructor({ trustedRoots, environment, clock = null }: VerifyReceiptEndpointOptions) {
    normalizeRoots(trustedRoots); // validate eagerly
    requireEndpointEnvironment(environment);
    this.#roots = trustedRoots;
    this.#environment = environment;
    this.#clock = normalizeClock(clock);
  }

  /**
   * Handles one verifyReceipt request: the request body as an object, or
   * as the raw JSON text an HTTP framework hands over. Never throws; a
   * failure is the result's `failureReason` and `status`.
   *
   * A request that is not an object, a string that is not a JSON object
   * (unparseable, `null`, an array, a scalar), and a `receipt-data` that is
   * missing, empty or not a string fail with `MALFORMED_REQUEST`, status
   * 21002. So does a string body over {@link MAX_REQUEST_BYTES} UTF-8 bytes
   * or nesting JSON more than 64 levels deep, before it is parsed. A
   * `receipt-data` over `ReceiptVerifier.MAX_RECEIPT_BYTES` characters fails
   * with `INVALID_RECEIPT_FORMAT`, also 21002, before it is decoded.
   *
   * `requestDate`, when given, becomes `request_date` in place of the
   * endpoint's clock. It reaches `request_date` and nothing else: receipt
   * chain validity is judged at the receipt's own creation date.
   */
  verifyReceiptResult(requestBody: unknown, requestDate: Date | null = null): VerifyReceiptResult {
    let at: number | undefined;
    try {
      at = requestInstant(requestDate, this.#clock);
      const body = typeof requestBody === 'string' ? parseRequestJson(requestBody) : requestBody;
      return this.#verify(receiptDataOf(body), at);
    } catch (error) {
      return failedResult(this.#environment, error, at ?? Date.now());
    }
  }

  /**
   * Verifies a bare base64 receipt, the value a request body would carry as
   * `receipt-data`, with no envelope around it. Never throws; a missing or
   * empty string fails with `MALFORMED_REQUEST`, as a missing
   * `receipt-data` does. `requestDate` as in {@link verifyReceiptResult}.
   */
  verifyReceiptData(receiptData: unknown, requestDate: Date | null = null): VerifyReceiptResult {
    let at: number | undefined;
    try {
      at = requestInstant(requestDate, this.#clock);
      return this.#verify(receiptData, at);
    } catch (error) {
      return failedResult(this.#environment, error, at ?? Date.now());
    }
  }

  /**
   * Handles one verifyReceipt request body in its raw wire form: the JSON
   * request body in, the JSON response body out, so an HTTP framework's
   * body can be piped straight through without a DTO in between. The same
   * as `verifyReceiptResult(body).toJson()` for a string body; anything
   * that is not a string answers `{"status":21002}`.
   *
   * Output is deterministic — the response object preserves insertion
   * order, so equal inputs serialize to equal bytes. Key order is not part
   * of the JSON contract.
   *
   * The four id keys come out with every digit intact
   * (`"download_id":9223372036854775807`), which no `JSON.stringify` of the
   * object form can do on Node 20.
   */
  verifyReceiptJson(body: string): string {
    return this.verifyReceiptResult(typeof body === 'string' ? body : undefined).toJson();
  }

  /**
   * The one verification path every entry point ends in. Callers catch
   * what it throws: a VerificationError is that reason, anything else is
   * INTERNAL_ERROR.
   */
  #verify(receiptData: unknown, at: number): VerifyReceiptResult {
    if (typeof receiptData !== 'string' || receiptData.length === 0) {
      return malformedRequest(this.#environment, at);
    }
    // The primitive itself, not a ReceiptVerifier built around a wildcard
    // bundle id: like Apple's endpoint, no bundle-id claim is checked here
    // (callers compare receipt.bundle_id).
    const receipt = verifyReceiptCore(decodeReceiptDataString(receiptData), this.#roots);
    return verifiedResult(this.#environment, receipt, at);
  }
}
