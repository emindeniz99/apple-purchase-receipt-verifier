import { normalizeClock, type Clock } from '../jws-claims.js';
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
} from '../verify-receipt-result.js';
import { normalizeRoots, type RootInput } from './chain.js';
import { decodeReceiptDataString, verifyReceiptCore, type AppReceipt } from './receipt.js';

export {
  Status,
  type VerifyReceiptRequestBody,
  type VerifyReceiptResponseBody,
} from '../verify-receipt-result.js';

/**
 * The outcome of one web {@link VerifyReceiptEndpoint} call; the receipt is
 * the web build's {@link AppReceipt}, with `Uint8Array` byte fields.
 */
export type VerifyReceiptResult = SharedVerifyReceiptResult<AppReceipt>;

export interface VerifyReceiptEndpointOptions {
  /** Pinned roots (production: `appleReceiptRoots()`). */
  trustedRoots: RootInput[];
  /** Which environment this endpoint instance emulates (21007/21008 routing). */
  environment: 'Production' | 'Sandbox';
  /** Optional source of "now" for `request_date`; omitted, the system clock. */
  clock?: Clock | null;
}

/**
 * The WebCrypto twin of the default entry point's `VerifyReceiptEndpoint`:
 * same options, same results, same response bytes. Every method returns a
 * Promise because `crypto.subtle` is async, and like the default build's,
 * none of them rejects.
 */
export class VerifyReceiptEndpoint {
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

  /** See the default build's `verifyReceiptResult`. */
  async verifyReceiptResult(
    requestBody: unknown,
    requestDate: Date | null = null,
  ): Promise<VerifyReceiptResult> {
    let at: number | undefined;
    try {
      at = requestInstant(requestDate, this.#clock);
      const body = typeof requestBody === 'string' ? parseRequestJson(requestBody) : requestBody;
      return await this.#verify(receiptDataOf(body), at);
    } catch (error) {
      return failedResult(this.#environment, error, at ?? Date.now());
    }
  }

  /** See the default build's `verifyReceiptData`. */
  async verifyReceiptData(
    receiptData: unknown,
    requestDate: Date | null = null,
  ): Promise<VerifyReceiptResult> {
    let at: number | undefined;
    try {
      at = requestInstant(requestDate, this.#clock);
      return await this.#verify(receiptData, at);
    } catch (error) {
      return failedResult(this.#environment, error, at ?? Date.now());
    }
  }

  /** See the default build's `verifyReceiptJson`. */
  async verifyReceiptJson(body: string): Promise<string> {
    return (await this.verifyReceiptResult(typeof body === 'string' ? body : undefined)).toJson();
  }

  async #verify(receiptData: unknown, at: number): Promise<VerifyReceiptResult> {
    if (typeof receiptData !== 'string' || receiptData.length === 0) {
      return malformedRequest(this.#environment, at);
    }
    const receipt = await verifyReceiptCore(decodeReceiptDataString(receiptData), this.#roots);
    return verifiedResult(this.#environment, receipt, at);
  }
}
