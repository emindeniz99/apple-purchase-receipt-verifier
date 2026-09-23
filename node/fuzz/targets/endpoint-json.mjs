/**
 * `VerifyReceiptEndpoint.verifyReceiptJson`, the one entry point that takes a
 * request body rather than a receipt: JSON parse, `receipt-data` extraction,
 * the receipt-base64 rule, then the whole DER path.
 *
 * Its documented contract is stronger than the other targets' — it never
 * throws at all — so that is what is asserted: any body, any bytes, gets a
 * JSON object with a numeric `status` back. The typed result behind that
 * body is checked too: exactly one of receipt and failureReason, the same
 * status, and never INTERNAL_ERROR. That reason means an unexpected error
 * inside the pipeline, or content a trusted signer signed that the library
 * cannot read; a fuzzer cannot forge a trusted signature, so for fuzz input
 * it can only be the first, and that is a bug.
 */
import { VerifyReceiptEndpoint } from '../../dist/index.js';
import { RECEIPT_ANCHORS, asUtf8 } from '../harness.mjs';

const endpoint = new VerifyReceiptEndpoint({
  trustedRoots: RECEIPT_ANCHORS,
  environment: 'Sandbox',
});

export function fuzz(data) {
  const body = asUtf8(data);
  if (body === null) {
    return;
  }
  let response;
  try {
    response = endpoint.verifyReceiptJson(body);
  } catch (error) {
    throw new Error(
      `the endpoint threw ${error?.constructor?.name}: ${error?.message}, but it documents that it never throws`,
      { cause: error },
    );
  }
  let parsed;
  try {
    parsed = JSON.parse(response);
  } catch (error) {
    throw new Error(`the endpoint answered with something that is not JSON: ${response}`, {
      cause: error,
    });
  }
  if (parsed === null || typeof parsed !== 'object' || typeof parsed.status !== 'number') {
    throw new Error(`the endpoint answered without a numeric status: ${response}`);
  }

  let result;
  try {
    result = endpoint.verifyReceiptResult(body);
  } catch (error) {
    throw new Error(
      `verifyReceiptResult threw ${error?.constructor?.name}: ${error?.message}, but it documents that it never throws`,
      { cause: error },
    );
  }
  if ((result.receipt === null) === (result.failureReason === null)) {
    throw new Error('verifyReceiptResult broke its receipt/failureReason invariant');
  }
  if (result.failureReason === 'INTERNAL_ERROR') {
    throw new Error('verifyReceiptResult hit an internal error', { cause: result.failureCause });
  }
  if (result.status !== parsed.status) {
    throw new Error(`verifyReceiptResult status ${result.status} differs from ${response}`);
  }
}
