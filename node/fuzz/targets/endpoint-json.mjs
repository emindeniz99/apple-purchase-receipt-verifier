/**
 * `VerifyReceiptEndpoint.verifyReceiptJson`, the one entry point that takes a
 * request body rather than a receipt: JSON parse, `receipt-data` extraction,
 * the receipt-base64 rule, then the whole DER path.
 *
 * Its documented contract is stronger than the other targets' — it never
 * throws at all — so that is what is asserted: any body, any bytes, gets a
 * JSON object with a numeric `status` back.
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
}
