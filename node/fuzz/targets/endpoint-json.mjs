/**
 * `Verifier.verifyReceiptEndpoint`, the one entry point that takes a request
 * body rather than a receipt: JSON parse, `receipt-data` extraction, the
 * receipt-base64 rule, then the whole DER path.
 *
 * Its documented contract is that it never throws at all, so that is what is
 * asserted: any body, any bytes, gets a JSON object with a numeric `status`
 * back, and never 21009 (INTERNAL_ERROR/UNREADABLE_PAYLOAD) — a fuzzer
 * cannot forge a trusted signature, so fuzz input can only reach 21009
 * through an unexpected library error, and that is a bug.
 */
import { Environment, createVerifier } from '../../dist/index.js';
import { RECEIPT_CONFIG } from '../harness.mjs';

const verifier = createVerifier(RECEIPT_CONFIG);

export function fuzz(data) {
  const body = data.toString('utf8');
  let response;
  try {
    response = verifier.verifyReceiptEndpoint(Environment.SANDBOX, body);
  } catch (error) {
    throw new Error(
      `verifyReceiptEndpoint threw ${error?.constructor?.name}: ${error?.message}, but it documents that it never throws`,
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
  if (parsed.status === 21009) {
    throw new Error(`the endpoint answered 21009 (INTERNAL_ERROR) for fuzz input: ${response}`);
  }
}
