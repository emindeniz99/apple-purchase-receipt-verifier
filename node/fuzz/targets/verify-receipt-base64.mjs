/**
 * `Verifier.verifyReceipt` on a string — the form a client actually sends —
 * through the receipt-data base64 rule and then the whole DER path.
 *
 * Bytes that are not UTF-8 are skipped: the API takes a string, so they
 * could not reach it. `verifyReceipt` never throws, and never answers
 * `INTERNAL_ERROR` for input nobody signed: a fuzzer cannot forge a trusted
 * signature, so that reason can only mean an unexpected library error.
 */
import { Reason, createVerifier } from '../../dist/index.js';
import { RECEIPT_CONFIG } from '../harness.mjs';

const verifier = createVerifier(RECEIPT_CONFIG);

const UTF8 = new TextDecoder('utf-8', { fatal: true });

export function fuzz(data) {
  let text;
  try {
    text = UTF8.decode(data);
  } catch {
    return;
  }
  const result = verifier.verifyReceipt(text);
  if (!result.verified && result.failure.reason === Reason.INTERNAL_ERROR) {
    throw new Error(
      `verifyReceipt answered INTERNAL_ERROR for fuzz input: ${result.failure.message}`,
      {
        cause: result.failure.cause,
      },
    );
  }
}
