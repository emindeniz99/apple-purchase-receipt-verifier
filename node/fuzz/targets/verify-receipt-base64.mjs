/**
 * `ReceiptVerifier.verify` on a string — the form a client actually sends —
 * through the receipt-data base64 rule and then the whole DER path. Seeded
 * from the `receipt-b64` fixtures and the public receipts, so the fuzzer
 * starts from strings that decode rather than from noise it has to grow
 * into base64 by itself.
 *
 * Bytes that are not UTF-8 are skipped: the API takes a string, so they
 * could not reach it.
 */
import { ReceiptVerifier } from '../../dist/index.js';
import { RECEIPT_ANCHORS, asUtf8, requireTypedError } from '../harness.mjs';

const verifier = new ReceiptVerifier({
  trustedRoots: RECEIPT_ANCHORS,
  bundleId: 'dev.bonzer.weeka.app',
});

export function fuzz(data) {
  const text = asUtf8(data);
  if (text === null) {
    return;
  }
  try {
    verifier.verify(text);
  } catch (error) {
    requireTypedError(error, 'ReceiptVerifier.verify');
  }
}
