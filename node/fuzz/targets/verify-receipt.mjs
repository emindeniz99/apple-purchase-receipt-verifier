/**
 * The whole legacy-receipt path on DER bytes: CMS walk, payload parse, chain
 * build, signature check.
 *
 * Three invariants, the same ones the Go and Rust ports state:
 *
 *   - nothing panics;
 *   - a failure is a `VerificationError`, never a foreign error type;
 *   - a receipt that verifies was accepted *because of* the anchors, proven
 *     by re-running it against an unrelated anchor set and requiring
 *     failure. Without that third one a fuzz target can only find crashes,
 *     never "accepts what it should not".
 */
import { verifyReceiptCore } from '../../dist/index.js';
import { RECEIPT_ANCHORS, UNRELATED_ANCHORS, requireTypedError } from '../harness.mjs';

export function fuzz(data) {
  const der = Buffer.isBuffer(data) ? data : Buffer.from(data);
  try {
    verifyReceiptCore(der, RECEIPT_ANCHORS);
  } catch (error) {
    requireTypedError(error, 'verifyReceiptCore');
    return;
  }
  let acceptedByUnrelated = false;
  try {
    verifyReceiptCore(der, UNRELATED_ANCHORS);
    acceptedByUnrelated = true;
  } catch (error) {
    requireTypedError(error, 'verifyReceiptCore against the unrelated anchors');
  }
  if (acceptedByUnrelated) {
    throw new Error(
      'this input verifies against an unrelated anchor set too, so the anchors are not being enforced',
    );
  }
}
