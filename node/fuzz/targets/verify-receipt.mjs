/**
 * The whole legacy-receipt path on raw DER bytes: CMS walk, payload parse,
 * chain build, signature check. 0.7's public API takes only base64 (the
 * `byte[]` DER overload was dropped, docs/design/0.7-api.md "Dropped"), so
 * `data` is re-encoded as canonical standard base64 first — the same bytes,
 * the form a client actually sends.
 *
 * Two invariants:
 *
 *   - `verifyReceipt` never throws and never answers `INTERNAL_ERROR` for
 *     fuzz input (a fuzzer cannot forge a trusted signature, so that reason
 *     can only mean an unexpected library error);
 *   - a receipt that verifies was accepted *because of* the anchors, proven
 *     by re-running it against an unrelated anchor set and requiring
 *     failure. Without that second one a fuzz target can only find crashes,
 *     never "accepts what it should not".
 */
import { Reason, createVerifier } from '../../dist/index.js';
import { RECEIPT_CONFIG, UNRELATED_CONFIG } from '../harness.mjs';

const verifier = createVerifier(RECEIPT_CONFIG);
const unrelated = createVerifier(UNRELATED_CONFIG);

export function fuzz(data) {
  const base64 = Buffer.from(data).toString('base64');
  const result = verifier.verifyReceipt(base64);
  if (!result.verified) {
    if (result.failure.reason === Reason.INTERNAL_ERROR) {
      throw new Error(
        `verifyReceipt answered INTERNAL_ERROR for fuzz input: ${result.failure.message}`,
        {
          cause: result.failure.cause,
        },
      );
    }
    return;
  }
  const acceptedByUnrelated = unrelated.verifyReceipt(base64).verified;
  if (acceptedByUnrelated) {
    throw new Error(
      'this input verifies against an unrelated anchor set too, so the anchors are not being enforced',
    );
  }
}
