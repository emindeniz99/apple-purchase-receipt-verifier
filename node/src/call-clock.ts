/**
 * Wraps a caller's clock so it is read at most once per top-level call (a
 * `verifyReceipt` with several SignerInfos would otherwise read it once per
 * signer) and only when a verdict needs it. A clock that throws is the
 * host's fault, not the input's, so it is reported as `INTERNAL_ERROR`
 * directly here — before it can land inside a guard that reports unexpected
 * exceptions on unverified input as `MALFORMED`.
 */
import { Reason, VerificationError } from './errors.js';

export function callClock(now: () => number): () => number {
  let cached: number | undefined;
  return (): number => {
    if (cached !== undefined) {
      return cached;
    }
    let value: number;
    try {
      value = now();
    } catch (cause) {
      throw new VerificationError(Reason.INTERNAL_ERROR, 'the configured clock failed', cause);
    }
    cached = value;
    return value;
  };
}
