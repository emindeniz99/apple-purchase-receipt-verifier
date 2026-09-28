/**
 * The StoreKit 2 / App Store Server JWS path: compact-JWS split, strict
 * base64url, JSON header and payload, `x5c` certificates, chain, ES256
 * signature. 0.7 has one method for every Apple JWS (`verifySignedData`) —
 * no separate `verifyTransaction`/`verifyAppTransaction`/`verifyRaw`, and no
 * bundle id or environment claim, since the library returns the payload
 * rather than judging it.
 *
 * Two invariants: `verifySignedData` never throws and never answers
 * `INTERNAL_ERROR` for fuzz input; and a JWS that verifies under the
 * fixture root must be refused under Apple's production roots, or the
 * anchors are not what decided it.
 */
import { Reason, createVerifier } from '../../dist/index.js';
import { APPLE_CONFIG, JWS_CONFIG, asUtf8 } from '../harness.mjs';

const verifier = createVerifier(JWS_CONFIG);
const unrelated = createVerifier(APPLE_CONFIG);

export function fuzz(data) {
  const jws = asUtf8(data);
  if (jws === null) {
    return;
  }
  const result = verifier.verifySignedData(jws);
  if (!result.verified) {
    if (result.failure.reason === Reason.INTERNAL_ERROR) {
      throw new Error(
        `verifySignedData answered INTERNAL_ERROR for fuzz input: ${result.failure.message}`,
        { cause: result.failure.cause },
      );
    }
    return;
  }
  const acceptedByApple = unrelated.verifySignedData(jws).verified;
  if (acceptedByApple) {
    throw new Error(
      "this input verifies against Apple's production roots too, so the anchors are not being enforced",
    );
  }
}
