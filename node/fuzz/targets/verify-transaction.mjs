/**
 * The StoreKit 2 path: compact-JWS split, strict base64url, JSON header and
 * payload, `x5c` certificates, chain, ES256 signature, then the three public
 * entry points' claim checks.
 *
 * Same invariants as the Go port's `FuzzVerifyTransaction`: nothing escapes
 * but a `VerificationError`, and a JWS that `verifyRaw` accepts under the
 * fixture root must be refused under Apple's roots, or the anchors are not
 * what decided it.
 */
import { Environment, JwsVerifier } from '../../dist/index.js';
import { APPLE_JWS_ANCHORS, JWS_ANCHORS, asUtf8, requireTypedError } from '../harness.mjs';

const options = {
  bundleId: 'com.example.app',
  acceptedEnvironments: [Environment.SANDBOX],
};
const verifier = new JwsVerifier({ ...options, trustedRoots: JWS_ANCHORS });
const unrelated = new JwsVerifier({ ...options, trustedRoots: APPLE_JWS_ANCHORS });

const CALLS = [
  ['verifyTransaction', (jws) => verifier.verifyTransaction(jws)],
  ['verifyAppTransaction', (jws) => verifier.verifyAppTransaction(jws)],
  ['verifyRaw', (jws) => verifier.verifyRaw(jws)],
];

export function fuzz(data) {
  const jws = asUtf8(data);
  if (jws === null) {
    return;
  }
  let acceptedByFixtureRoot = false;
  for (const [name, call] of CALLS) {
    try {
      call(jws);
      if (name === 'verifyRaw') {
        acceptedByFixtureRoot = true;
      }
    } catch (error) {
      requireTypedError(error, name);
    }
  }
  if (!acceptedByFixtureRoot) {
    return;
  }
  let acceptedByApple = false;
  try {
    unrelated.verifyRaw(jws);
    acceptedByApple = true;
  } catch (error) {
    requireTypedError(error, 'verifyRaw against Apple roots');
  }
  if (acceptedByApple) {
    throw new Error(
      "this input verifies against Apple's roots too, so the anchors are not being enforced",
    );
  }
}
