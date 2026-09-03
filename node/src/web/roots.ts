import { base64Decode } from '../bytes.js';
import { APPLE_ROOT_DER_BASE64 } from '../roots-data.js';

/**
 * The Apple root certificates bundled with this package (copies of the
 * public roots from https://www.apple.com/certificateauthority/), inlined
 * by scripts/gen-roots.mjs from certs/. Production trust anchors; tests
 * use the shared fixture PKI instead.
 *
 * Both sets contain all three published Apple roots. Apple deliberately
 * documents the JWS chain as ending in "an Apple root certificate" (not a
 * specific one) and its guidance is to trust every root on the PKI page,
 * so anchoring on a single root would break silently if Apple re-anchored
 * a path — see PLAN.md D15.
 */
function allRoots(): Uint8Array[] {
  return APPLE_ROOT_DER_BASE64.map((b64) => base64Decode(b64));
}

/**
 * Trust anchors for StoreKit 2 / App Store Server JWS chains.
 * Production chains currently end at Apple Root CA - G3.
 */
export function appleJwsRoots(): Uint8Array[] {
  return allRoots();
}

/**
 * Trust anchors for legacy PKCS#7 app-receipt chains.
 * Production chains currently end at the Apple Inc. Root CA.
 */
export function appleReceiptRoots(): Uint8Array[] {
  return allRoots();
}
